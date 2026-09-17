"""CycloneDX CBOM -> ``CryptoArtefact`` ingest (plan task 2.6).

This is Stage 5 of the lifecycle and the second of two validation points. The Go
scanner validates before it writes; Python validates again on read. Defence in
depth: a schema drift on either side is caught at the boundary rather than three
layers deep.

Three rules govern this module, and each exists because violating it produces a
*dishonest* inventory rather than a merely broken one:

* **A library finding never carries an algorithm.** OpenSSL being installed
  proves a crypto implementation exists, not that any algorithm is used.
* **Absent means unobserved.** A missing key size stays missing, so the artefact
  degrades to ``NEEDS_CONTEXT`` rather than acquiring a plausible default (P3).
* **Nothing a scanner produced is ever lost.** The whole component is preserved
  verbatim in ``raw_cbom``, even where Trinetra does not model it yet.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models.enums import (
    AssetType,
    Confidence,
    DetectionMethod,
    ScannerKind,
)
from app.schemas.artefact import AlgorithmDetail, CryptoArtefact, LibraryDetail
from app.schemas.common import Evidence, SourceLocation
from app.schemas.scan import CoverageGap, ToolVersion
from app.schemas.vocab import (
    TRINETRA_ASSET_TYPE_PROPERTY,
    asset_type_from_cyclonedx,
    mode_from_cyclonedx,
    normalise_purposes,
    padding_from_cyclonedx,
    primitive_from_cyclonedx,
)

#: The CycloneDX component type Trinetra reads. Anything else is skipped, not
#: rejected: a real-world CBOM legitimately contains other component types, and
#: refusing them would make ingest brittle against valid documents.
CRYPTO_ASSET_TYPE = "cryptographic-asset"

SUPPORTED_SPEC_VERSION = "1.6"

TRINETRA_KEY_SIZE_PROPERTY = "trinetra:key-size-bits"
TRINETRA_DATA_CATEGORY_PROPERTY = "trinetra:data-category"
TRINETRA_DETECTION_METHOD_PROPERTY = "trinetra:detection-method"
TRINETRA_CONFIDENCE_PROPERTY = "trinetra:confidence"
TRINETRA_RULE_ID_PROPERTY = "trinetra:rule-id"
TRINETRA_ALGORITHM_PROPERTY = "trinetra:algorithm"


class CBOMValidationError(ValueError):
    """The document does not satisfy the frozen contract.

    Carries every problem rather than the first, so a contract drift is fixed in
    one pass instead of being rediscovered on each retry.
    """

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("CBOM validation failed: " + "; ".join(problems))


class IngestResult:
    """What one document yielded.

    ``skipped_components`` and ``gaps`` are part of the result, not diagnostics:
    a document reported as clean because components were silently dropped is
    more dangerous than an honest error.
    """

    def __init__(
        self,
        artefacts: list[CryptoArtefact],
        tools: list[ToolVersion],
        skipped_components: int = 0,
        gaps: list[CoverageGap] | None = None,
    ) -> None:
        self.artefacts = artefacts
        self.tools = tools
        self.skipped_components = skipped_components
        self.gaps = gaps or []

    @property
    def artefact_count(self) -> int:
        return len(self.artefacts)


def validate_document(document: dict[str, Any]) -> None:
    """Validate a CBOM against the contract, raising on any problem."""
    problems: list[str] = []

    if document.get("bomFormat") != "CycloneDX":
        problems.append(f"bomFormat must be CycloneDX, got {document.get('bomFormat')!r}")
    if document.get("specVersion") != SUPPORTED_SPEC_VERSION:
        problems.append(
            f"specVersion must be {SUPPORTED_SPEC_VERSION}, "
            f"got {document.get('specVersion')!r}"
        )

    serial = document.get("serialNumber", "")
    if not isinstance(serial, str) or not serial.startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid")

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        problems.append("metadata is required")
    else:
        if not metadata.get("timestamp"):
            problems.append("metadata.timestamp is required")
        tools = metadata.get("tools")
        if not isinstance(tools, list) or not tools:
            # A CBOM that cannot say which version of which tool produced it is
            # not an audit artefact.
            problems.append("metadata.tools must record at least one tool")

    components = document.get("components")
    if components is not None and not isinstance(components, list):
        problems.append("components must be a list when present")

    if problems:
        raise CBOMValidationError(problems)


def ingest_document(
    document: dict[str, Any],
    *,
    scan_target: str,
    discovered_by: ScannerKind = ScannerKind.SOURCE,
) -> IngestResult:
    """Convert a validated CBOM into artefacts.

    ``scan_target`` participates in each artefact's deterministic id, so the
    same finding in a later scan of the same target keeps its identity — which
    is what makes "has this been fixed?" answerable.
    """
    validate_document(document)

    metadata = document.get("metadata") or {}
    observed_at = _parse_timestamp(metadata.get("timestamp"))
    tools = _parse_tools(metadata.get("tools") or [])

    artefacts: dict[str, CryptoArtefact] = {}
    skipped = 0
    gaps: list[CoverageGap] = []

    for index, component in enumerate(document.get("components") or []):
        if not isinstance(component, dict):
            skipped += 1
            continue

        if component.get("type") != CRYPTO_ASSET_TYPE:
            # Legitimately present in a CBOM; not ours to interpret.
            skipped += 1
            continue

        try:
            artefact = _component_to_artefact(
                component,
                scan_target=scan_target,
                discovered_by=discovered_by,
                observed_at=observed_at,
                discriminator=str(index),
            )
        except (ValueError, KeyError) as exc:
            # One malformed component must not discard the rest of the
            # inventory, but the loss must be visible rather than silent.
            gaps.append(
                CoverageGap(
                    kind="unparseable",
                    reason=(
                        f"component {component.get('name', index)!r} could not be "
                        f"ingested: {exc}"
                    ),
                )
            )
            continue

        if artefact is None:
            skipped += 1
            continue

        existing = artefacts.get(artefact.artefact_id)
        artefacts[artefact.artefact_id] = (
            existing.merged_with(artefact) if existing else artefact
        )

    return IngestResult(
        artefacts=list(artefacts.values()),
        tools=tools,
        skipped_components=skipped,
        gaps=gaps,
    )


def _component_to_artefact(
    component: dict[str, Any],
    *,
    scan_target: str,
    discovered_by: ScannerKind,
    observed_at: datetime,
    discriminator: str,
) -> CryptoArtefact | None:
    crypto = component.get("cryptoProperties") or {}
    properties = _index_properties(component.get("properties") or [])

    asset_type = asset_type_from_cyclonedx(
        crypto.get("assetType", "algorithm"),
        trinetra_hint=properties.get(TRINETRA_ASSET_TYPE_PROPERTY),
    )

    name = (component.get("name") or "").strip()
    if not name:
        raise ValueError("component has no name")

    evidence = _build_evidence(component, properties)
    if not evidence:
        # An unsourced finding is a bug, not a low-quality artefact: a human
        # cannot verify it, so it is reported as a gap by the caller.
        raise ValueError("component carries no verifiable occurrence")

    algo_props = crypto.get("algorithmProperties") or {}

    fields: dict[str, Any] = {
        "oid": crypto.get("oid") or None,
        "raw_cbom": component,
    }

    if primitive := algo_props.get("primitive"):
        fields["primitive"] = primitive_from_cyclonedx(primitive)
    if functions := algo_props.get("cryptoFunctions"):
        fields["purposes"] = normalise_purposes(list(functions))

    if asset_type is AssetType.LIBRARY:
        # The rule that keeps the risk engine honest, enforced a third time
        # here (after the Pydantic validator and the database CHECK).
        fields["detail"] = LibraryDetail(package_name=name)
    else:
        fields["algorithm"] = _resolve_algorithm(name, properties)
        if asset_type is AssetType.ALGORITHM:
            detail = _build_algorithm_detail(algo_props, properties)
            if detail is not None:
                fields["detail"] = detail

    artefact = CryptoArtefact.from_evidence(
        scan_target=scan_target,
        asset_type=asset_type,
        name=name,
        evidence=evidence,
        discovered_by=discovered_by,
        observed_at=observed_at,
        discriminator=discriminator,
        **fields,
    )
    return artefact


def _build_algorithm_detail(
    algo_props: dict[str, Any], properties: dict[str, str]
) -> AlgorithmDetail | None:
    """Build the R19 detail: version, mode, padding, key size, curve.

    Every field stays ``None`` when the document did not state it. The Trinetra
    key-size property is preferred over ``parameterSetIdentifier`` because the
    latter is a string that also carries non-numeric parameter set names such as
    ``ML-KEM-768``.
    """
    key_size: int | None = None
    if raw := properties.get(TRINETRA_KEY_SIZE_PROPERTY):
        key_size = _parse_positive_int(raw)

    parameter_set = algo_props.get("parameterSetIdentifier") or None
    if key_size is None and parameter_set:
        key_size = _parse_positive_int(parameter_set)
        if key_size is not None:
            # A purely numeric parameter set *is* the key size; keeping it in
            # both fields would duplicate the same fact.
            parameter_set = None

    mode = algo_props.get("mode")
    padding = algo_props.get("padding")

    detail = AlgorithmDetail(
        mode=mode_from_cyclonedx(mode) if mode else None,
        padding=padding_from_cyclonedx(padding) if padding else None,
        key_size_bits=key_size,
        curve=algo_props.get("curve") or None,
        parameter_set=parameter_set,
    )

    # Omit an entirely empty detail rather than attaching a hollow object that
    # implies a lookup nobody performed.
    if detail.model_dump(exclude={"detail_type"}, exclude_none=True):
        return detail
    return None


def _build_evidence(
    component: dict[str, Any], properties: dict[str, str]
) -> list[Evidence]:
    occurrences = ((component.get("evidence") or {}).get("occurrences")) or []

    method = _parse_detection_method(properties.get(TRINETRA_DETECTION_METHOD_PROPERTY))
    confidence = _parse_confidence(properties.get(TRINETRA_CONFIDENCE_PROPERTY))
    rule_id = properties.get(TRINETRA_RULE_ID_PROPERTY)

    evidence: list[Evidence] = []
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            continue
        location = (occurrence.get("location") or "").strip()
        if not location:
            continue

        evidence.append(
            Evidence(
                location=SourceLocation(
                    path=location,
                    line=_parse_positive_int(occurrence.get("line")),
                ),
                detection_method=method,
                confidence=confidence,
                rule_id=rule_id,
                additional_context=occurrence.get("additionalContext") or None,
            )
        )
    return evidence


def _resolve_algorithm(name: str, properties: dict[str, str]) -> str | None:
    """Normalise the algorithm name.

    The scanner's explicit ``trinetra:algorithm`` wins; otherwise the leading
    token of the display name is used, so "AES-128-CBC" yields "aes".
    """
    if explicit := properties.get(TRINETRA_ALGORITHM_PROPERTY):
        return explicit.strip().lower() or None

    token = name.strip().lower()
    for separator in ("-", "_", "/"):
        token = token.split(separator)[0]
    return token or None


def _index_properties(properties: list[Any]) -> dict[str, str]:
    indexed: dict[str, str] = {}
    for prop in properties:
        if not isinstance(prop, dict):
            continue
        key = prop.get("name")
        value = prop.get("value")
        if isinstance(key, str) and isinstance(value, str):
            indexed[key] = value
    return indexed


def _parse_tools(tools: list[Any]) -> list[ToolVersion]:
    parsed: list[ToolVersion] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        version = tool.get("version")
        if isinstance(name, str) and isinstance(version, str):
            parsed.append(ToolVersion(name=name, version=version))
    return parsed


def _parse_timestamp(raw: Any) -> datetime:
    """Parse the document timestamp, falling back to now.

    A malformed timestamp must not discard a whole inventory, but the fallback
    is deliberately the ingest time rather than a zero date, which would sort
    the artefact to 1970 in every trend view.
    """
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


def _parse_positive_int(raw: Any) -> int | None:
    """Return a positive int, or ``None`` when the value is absent or invalid.

    Never returns 0: a zero key size is not a measurement, and letting it
    through would present "unobserved" as "zero bits".
    """
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _parse_detection_method(raw: str | None) -> DetectionMethod:
    if raw and DetectionMethod.has_value(raw):
        return DetectionMethod(raw)
    return DetectionMethod.OTHER


def _parse_confidence(raw: str | None) -> Confidence:
    if raw and Confidence.has_value(raw):
        return Confidence(raw)
    # An unstated confidence is low, never high: the document did not claim it.
    return Confidence.LOW


__all__ = [
    "CRYPTO_ASSET_TYPE",
    "CBOMValidationError",
    "IngestResult",
    "ingest_document",
    "validate_document",
]
