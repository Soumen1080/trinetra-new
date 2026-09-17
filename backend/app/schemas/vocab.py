"""CycloneDX <-> canonical vocabulary translation (P6).

Three vocabularies exist: Semgrep metadata, the CycloneDX wire format, and the
engines. **snake_case is canonical.** This module is the only place CycloneDX
spellings appear on the Python side; the Go scanner holds the mirror image in
``vocab.go``.

The two tables must remain exact inverses. ``test_vocab.py`` asserts the
round-trip identity for every member of every enum, so a one-sided edit fails the
build rather than silently corrupting one direction of translation.
"""

from __future__ import annotations

from app.models.enums import AssetType, CipherMode, Padding, Primitive, Purpose

# ---------------------------------------------------------------------------
# assetType
# ---------------------------------------------------------------------------

#: CycloneDX models hardware modules and cloud services as related-crypto-material.
#: Translation is therefore lossy in that direction by design, and
#: ``_ASSET_TYPE_FROM_CYCLONEDX`` maps the shared wire value back to the single
#: canonical type that round-trips.
_ASSET_TYPE_TO_CYCLONEDX: dict[AssetType, str] = {
    AssetType.ALGORITHM: "algorithm",
    AssetType.KEY: "related-crypto-material",
    AssetType.CERTIFICATE: "certificate",
    AssetType.PROTOCOL: "protocol",
    AssetType.LIBRARY: "library",
    AssetType.HARDWARE_MODULE: "related-crypto-material",
    AssetType.CLOUD_SERVICE: "related-crypto-material",
    AssetType.RELATED_MATERIAL: "related-crypto-material",
}

_ASSET_TYPE_FROM_CYCLONEDX: dict[str, AssetType] = {
    "algorithm": AssetType.ALGORITHM,
    "certificate": AssetType.CERTIFICATE,
    "protocol": AssetType.PROTOCOL,
    "library": AssetType.LIBRARY,
    "related-crypto-material": AssetType.RELATED_MATERIAL,
}

#: Canonical types whose wire spelling is shared and therefore not recoverable
#: from ``assetType`` alone. These are disambiguated by the
#: ``trinetra:asset-type`` property, written on export and read on ingest.
_AMBIGUOUS_ASSET_TYPES: frozenset[AssetType] = frozenset(
    {AssetType.KEY, AssetType.HARDWARE_MODULE, AssetType.CLOUD_SERVICE}
)

TRINETRA_ASSET_TYPE_PROPERTY = "trinetra:asset-type"


# ---------------------------------------------------------------------------
# primitive
# ---------------------------------------------------------------------------

_PRIMITIVE_TO_CYCLONEDX: dict[Primitive, str] = {
    Primitive.BLOCK_CIPHER: "block-cipher",
    Primitive.STREAM_CIPHER: "stream-cipher",
    Primitive.HASH: "hash",
    Primitive.MAC: "mac",
    Primitive.AEAD: "ae",
    Primitive.SIGNATURE: "signature",
    Primitive.PKE: "pke",
    Primitive.KEM: "kem",
    Primitive.KEY_AGREEMENT: "key-agree",
    Primitive.KDF: "kdf",
    Primitive.DRBG: "drbg",
    Primitive.OTHER: "other",
}

_PRIMITIVE_FROM_CYCLONEDX: dict[str, Primitive] = {
    wire: canonical for canonical, wire in _PRIMITIVE_TO_CYCLONEDX.items()
}


# ---------------------------------------------------------------------------
# purpose  (CycloneDX cryptoFunctions)
# ---------------------------------------------------------------------------

_PURPOSE_TO_CYCLONEDX: dict[Purpose, str] = {
    Purpose.ENCRYPTION: "encrypt",
    Purpose.DECRYPTION: "decrypt",
    Purpose.DIGITAL_SIGNATURE: "sign",
    Purpose.VERIFY: "verify",
    Purpose.KEY_ENCAPSULATION: "encapsulate",
    Purpose.KEY_AGREEMENT: "keygen",
    Purpose.KEY_DERIVATION: "derive",
    Purpose.HASHING: "digest",
    Purpose.AUTHENTICATION: "tag",
    Purpose.INTEGRITY: "verify-integrity",
    Purpose.RANDOM_GENERATION: "generate",
    Purpose.OTHER: "other",
}

_PURPOSE_FROM_CYCLONEDX: dict[str, Purpose] = {
    wire: canonical for canonical, wire in _PURPOSE_TO_CYCLONEDX.items()
}


# ---------------------------------------------------------------------------
# mode and padding
# ---------------------------------------------------------------------------

_MODE_TO_CYCLONEDX: dict[CipherMode, str] = {
    CipherMode.ECB: "ecb",
    CipherMode.CBC: "cbc",
    CipherMode.CTR: "ctr",
    CipherMode.GCM: "gcm",
    CipherMode.CCM: "ccm",
    CipherMode.OFB: "ofb",
    CipherMode.CFB: "cfb",
    CipherMode.XTS: "xts",
    CipherMode.SIV: "siv",
    CipherMode.POLY1305: "poly1305",
    CipherMode.OTHER: "other",
}

_MODE_FROM_CYCLONEDX: dict[str, CipherMode] = {
    wire: canonical for canonical, wire in _MODE_TO_CYCLONEDX.items()
}

_PADDING_TO_CYCLONEDX: dict[Padding, str] = {
    Padding.PKCS1_V15: "pkcs1v15",
    Padding.OAEP: "oaep",
    Padding.PSS: "pss",
    Padding.PKCS7: "pkcs7",
    Padding.ANSI_X923: "ansix923",
    Padding.ISO10126: "iso10126",
    Padding.ZERO: "zeros",
    Padding.RAW: "raw",
    Padding.NONE: "none",
    Padding.OTHER: "other",
}

_PADDING_FROM_CYCLONEDX: dict[str, Padding] = {
    wire: canonical for canonical, wire in _PADDING_TO_CYCLONEDX.items()
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def asset_type_to_cyclonedx(value: AssetType) -> str:
    return _ASSET_TYPE_TO_CYCLONEDX[value]


def asset_type_from_cyclonedx(
    value: str, *, trinetra_hint: str | None = None
) -> AssetType:
    """Translate a wire ``assetType`` back to canonical.

    ``trinetra_hint`` carries the ``trinetra:asset-type`` property when present,
    which is what makes keys, hardware modules and cloud services survive the
    round trip despite sharing one CycloneDX spelling.

    Defaults to ``ALGORITHM`` for an unrecognised value rather than raising:
    ingesting a third-party CBOM with a newer assetType should degrade, not fail.
    """
    if trinetra_hint is not None and AssetType.has_value(trinetra_hint):
        return AssetType(trinetra_hint)
    return _ASSET_TYPE_FROM_CYCLONEDX.get(value, AssetType.ALGORITHM)


def asset_type_needs_hint(value: AssetType) -> bool:
    """Whether exporting ``value`` requires the disambiguating property."""
    return value in _AMBIGUOUS_ASSET_TYPES


def primitive_to_cyclonedx(value: Primitive) -> str:
    return _PRIMITIVE_TO_CYCLONEDX[value]


def primitive_from_cyclonedx(value: str) -> Primitive:
    return _PRIMITIVE_FROM_CYCLONEDX.get(value, Primitive.OTHER)


def purpose_to_cyclonedx(value: Purpose) -> str:
    return _PURPOSE_TO_CYCLONEDX[value]


def purpose_from_cyclonedx(value: str) -> Purpose:
    return _PURPOSE_FROM_CYCLONEDX.get(value, Purpose.OTHER)


def normalise_purposes(values: list[str]) -> list[Purpose]:
    """Translate a CycloneDX ``cryptoFunctions`` array, preserving order.

    Duplicates are collapsed because two wire spellings can map to one canonical
    purpose, and a repeated purpose carries no extra information.
    """
    seen: set[Purpose] = set()
    result: list[Purpose] = []
    for value in values:
        purpose = purpose_from_cyclonedx(value)
        if purpose not in seen:
            seen.add(purpose)
            result.append(purpose)
    return result


def mode_to_cyclonedx(value: CipherMode) -> str:
    return _MODE_TO_CYCLONEDX[value]


def mode_from_cyclonedx(value: str) -> CipherMode:
    return _MODE_FROM_CYCLONEDX.get(value, CipherMode.OTHER)


def padding_to_cyclonedx(value: Padding) -> str:
    return _PADDING_TO_CYCLONEDX[value]


def padding_from_cyclonedx(value: str) -> Padding:
    return _PADDING_FROM_CYCLONEDX.get(value, Padding.OTHER)


__all__ = [
    "TRINETRA_ASSET_TYPE_PROPERTY",
    "asset_type_from_cyclonedx",
    "asset_type_needs_hint",
    "asset_type_to_cyclonedx",
    "mode_from_cyclonedx",
    "mode_to_cyclonedx",
    "normalise_purposes",
    "padding_from_cyclonedx",
    "padding_to_cyclonedx",
    "primitive_from_cyclonedx",
    "primitive_to_cyclonedx",
    "purpose_from_cyclonedx",
    "purpose_to_cyclonedx",
]
