"""Vocabulary translation tests (P6).

The canonical -> CycloneDX -> canonical round trip must be the identity for
every enum member. A one-sided edit to either table is exactly the kind of drift
that produces findings which look right in the database and wrong in the export.
"""

from __future__ import annotations

import pytest

from app.models.enums import AssetType, CipherMode, Padding, Primitive, Purpose
from app.schemas import vocab


@pytest.mark.parametrize("member", list(Primitive))
def test_primitive_round_trips(member: Primitive) -> None:
    wire = vocab.primitive_to_cyclonedx(member)
    assert vocab.primitive_from_cyclonedx(wire) is member


@pytest.mark.parametrize("member", list(Purpose))
def test_purpose_round_trips(member: Purpose) -> None:
    wire = vocab.purpose_to_cyclonedx(member)
    assert vocab.purpose_from_cyclonedx(wire) is member


@pytest.mark.parametrize("member", list(CipherMode))
def test_mode_round_trips(member: CipherMode) -> None:
    wire = vocab.mode_to_cyclonedx(member)
    assert vocab.mode_from_cyclonedx(wire) is member


@pytest.mark.parametrize("member", list(Padding))
def test_padding_round_trips(member: Padding) -> None:
    wire = vocab.padding_to_cyclonedx(member)
    assert vocab.padding_from_cyclonedx(wire) is member


@pytest.mark.parametrize("member", list(AssetType))
def test_asset_type_round_trips_with_hint(member: AssetType) -> None:
    """Keys, hardware modules and cloud services share one CycloneDX spelling.

    They survive the round trip through the ``trinetra:asset-type`` property,
    which export writes whenever :func:`asset_type_needs_hint` says it must.
    """
    wire = vocab.asset_type_to_cyclonedx(member)
    hint = member.value if vocab.asset_type_needs_hint(member) else None
    assert vocab.asset_type_from_cyclonedx(wire, trinetra_hint=hint) is member


def test_every_ambiguous_type_is_flagged_for_a_hint() -> None:
    """Any type whose wire spelling is shared must require the hint.

    Without this, adding a new type that maps to related-crypto-material would
    silently start round-tripping to the wrong canonical value.
    """
    for member in AssetType:
        wire = vocab.asset_type_to_cyclonedx(member)
        sharers = [m for m in AssetType if vocab.asset_type_to_cyclonedx(m) == wire]
        if len(sharers) > 1:
            unhinted = vocab.asset_type_from_cyclonedx(wire)
            if unhinted is not member:
                assert vocab.asset_type_needs_hint(member), (
                    f"{member.value} shares the wire spelling {wire!r} but is "
                    "not flagged as needing a disambiguating hint"
                )


class TestDegradation:
    """Ingesting a third-party CBOM should degrade, not fail."""

    def test_unknown_asset_type_defaults_to_algorithm(self) -> None:
        assert (
            vocab.asset_type_from_cyclonedx("some-future-type") is AssetType.ALGORITHM
        )

    def test_unknown_primitive_degrades_to_other(self) -> None:
        assert vocab.primitive_from_cyclonedx("quantum-widget") is Primitive.OTHER

    def test_unknown_purpose_degrades_to_other(self) -> None:
        assert vocab.purpose_from_cyclonedx("teleport") is Purpose.OTHER


class TestPurposeNormalisation:
    def test_order_is_preserved(self) -> None:
        result = vocab.normalise_purposes(["sign", "encrypt", "verify"])
        assert result == [Purpose.DIGITAL_SIGNATURE, Purpose.ENCRYPTION, Purpose.VERIFY]

    def test_duplicates_are_collapsed(self) -> None:
        """Two wire spellings can map to one canonical purpose."""
        result = vocab.normalise_purposes(["encrypt", "encrypt", "teleport", "warp"])
        assert result == [Purpose.ENCRYPTION, Purpose.OTHER]

    def test_empty_input_yields_empty_output(self) -> None:
        assert vocab.normalise_purposes([]) == []
