"""The canonical artefact contract.

Every later phase imports its data types from here. This is the frozen schema
the plan's Phase 1 exit criteria refer to: scanners write these shapes, engines
consume them, and the API serialises them.
"""

from app.schemas.artefact import (
    AlgorithmDetail,
    ArtefactDetail,
    CertificateDetail,
    CloudServiceDetail,
    CryptoArtefact,
    HardwareModuleDetail,
    KeyDetail,
    LibraryDetail,
    ProtocolDetail,
    RelatedMaterialDetail,
)
from app.schemas.common import (
    ARTEFACT_ID_VERSION,
    Evidence,
    Provenance,
    SourceLocation,
    TrinetraModel,
    compute_artefact_id,
)
from app.schemas.context import (
    SCANNER_SUPPLIABLE_FIELDS,
    Application,
    ArtefactContext,
    DependencyEdge,
    RetentionEvidence,
)
from app.schemas.risk import (
    FACTOR_WEIGHTS,
    MoscaTrack,
    ResourceTrack,
    RiskAssessment,
    ScoreContribution,
    band_for_score,
)
from app.schemas.scan import (
    CoverageGap,
    CoverageStats,
    ScanError,
    ScanResult,
    ScanTarget,
    ToolVersion,
)

#: Version of the artefact contract. Bumped when a change would break a scanner
#: or an engine; consumers assert against it on ingest.
SCHEMA_VERSION = "1.0"

__all__ = [
    "ARTEFACT_ID_VERSION",
    "FACTOR_WEIGHTS",
    "SCANNER_SUPPLIABLE_FIELDS",
    "SCHEMA_VERSION",
    "AlgorithmDetail",
    "Application",
    "ArtefactContext",
    "ArtefactDetail",
    "CertificateDetail",
    "CloudServiceDetail",
    "CoverageGap",
    "CoverageStats",
    "CryptoArtefact",
    "DependencyEdge",
    "Evidence",
    "HardwareModuleDetail",
    "KeyDetail",
    "LibraryDetail",
    "MoscaTrack",
    "ProtocolDetail",
    "Provenance",
    "RelatedMaterialDetail",
    "ResourceTrack",
    "RetentionEvidence",
    "RiskAssessment",
    "ScanError",
    "ScanResult",
    "ScanTarget",
    "ScoreContribution",
    "SourceLocation",
    "ToolVersion",
    "TrinetraModel",
    "band_for_score",
    "compute_artefact_id",
]
