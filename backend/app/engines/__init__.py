"""Pure, profile-driven analysis engines.

Nothing in this package reads a database, calls a service, or reads the clock.
That boundary is intentional: the same artefact, context, profiles and explicit
settings must always produce the same verdict.
"""

from app.engines.context_engine import inherit_dependency_criticality
from app.engines.final_risk_engine import RiskSettings, classify_risk, rescore_all
from app.engines.migration_planner import plan_migration_waves
from app.engines.mosca_engine import evaluate_mosca
from app.engines.recommendation_engine import (
    DEFAULT_CLASSICAL_PARTNER,
    recommend_replacement,
    recommendation_id_for_assessment,
)
from app.engines.resource_engine import evaluate_resources

__all__ = [
    "DEFAULT_CLASSICAL_PARTNER",
    "RiskSettings",
    "classify_risk",
    "evaluate_mosca",
    "evaluate_resources",
    "inherit_dependency_criticality",
    "plan_migration_waves",
    "recommend_replacement",
    "recommendation_id_for_assessment",
    "rescore_all",
]
