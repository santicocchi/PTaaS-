"""Schemas de intercambio entre agentes + reglas deterministas (priorización, dedupe, escalado)."""
from __future__ import annotations

from dataclasses import dataclass, field


class SchemaError(ValueError): ...


@dataclass(frozen=True)
class Asset:
    id: str
    type: str
    address: str
    source_tool: str
    technologies: tuple[str, ...] = ()
    iteration: int = 0                 # versión del grafo en la que apareció (change 004)
    in_scope: bool = True
    reason: str | None = None          # motivo si está fuera de alcance

    def __post_init__(self):
        if not self.source_tool:
            raise SchemaError("Asset requiere source_tool")


CONFIDENCE = ("low", "medium", "high")
CVSS_VERSIONS = ("4.0", "3.1")


@dataclass
class CandidateFinding:
    id: str
    asset_id: str
    cwe: str = "unknown"
    cve: str | None = None
    epss: float | None = None
    attack_technique: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    confidence: str = "medium"
    # change 005: el puntaje se guarda con su versión y nunca se convierte (D5)
    cvss_score: float | None = None
    cvss_version: str | None = None
    feed_stale: bool = False
    host: str = ""                     # host del activo, para el análisis (D7)
    title: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise SchemaError("CandidateFinding requiere evidence_refs")
        if self.epss is not None and not (0.0 <= self.epss <= 1.0):
            raise SchemaError("epss fuera de rango")
        if self.confidence not in CONFIDENCE:
            raise SchemaError("confianza inválida")
        if (self.cvss_score is None) != (self.cvss_version is None):
            raise SchemaError("cvss_score y cvss_version van juntos")
        if self.cvss_version is not None and self.cvss_version not in CVSS_VERSIONS:
            raise SchemaError("versión de CVSS inválida")
        if self.cvss_score is not None and not (0.0 <= self.cvss_score <= 10.0):
            raise SchemaError("cvss fuera de rango")


@dataclass(frozen=True)
class PrioritizedVuln:
    finding_id: str
    status: str                  # confirmed | discarded | inconclusive
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    cvss_v4_score: float | None = None
    cvss_score: float | None = None     # change 005: el que haya, con su versión
    cvss_version: str | None = None
    priority: float | None = None       # None = "sin puntaje" (va al final)
    needs_review: bool = False          # contradicción entre herramientas (D8)

    def __post_init__(self):
        if self.status not in {"confirmed", "discarded", "inconclusive"}:
            raise SchemaError("status inválido")
        if not self.rationale.strip():
            raise SchemaError("PrioritizedVuln requiere rationale")


def dedupe(candidates: list[CandidateFinding]) -> list[CandidateFinding]:
    """Deduplica por (activo, CVE|CWE); fusiona evidencia y se queda con la mayor confianza."""
    merged: dict[tuple[str, str], CandidateFinding] = {}
    for c in candidates:
        key = (c.asset_id, c.cve or c.cwe)
        if key in merged:
            m = merged[key]
            m.evidence_refs = sorted(set(m.evidence_refs) | set(c.evidence_refs))
            if CONFIDENCE.index(c.confidence) > CONFIDENCE.index(m.confidence):
                m.confidence = c.confidence
        else:
            merged[key] = CandidateFinding(**{**c.__dict__, "evidence_refs": list(c.evidence_refs)})
    return list(merged.values())


def priority_score(cvss_v4: float, epss: float | None, asset_criticality: int) -> float:
    """Determinista y reproducible. cvss 0-10, epss 0-1 (None→0), criticidad 1-5."""
    if not (0 <= cvss_v4 <= 10) or not (1 <= asset_criticality <= 5):
        raise SchemaError("insumos fuera de rango")
    e = 0.0 if epss is None else epss
    return round(0.6 * cvss_v4 + 2.5 * e + 0.25 * asset_criticality, 2)


class SchemaGate:
    """Tras 2 salidas inválidas consecutivas, escala a HITL (no reintenta más)."""

    def __init__(self, max_failures: int = 2):
        self.max_failures, self.failures = max_failures, 0

    def record(self, valid: bool) -> str:
        self.failures = 0 if valid else self.failures + 1
        return "PENDING_HITL" if self.failures >= self.max_failures else ("OK" if valid else "RETRY")
