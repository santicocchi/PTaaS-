"""Tabla curada del informe (change 007, D3): `data/report_catalog.yaml`.

Una entrada vale solo si está revisada (revisor no vacío, distinto de `pendiente` y del autor)
y si sus textos pasan las reglas: sin datos sensibles y, en lo que lee una audiencia no técnica
(título, impacto y la primera oración de la remediación), sin jerga técnica. Una entrada que
no vale NO EXISTE para el builder: el hallazgo queda sin vector ni remediación y el informe
falla, que es lo que pide el criterio 1.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from harness.redaction import scan

ROOT = Path(__file__).resolve().parents[1]
REPORT_CATALOG = ROOT / "data" / "report_catalog.yaml"
TEXT_FIELDS = ("title", "technical_description", "business_impact", "remediation")
REQUIRED = (*TEXT_FIELDS, "references", "cvss_v4_vector", "author", "reviewer", "date")
_KEY_RE = re.compile(r"^(CVE-[0-9]{4}-[0-9]{4,}|CWE-[1-9][0-9]{0,4})\Z")

# Lo que no puede leer una audiencia no técnica (D8): identificadores, vectores, IP (v4 y v6),
# URL, rutas y referencias a evidencia.
JARGON_RE = re.compile(
    r"CVE-|CWE-|CVSS:|#sha256=|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}::?[0-9A-Fa-f]{1,4}\b|::[0-9A-Fa-f]{1,4}\b"
    r"|\b[a-z][a-z0-9+.-]*://"
    r"|\b(?:state|evidence|reports|demo|harness|data|tests|openspec|audit)/"
    r"|(?<![\w])/[\w.-]+/|\b[\w-]+\.(?:py|ya?ml|json|sqlite3|md)\b")


def has_jargon(text: str) -> bool:
    return JARGON_RE.search(text) is not None


def first_sentence(text: str) -> str:
    head = text.strip().split(". ", 1)[0].strip()
    return head if head.endswith(".") else head + "."


@dataclass(frozen=True)
class CatalogEntry:
    key: str
    title: str
    technical_description: str
    business_impact: str
    remediation: str
    references: tuple[str, ...]
    cvss_v4_vector: str
    author: str
    reviewer: str
    date: str

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title,
                "technical_description": self.technical_description,
                "business_impact": self.business_impact, "remediation": self.remediation,
                "references": list(self.references), "cvss_v4_vector": self.cvss_v4_vector,
                "author": self.author, "reviewer": self.reviewer, "date": self.date}


def entry_problems(key: str, raw: Any) -> list[str]:
    """Campos por los que la entrada no vale. Vacío = entrada válida."""
    if not isinstance(raw, dict):
        return ["entry"]
    problems = [f for f in REQUIRED if f not in raw]
    if problems:
        return problems
    for f in ("author", "reviewer", "date", "cvss_v4_vector"):
        if not isinstance(raw[f], str):       # `date: 2026-11-20` sin comillas es una fecha
            problems.append(f)
    reviewer = raw["reviewer"].strip() if isinstance(raw["reviewer"], str) else ""
    author = raw["author"].strip() if isinstance(raw["author"], str) else ""
    if not reviewer or reviewer.casefold() == "pendiente" \
            or reviewer.casefold() == author.casefold():
        problems.append("reviewer")
    for f in TEXT_FIELDS:
        if not isinstance(raw[f], str) or scan(raw[f], f):
            problems.append(f)
    for f in ("title", "business_impact"):
        if isinstance(raw[f], str) and has_jargon(raw[f]):
            problems.append(f)
    if isinstance(raw["remediation"], str) and raw["remediation"].strip() \
            and has_jargon(first_sentence(raw["remediation"])):
        problems.append("remediation")
    refs = raw["references"]
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs) \
            or any(scan(r, "references") for r in refs):
        problems.append("references")
    return sorted(set(problems))


class ReportCatalog:
    def __init__(self, data: dict[str, Any], sha256: str) -> None:
        entries = data.get("entries") or {}
        if not isinstance(entries, dict) or not all(_KEY_RE.match(str(k)) for k in entries):
            raise ValueError("report_catalog: claves inválidas (CVE-AAAA-N o CWE-N)")
        self.raw: dict[str, Any] = entries
        self.sha256 = sha256

    @classmethod
    def load(cls, path: Path = REPORT_CATALOG) -> ReportCatalog:
        data = path.read_bytes()
        return cls(yaml.safe_load(data) or {}, hashlib.sha256(data).hexdigest())

    @classmethod
    def from_entries(cls, entries: dict[str, Any], sha256: str) -> ReportCatalog:
        return cls({"entries": entries}, sha256)

    def lookup(self, cve: str | None, cwe: str) -> tuple[CatalogEntry | None, list[str]]:
        """La entrada válida para el hallazgo (primero por CVE, después por CWE) y, si no
        hay, los campos por los que no valen las que hay."""
        problems: list[str] = []
        for key in (cve, cwe):
            if not key or key not in self.raw:
                continue
            found = entry_problems(key, self.raw[key])
            if not found:
                raw = self.raw[key]
                return CatalogEntry(key, raw["title"].strip(),
                                    raw["technical_description"].strip(),
                                    raw["business_impact"].strip(), raw["remediation"].strip(),
                                    tuple(raw["references"]), raw["cvss_v4_vector"],
                                    raw["author"], raw["reviewer"], raw["date"]), []
            problems += found
        return None, sorted(set(problems))
