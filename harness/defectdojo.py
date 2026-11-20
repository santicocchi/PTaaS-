"""Exportación del informe a DefectDojo (change 007, D12): Generic Findings Import.

El documento se arma con una LISTA PERMITIDA de campos (`DD_FIELDS`), desde el archivo de la
versión aprobada del informe, nunca quitando campos de algo más grande. No sale:

- contenido de la evidencia (solo el SHA-256 de cada archivo, sin ruta);
- rutas locales, `sandbox_id`, contenedores, IP de la red `tools` o del runner;
- parámetros de PoC, canarios y solicitudes;
- registros de la bitácora, decisiones del Reviewer, sus nombres y sus motivos;
- datos del RoE, tokens, claves, el `rationale` del loop B;
- el anexo de divulgación y los hallazgos `discarded`.

Al final todo el JSON pasa por el escáner de `harness/redaction.py` y por una lista de marcas
internas: ante una coincidencia no se envía ni se escribe nada.
"""
from __future__ import annotations

import json
import re
from typing import Any

from harness.redaction import SensitiveData

DD_FIELDS = ("title", "severity", "description", "mitigation", "impact", "references", "cwe",
             "vulnerability_ids", "date", "active", "verified", "false_p",
             "unique_id_from_tool", "component_name", "component_version", "endpoints",
             "tags")
SCAN_TYPE = "Generic Findings Import"
_SEVERITY = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low",
             "None": "Info"}
# Marcas de algo interno que nunca tendría que llegar a un documento armado por lista permitida.
_INTERNAL_RE = re.compile(r"\b(?:state|evidence|approvals|audit|reports)/|ptaas-sbx-"
                          r"|\b10\.97\.\d{1,3}\.\d{1,3}\b|reviewer:|#sha256=")
_TAG_RE = re.compile(r"[^a-z0-9_-]+")


class ExportError(ValueError):
    """La exportación no se arma. `reason` es un motivo de `report.delivery`."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


def _ports(report: dict[str, Any]) -> dict[str, list[int]]:
    for s in report["sections"]:
        if s["key"] == "information_gathering":
            return {a["host"]: list(a["ports"]) for a in s["content"]["assets"]}
    return {}


def _component(technologies: list[str]) -> tuple[str | None, str | None]:
    """Primera tecnología del activo como `nombre/versión` o `nombre versión`, si la hay."""
    if not technologies:
        return None, None
    m = re.match(r"^(.+?)[/ ]v?([0-9][\w.-]*)$", technologies[0])
    return (m.group(1), m.group(2)) if m else (technologies[0], None)


def _description(f: dict[str, Any], report_id: str, report_sha256: str) -> str:
    v = f["validation"]
    hashes = sorted({r.split("#sha256=", 1)[1] for r in f["evidence"]})
    lines = [f["technical_description"], "",
             (f"CVSS v4.0: {f['cvss_v4_score']} {f['severity']} "
             f"({f['cvss_v4_nomenclature']}, {f['cvss_v4_vector']})"),
             f"EPSS: {f['epss']['text']}",
             "Validación: " + ("validado en sandbox" if v["status"] == "validated"
                               else f"no validado ({v['text']})"),
             f"Informe: {report_id}, SHA-256 {report_sha256}"]
    if hashes:
        lines.append("Evidencia (SHA-256): " + ", ".join(hashes))
    return "\n".join(lines)


def _finding(f: dict[str, Any], report: dict[str, Any], report_sha256: str,
             ports: dict[str, list[int]]) -> dict[str, Any]:
    validated = f["validation"]["status"] == "validated"
    name, version = _component(f["technologies"])
    endpoint: dict[str, Any] = {"host": f["host"]}
    if ports.get(f["host"]):
        endpoint["port"] = ports[f["host"]][0]
    reason = f["validation"]["reason"]
    tags = ["ptaas", "validated" if validated else "not-validated"]
    if reason:
        tags.append(_TAG_RE.sub("-", str(reason).lower()))
    doc: dict[str, Any] = {
        "title": f["title"],
        "severity": _SEVERITY[f["severity"]],
        "description": _description(f, report["report_id"], report_sha256),
        "mitigation": f["remediation"],
        "impact": f["business_impact"],
        "references": "\n".join(f["references"]),
        "cwe": int(f["cwe"].split("-", 1)[1]),
        "vulnerability_ids": [f["cve"]] if f.get("cve") else [],
        "date": report["as_of"][:10],
        "active": True,
        "verified": validated,
        "false_p": False,
        "unique_id_from_tool": f["fingerprint"],
        "component_name": name,
        "component_version": version,
        "endpoints": [endpoint],
        "tags": tags,
    }
    assert tuple(doc) == DD_FIELDS               # la lista permitida es la única fuente
    return doc


def build_export(report: dict[str, Any], report_sha256: str) -> dict[str, Any]:
    """Documento Generic Findings Import del informe. Lanza ExportError."""
    ports = _ports(report)
    doc = {"findings": [_finding(f, report, report_sha256, ports)
                        for f in report["findings"]]}
    try:
        SensitiveData.check(doc, "defectdojo")
    except SensitiveData as exc:
        raise ExportError("sensitive_data", exc.where) from exc
    raw = json.dumps(doc, ensure_ascii=False)
    if _INTERNAL_RE.search(raw):
        raise ExportError("sensitive_data", "la exportación tiene una referencia interna")
    return doc


def serialize(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
