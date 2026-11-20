"""Evidencia de validación (change 006, D7): redactada, con hash y referenciada en bitácora.

Por intento: `<state>/evidence/<engagement>/<finding_id>-<intento>.json`. La bitácora guarda
`evidence/<engagement>/<finding_id>-<intento>.json#sha256=<hex>` (formato de `EVIDENCE_RE`).

La evidencia prueba la condición; no copia datos del laboratorio que no hacen falta:
encabezados de una lista permitida, cookies sin valor, `Authorization`/`Cookie`/`Set-Cookie`
como `[redacted]`, el SHA-256 del cuerpo y un extracto de a lo sumo 512 bytes alrededor del
canario o de la coincidencia del evaluador.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from harness.contracts import EVIDENCE_RE, SUBJECT_RE
from harness.poc.catalog import ResponseRecord, match_span
from harness.sandbox import SandboxRequest

ALLOWED_HEADERS = frozenset(h.lower() for h in (
    "Content-Type", "Server", "Location", "Content-Length", "X-Frame-Options",
    "Content-Security-Policy", "Strict-Transport-Security"))
REDACTED_HEADERS = frozenset({"authorization", "cookie", "set-cookie"})
REDACTED = "[redacted]"
EXCERPT_BYTES = 512
RESULTS = frozenset({"validated", "not_validated", "failed"})
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
_CONTEXT_CHARS = 200


def _cookie(raw: str) -> dict[str, Any]:
    """Nombre y atributos de un Set-Cookie, nunca el valor."""
    first, *attrs = [part.strip() for part in raw.split(";")]
    return {"name": first.split("=", 1)[0].strip(),
            "attributes": [a for a in attrs if a]}


def _excerpt(body: str, span: tuple[int, int] | None) -> str:
    if span is None:
        return ""
    start, end = max(0, span[0] - _CONTEXT_CHARS), min(len(body), span[1] + _CONTEXT_CHARS)
    raw = body[start:end].encode("utf-8")
    if len(raw) > EXCERPT_BYTES:                     # centrado en la coincidencia
        hit = len(body[start:span[0]].encode("utf-8"))
        lo = max(0, min(hit - (EXCERPT_BYTES // 4), len(raw) - EXCERPT_BYTES))
        raw = raw[lo:lo + EXCERPT_BYTES]
    return raw.decode("utf-8", "ignore")


def response_summary(record: ResponseRecord, evaluator: str) -> dict[str, Any]:
    headers: dict[str, str] = {}
    for name, value in record.headers.items():
        low = name.lower()
        if low in REDACTED_HEADERS:
            headers[name] = REDACTED
        elif low in ALLOWED_HEADERS:
            headers[name] = value
    return {
        "status": record.status,
        "headers": headers,
        "set_cookies": [_cookie(c) for c in record.set_cookies],
        "body_sha256": hashlib.sha256(record.body.encode("utf-8")).hexdigest(),
        "excerpt": _excerpt(record.body, match_span(evaluator, record)),
    }


def build_evidence(*, finding_id: str, attempt: int, poc_id: str, poc_version: str,
                   catalog_version: str, parameters: dict[str, str], sandbox_id: str | None,
                   request: SandboxRequest | None, record: ResponseRecord | None,
                   evaluator: str, canary: str | None, result: str, detail: str,
                   truncated: bool) -> dict[str, Any]:
    if result not in RESULTS:
        raise ValueError(f"resultado inválido: {result!r}")
    if record is not None and canary is not None:
        record = ResponseRecord(record.status, record.headers, record.body, record.set_cookies,
                                canary)
    return {
        "finding_id": finding_id, "attempt": attempt,
        "poc_id": poc_id, "poc_version": poc_version, "catalog_version": catalog_version,
        "parameters": dict(parameters), "sandbox_id": sandbox_id,
        "request": None if request is None else {
            "method": request.method, "path": request.path, "host": request.host,
            "ip": request.ip, "port": request.port},
        "response": None if record is None else response_summary(record, evaluator),
        "result": result, "detail": detail, "truncated": truncated,
    }


def write_evidence(state_dir: Path | str, engagement_id: str, finding_id: str, attempt: int,
                   document: dict[str, Any]) -> str:
    """Escribe el archivo (sin sobrescribir) y devuelve la referencia para la bitácora."""
    if not _ENGAGEMENT_RE.match(engagement_id) or not SUBJECT_RE.match(finding_id) \
            or type(attempt) is not int or attempt < 1:
        raise ValueError("engagement, hallazgo o intento inválidos")
    rel = f"evidence/{engagement_id}/{finding_id}-{attempt}.json"
    path = Path(state_dir) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
    with path.open("xb") as fh:                      # la bitácora ya puede apuntar a otro
        fh.write(data)
    return f"{rel}#sha256={hashlib.sha256(data).hexdigest()}"


def verify_evidence(state_dir: Path | str, ref: str) -> bool:
    """True si el archivo existe y su SHA-256 coincide con el de la bitácora."""
    if not EVIDENCE_RE.match(ref):
        return False
    rel, digest = ref.split("#sha256=", 1)
    if ".." in rel.split("/"):
        return False
    path = Path(state_dir) / rel
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(data).hexdigest() == digest
