"""Catálogo de verificaciones inertes: carga, validación y ejecución parametrizada.

El agente de validación SOLO elige un id del catálogo y completa parámetros
declarados. No puede agregar parámetros, ni pasar código, ni usar ids ajenos.
La verificación se evalúa sobre una respuesta ya obtenida (`ResponseRecord`),
lo que permite probarla offline con fixtures.
"""
from __future__ import annotations

import dataclasses
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harness.contracts import normalize_target

_CATALOG = Path(__file__).resolve().parent / "catalog.yaml"
_REQUIRED = {"id", "version", "title", "cwe", "kind", "method", "parameters",
             "evaluator", "lab_only", "proposed_by", "approved_by", "approved_at"}


# `lab_targets` del catálogo → FQDN exactos del laboratorio (lab/docker-compose.yml, alias de
# la red `lab`; harness/profiles.yaml, targets.lab_only_domains). Se compara el host canónico
# completo: nada de prefijos, sufijos ni caracteres ignorados (revisión 006).
LAB_TARGET_HOSTS: dict[str, frozenset[str]] = {
    "dvwa": frozenset({"dvwa.lab.test"}),
    "juice-shop": frozenset({"juiceshop.lab.test"}),
}


def host_in_lab_targets(host: str, lab_targets: list[str]) -> bool:
    """True si el host canónico es uno de los FQDN de alguno de esos `lab_targets`."""
    canon = normalize_target(host) if host else None
    if canon is None:
        return False
    return any(canon in LAB_TARGET_HOSTS.get(t, frozenset()) for t in lab_targets)


class NotInCatalog(Exception): ...
class InvalidCatalog(Exception): ...
class ParameterError(Exception): ...
class ApprovalRequired(Exception): ...


@dataclass(frozen=True)
class ResponseRecord:
    status: int
    headers: dict[str, str]
    body: str
    set_cookies: tuple[str, ...] = ()
    canary: str | None = None     # canario enviado (solo POC-REFLECT-001)


@dataclass(frozen=True)
class Evidence:
    poc_id: str
    poc_version: str
    status: str                   # "validated" | "not_validated"
    detail: str
    parameters: dict[str, Any] = field(default_factory=dict)


def load_catalog(path: Path = _CATALOG) -> dict[str, dict[str, Any]]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return validate_entries(data["entries"])


def catalog_version(path: Path = _CATALOG) -> str:
    """Versión del catálogo: sube con cada entrada nueva o cambiada (006, D10)."""
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    version = data.get("catalog_version")
    if not isinstance(version, str) or not version:
        raise InvalidCatalog("catalog_version ausente")
    return version


def validate_entries(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for e in entries:
        missing = _REQUIRED - e.keys()
        if missing:
            raise InvalidCatalog(f"{e.get('id', '?')}: faltan campos {sorted(missing)}")
        if e["kind"] != "inert_check":
            raise InvalidCatalog(f"{e['id']}: solo se admiten verificaciones 'inert_check'")
        if e["lab_only"] is not True:
            raise InvalidCatalog(f"{e['id']}: debe ser lab_only")
        if not e["approved_by"] or not e["approved_at"]:
            raise InvalidCatalog(f"{e['id']}: sin aprobación registrada")
        proposer = str(e["proposed_by"] or "").strip().lower()
        if not proposer or proposer == str(e["approved_by"]).strip().lower():
            raise InvalidCatalog(f"{e['id']}: nadie aprueba su propia verificación")
        unknown = set(e.get("lab_targets") or []) - set(LAB_TARGET_HOSTS)
        if unknown:
            raise InvalidCatalog(f"{e['id']}: lab_targets desconocidos {sorted(unknown)}")
        if e["evaluator"] not in EVALUATORS:          # un evaluador nuevo es código (D10)
            raise InvalidCatalog(f"{e['id']}: evaluador desconocido {e['evaluator']!r}")
        if e["id"] in out:
            raise InvalidCatalog(f"id duplicado: {e['id']}")
        out[e["id"]] = e
    return out


# ---- Evaluadores: funciones puras sobre la respuesta observada -----------------

def _header(r: ResponseRecord, name: str) -> str | None:
    for k, v in r.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def header_missing_frame_protection(r: ResponseRecord) -> tuple[bool, str]:
    xfo = _header(r, "X-Frame-Options")
    csp = _header(r, "Content-Security-Policy") or ""
    ok = bool(xfo) or "frame-ancestors" in csp.lower()
    return (not ok, "sin X-Frame-Options ni frame-ancestors" if not ok else "protección presente")


def header_missing_csp(r: ResponseRecord) -> tuple[bool, str]:
    missing = not _header(r, "Content-Security-Policy")
    return (missing, "sin Content-Security-Policy" if missing else "CSP presente")


def cookie_flags_missing(r: ResponseRecord) -> tuple[bool, str]:
    problems = []
    for c in r.set_cookies:
        low = c.lower()
        miss = [f for f in ("secure", "httponly", "samesite") if f not in low]
        if miss:
            problems.append(f"{c.split('=')[0]} sin {','.join(miss)}")
    return (bool(problems), "; ".join(problems) if problems else "flags correctos")


_DIRLIST_RE = re.compile(r"<title>\s*index of /", re.IGNORECASE)
_ERROR_SIGNATURES = tuple(re.compile(s, re.IGNORECASE) for s in (
    r"stack trace", r"traceback \(most recent call", r"at [\w.$]+\(.+\.(java|js|py|php):\d+",
    r"fatal error:.*on line \d+", r"sqlstate\[", r"you have an error in your sql syntax"))


def directory_listing_enabled(r: ResponseRecord) -> tuple[bool, str]:
    hit = r.status == 200 and _DIRLIST_RE.search(r.body) is not None
    return (hit, "listado de directorio visible" if hit else "sin listado")


def input_reflected_unencoded(r: ResponseRecord) -> tuple[bool, str]:
    if not r.canary:
        return (False, "sin canario enviado")
    # Vulnerable si los caracteres especiales del canario aparecen SIN codificar.
    hit = r.canary in r.body
    return (hit, "canario reflejado sin codificar" if hit else "canario ausente o codificado")


def verbose_error_disclosure(r: ResponseRecord) -> tuple[bool, str]:
    found = [s for s in _ERROR_SIGNATURES if s.search(r.body)]
    return (bool(found), f"firmas de error: {len(found)}" if found else "sin divulgación")


EVALUATORS: dict[str, Callable[[ResponseRecord], tuple[bool, str]]] = {
    "header_missing_frame_protection": header_missing_frame_protection,
    "header_missing_csp": header_missing_csp,
    "cookie_flags_missing": cookie_flags_missing,
    "directory_listing_enabled": directory_listing_enabled,
    "input_reflected_unencoded": input_reflected_unencoded,
    "verbose_error_disclosure": verbose_error_disclosure,
}


def match_span(evaluator: str, r: ResponseRecord) -> tuple[int, int] | None:
    """Dónde está, en el cuerpo, lo que vio el evaluador (para el extracto de la evidencia)."""
    if evaluator == "input_reflected_unencoded" and r.canary:
        i = r.body.find(r.canary)
        return None if i < 0 else (i, i + len(r.canary))
    patterns: tuple[re.Pattern[str], ...] = ()
    if evaluator == "directory_listing_enabled":
        patterns = (_DIRLIST_RE,)
    elif evaluator == "verbose_error_disclosure":
        patterns = _ERROR_SIGNATURES
    for pattern in patterns:
        m = pattern.search(r.body)
        if m:
            return m.span()
    return None


def new_canary() -> str:
    """Canario inerte: identificador único + caracteres especiales, sin marcado ejecutable."""
    return f"ptaas{secrets.token_hex(4)}\"'<>"


# ---- Ejecución parametrizada ---------------------------------------------------

Sender = Callable[[str, dict[str, str]], ResponseRecord]   # lo provee el sandbox (fuera del kit)


def run_parametrized(catalog: dict[str, dict[str, Any]], poc_id: str, params: dict[str, str],
                     approved: bool, sender: Sender) -> Evidence:
    entry = catalog.get(poc_id)
    if entry is None:
        raise NotInCatalog(poc_id)
    if not approved:
        raise ApprovalRequired(f"{poc_id} requiere aprobación del Reviewer")
    declared = set(entry["parameters"])
    if set(params) != declared:
        raise ParameterError(f"parámetros esperados {sorted(declared)}, recibidos {sorted(params)}")
    for k, v in params.items():
        if not isinstance(v, str) or len(v) > 512 or re.search(r"[\r\n\x00]", v):
            raise ParameterError(f"valor inválido para {k}")
    send_params = dict(params)
    if entry["evaluator"] == "input_reflected_unencoded":
        send_params["canary"] = new_canary()
    response = sender(poc_id, send_params)
    if "canary" in send_params:
        # Se evalúa con el canario de ESTE intento, diga lo que diga la respuesta: un reflejo
        # de una corrida anterior no es un positivo (006, D9).
        response = dataclasses.replace(response, canary=send_params["canary"])
    vulnerable, detail = EVALUATORS[entry["evaluator"]](response)
    return Evidence(poc_id, entry["version"], "validated" if vulnerable else "not_validated",
                    detail, params)
