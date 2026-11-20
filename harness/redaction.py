"""Redacción de datos sensibles del informe (change 007, D13).

Dos pasos:
1. `redact()` reemplaza cada coincidencia por `[redacted:<id>]` en los textos que llegan de
   herramientas o de la evidencia. Los textos curados no se redactan: se validan con `scan()`.
2. `scan()` / `SensitiveData.check()` corren sobre el informe final y sobre la exportación:
   si queda una coincidencia, no se genera ni se envía nada. El error nombra el patrón y la
   sección, nunca el valor.

Los SHA-256 (64 hex) y los hashes cortos (12 hex) no son sensibles: el patrón MD5 exige
exactamente 32 hex con límites. Agregar o cambiar un patrón es un cambio revisado por el
security-reviewer, con su test positivo y negativo en tests/reporting/test_redaction.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# La redacción de encabezados de la evidencia (006 D7) vive en harness/evidence.py y se
# reutiliza tal cual; estos patrones cubren el texto libre que entra al informe.


@dataclass(frozen=True)
class Pattern:
    id: str
    regex: re.Pattern[str]
    scan_regex: re.Pattern[str] | None = None   # si el escaneo final tolera algo más

    @property
    def scanner(self) -> re.Pattern[str]:
        return self.scan_regex or self.regex


# El orden importa para redactar: primero lo más específico (una clave PEM o un JWT antes que
# un encabezado genérico), así cada valor queda bajo el id que mejor lo describe.
PATTERNS: tuple[Pattern, ...] = tuple(
    Pattern(i, re.compile(r), re.compile(scan) if scan else None) for i, r, scan in (
        ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", None),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", None),
        # Hasta el fin de línea: `Authorization: Basic <valor>` tiene un espacio en el medio.
        ("auth-header", r"(?i)\bauthorization\s*:[ \t]*\S[^\r\n]*", None),
        ("bearer", r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*", None),
        # Hasta el fin de línea: `Cookie: a=1; sid=s3cr3t` tiene varios pares (006 D7).
        ("cookie-value", r"(?i)\b(set-)?cookie\s*:[ \t]*[^\s;=]+=[^\r\n]*", None),
        ("api-key-header",
         r"(?i)\b(x-api-key|api-key|x-auth-token|x-access-token)\s*:[ \t]*\S[^\r\n]*", None),
        ("session-id", r"(?i)\b(PHPSESSID|JSESSIONID|connect\.sid|token)=[^;&\s]+", None),
        ("credential-param",
         r"(?i)\b(password|passwd|pwd|pass|secret|api[_-]?key|access[_-]?token)=[^&\s]+", None),
        ("url-query", r"\bhttps?://[^\s?#]+[?#]\S*", None),
        ("aws-key", r"\bAKIA[0-9A-Z]{16}\b", None),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", None),
        # La huella de un hallazgo (`fp1-` + 32 hex, 007 D10) no es un MD5: el escaneo final
        # la tolera, pero la redacción de texto de herramientas no hace excepciones.
        ("md5-hash", r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])",
         r"(?<![0-9a-fA-F])(?<!fp1-)[0-9a-fA-F]{32}(?![0-9a-fA-F])"),
        ("canary", r"ptaas[0-9a-f]{8}", None),
        ("lab-default-cred", r"(?i)\badmin\s*[:/]\s*(password|admin123)\b", None),
    ))


@dataclass(frozen=True)
class Match:
    pattern: str
    section: str


def redact(text: str) -> str:
    """Reemplaza cada dato sensible por `[redacted:<id>]`."""
    for p in PATTERNS:
        text = p.regex.sub(f"[redacted:{p.id}]", text)
    return text


def scan(text: str, section: str) -> list[Match]:
    """Patrones que aparecen en `text`. Nunca devuelve el valor."""
    return [Match(p.id, section) for p in PATTERNS if p.scanner.search(text)]


def _walk(value: Any, path: str) -> list[Match]:
    if isinstance(value, str):
        return scan(value, path)
    if isinstance(value, dict):
        return [m for k, v in value.items()
                for m in _walk(v, f"{path}.{k}" if path else str(k))]
    if isinstance(value, (list, tuple)):
        return [m for i, v in enumerate(value) for m in _walk(v, f"{path}[{i}]")]
    return []


class SensitiveData(ValueError):
    """Quedó un dato sensible en un documento que iba a salir."""

    reason = "sensitive_data"

    def __init__(self, matches: list[Match]) -> None:
        self.matches = matches
        self.where = ", ".join(f"{m.pattern} en {m.section}" for m in matches[:5])
        super().__init__(f"sensitive_data: {self.where}")

    @classmethod
    def check(cls, doc: Any, section: str = "") -> None:
        found = _walk(doc, section)
        if found:
            raise cls(found)
