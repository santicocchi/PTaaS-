"""Vector CVSS v4.0 (change 007, D4): validación propia, determinista y sin LLM.

El parser es nuestro y estricto: prefijo exacto, las 11 métricas base una vez y en el orden de
la especificación de FIRST, opcionales como mucho una vez y en su orden, solo valores
permitidos y sin nada después (`\\Z`). El puntaje lo calcula la biblioteca `cvss` (fijada en
requirements.txt), que implementa el algoritmo de referencia de FIRST (macrovectores y tabla
de búsqueda), y solo se le pasa un vector que ya pasó el parser.

Con métricas de amenaza (E) o ambientales (CR..MSA) distintas de X, el puntaje deja de ser el
base: FIRST lo nombra CVSS-BT, CVSS-BE o CVSS-BTE, y el informe muestra esa nomenclatura.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from cvss import CVSS4

PREFIX = "CVSS:4.0/"

BASE: tuple[tuple[str, str], ...] = (
    ("AV", "NALP"), ("AC", "LH"), ("AT", "NP"), ("PR", "NLH"), ("UI", "NPA"),
    ("VC", "HLN"), ("VI", "HLN"), ("VA", "HLN"), ("SC", "HLN"), ("SI", "HLN"), ("SA", "HLN"),
)
# Opcionales en el orden de la especificación de FIRST (threat, environmental, supplemental).
OPTIONAL: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("E", tuple("XAPU")),
    ("CR", tuple("XHML")), ("IR", tuple("XHML")), ("AR", tuple("XHML")),
    ("MAV", tuple("XNALP")), ("MAC", tuple("XLH")), ("MAT", tuple("XNP")),
    ("MPR", tuple("XNLH")), ("MUI", tuple("XNPA")),
    ("MVC", tuple("XHLN")), ("MVI", tuple("XHLN")), ("MVA", tuple("XHLN")),
    ("MSC", tuple("XHLN")), ("MSI", tuple("XSHLN")), ("MSA", tuple("XSHLN")),
    ("S", tuple("XNP")), ("AU", tuple("XNY")), ("R", tuple("XAUI")), ("V", tuple("XDC")),
    ("RE", tuple("XLMH")), ("U", ("X", "Clear", "Green", "Amber", "Red")),
)
_ENVIRONMENTAL = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA",
                  "MSC", "MSI", "MSA")
_PAIR_RE = re.compile(r"^([A-Z]{1,3}):([A-Za-z]{1,5})\Z")


class InvalidVector(ValueError):
    """El texto no es un vector CVSS v4.0 válido. El mensaje dice por qué."""


@dataclass(frozen=True)
class Cvss4Vector:
    text: str
    metrics: dict[str, str]

    @property
    def score(self) -> float:
        return float(CVSS4(self.text).base_score)

    @property
    def severity(self) -> str:
        return severity(self.score)

    @property
    def nomenclature(self) -> str:
        """CVSS-B, CVSS-BT, CVSS-BE o CVSS-BTE (especificación de FIRST, sección 1.3)."""
        threat = self.metrics.get("E", "X") != "X"
        env = any(self.metrics.get(k, "X") != "X" for k in _ENVIRONMENTAL)
        return "CVSS-B" + ("T" if threat else "") + ("E" if env else "")


def parse_vector(text: str) -> Cvss4Vector:
    if not isinstance(text, str):
        raise InvalidVector("el vector no es texto")
    if not text.startswith(PREFIX):
        raise InvalidVector("falta el prefijo CVSS:4.0/")
    body = text[len(PREFIX):]
    # `\Z` y no `$`: un salto de línea final no es parte de un vector válido (006 A5).
    if not re.fullmatch(r"[A-Za-z:/]+", body) or "\n" in text:
        raise InvalidVector("caracteres no permitidos")
    parts = body.split("/")
    if len(parts) < len(BASE):
        raise InvalidVector("faltan métricas base")
    metrics: dict[str, str] = {}
    for (key, allowed), part in zip(BASE, parts[:len(BASE)], strict=True):
        m = _PAIR_RE.match(part)
        if m is None or m.group(1) != key:
            raise InvalidVector(f"se esperaba la métrica base {key}")
        if len(m.group(2)) != 1 or m.group(2) not in allowed:
            raise InvalidVector(f"valor no permitido para {key}")
        metrics[key] = m.group(2)
    position = 0
    for part in parts[len(BASE):]:
        m = _PAIR_RE.match(part)
        if m is None:
            raise InvalidVector("métrica mal formada")
        key, value = m.groups()
        for i in range(position, len(OPTIONAL)):
            if OPTIONAL[i][0] == key:
                break
        else:                                  # desconocida, duplicada o fuera de orden
            raise InvalidVector(f"métrica opcional {key} repetida, fuera de orden o desconocida")
        if value not in OPTIONAL[i][1]:
            raise InvalidVector(f"valor no permitido para {key}")
        metrics[key] = value
        position = i + 1
    return Cvss4Vector(text, metrics)


def severity(score: float) -> str:
    """Severidad cualitativa de FIRST a partir del puntaje."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
