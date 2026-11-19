"""Parseo de salidas JSONL de herramientas: línea por línea, todo dato es no confiable."""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

Record = dict[str, Any]


def jsonl_records(raw: str) -> Iterator[Any]:
    """Cada línea no vacía como JSON, o `None` si no parsea."""
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except ValueError:
            yield None


def parse_lines(raw: str, parse: Callable[[Any], Record | None]) -> tuple[list[Record], int]:
    """(registros válidos, cantidad de líneas inválidas)."""
    valid: list[Record] = []
    invalid = 0
    for obj in jsonl_records(raw):
        rec = parse(obj) if isinstance(obj, dict) else None
        if rec is None:
            invalid += 1
        else:
            valid.append(rec)
    return valid, invalid


def status_of(valid: int, invalid: int) -> str:
    """ok / partial / invalid_output (design.md D6). Salida vacía es ok."""
    if invalid == 0:
        return "ok"
    return "partial" if valid else "invalid_output"


def clean_text(value: Any, limit: int = 200) -> str | None:
    """Texto de la herramienta sin caracteres de control y acotado."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("se esperaba texto")
    return "".join(ch for ch in value if ch.isprintable())[:limit]
