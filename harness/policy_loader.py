"""Carga policy.yaml y tools.yaml; verifica que sean coherentes entre sí."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from harness.contracts import Phase

_DIR = Path(__file__).resolve().parent


def load_policy(path: Path = _DIR / "policy.yaml") -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_tools(path: Path = _DIR / "tools.yaml") -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def phase_allowlist(policy: dict | None = None) -> dict[Phase, set[str]]:
    policy = policy or load_policy()
    return {Phase(ph): set(v["allowed"]) for ph, v in policy["phases"].items()}


def hitl_phases(policy: dict[str, Any] | None = None) -> set[Phase]:
    """Fases en las que TODA acción exige aprobación humana (gates_hitl con `before: <fase>`)."""
    policy = policy or load_policy()
    fases = {p.value for p in Phase}
    otros_gates = {"deliver", "first_active_action"}   # los aplica la máquina de estados
    desconocidos = {g["before"] for g in policy.get("gates_hitl", [])} - fases - otros_gates
    if desconocidos:                 # una fase mal escrita no puede apagar un gate en silencio
        raise ValueError(f"gates_hitl con fases desconocidas: {sorted(desconocidos)}")
    return {Phase(g["before"]) for g in policy.get("gates_hitl", []) if g["before"] in fases}


def inconsistencies(policy: dict | None = None, tools: dict | None = None) -> dict[str, set]:
    policy, tools = policy or load_policy(), tools or load_tools()
    in_policy = {(ph, c) for ph, v in policy["phases"].items() for c in v["allowed"]}
    in_tools = {(x["phase"], x["capability"]) for x in tools["mvp"]}
    return {"solo_en_policy": in_policy - in_tools, "solo_en_tools": in_tools - in_policy}
