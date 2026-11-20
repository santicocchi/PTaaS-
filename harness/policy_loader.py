"""Carga policy.yaml y tools.yaml; verifica que sean coherentes entre sí."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from harness.contracts import Phase

_DIR = Path(__file__).resolve().parent


def load_policy(path: Path = _DIR / "policy.yaml") -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def load_tools(path: Path = _DIR / "tools.yaml") -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def phase_allowlist(policy: dict[str, Any] | None = None) -> dict[Phase, set[str]]:
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


def hitl_capabilities(policy: dict[str, Any] | None = None) -> set[str]:
    """Capabilities que SIEMPRE exigen aprobación humana (`gates_hitl[].capabilities`, 007)."""
    policy = policy or load_policy()
    found: set[str] = set()
    for gate in policy.get("gates_hitl", []):
        caps = gate.get("capabilities") or []
        if not isinstance(caps, list) or not all(isinstance(c, str) and c for c in caps):
            raise ValueError(f"gates_hitl.capabilities inválido: {caps!r}")
        found.update(caps)
    return found


def delivery_ttl_minutes(policy: dict[str, Any] | None = None) -> int:
    """Vencimiento de una aprobación de entrega (gate `before: deliver`)."""
    gates = (policy or load_policy()).get("gates_hitl") or []
    (gate,) = [g for g in gates if g.get("before") == "deliver"]
    ttl = gate.get("approval_ttl_minutes")
    if type(ttl) is not int or ttl < 1:
        raise ValueError(f"approval_ttl_minutes del gate de entrega inválido: {ttl!r}")
    return ttl


def defectdojo_limits(policy: dict[str, Any] | None = None) -> tuple[float, int]:
    """(timeout_s, max_response_bytes) de `reporting.defectdojo`."""
    cfg = (policy or load_policy())["reporting"]["defectdojo"]
    timeout, size = cfg["timeout_s"], cfg["max_response_bytes"]
    if not isinstance(timeout, int | float) or timeout <= 0 or type(size) is not int or size < 1:
        raise ValueError("reporting.defectdojo: timeout_s y max_response_bytes inválidos")
    return float(timeout), size


def inconsistencies(policy: dict[str, Any] | None = None, tools: dict[str, Any] | None = None
                    ) -> dict[str, set[tuple[str, str]]]:
    policy, tools = policy or load_policy(), tools or load_tools()
    in_policy = {(ph, c) for ph, v in policy["phases"].items() for c in v["allowed"]}
    in_tools = {(x["phase"], x["capability"]) for x in tools["mvp"]}
    return {"solo_en_policy": in_policy - in_tools, "solo_en_tools": in_tools - in_policy}
