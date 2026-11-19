"""Adaptador subfinder.enum: enumeración pasiva de subdominios (change 004)."""
from __future__ import annotations

from typing import Any

from harness.adapters.common import (
    InvalidTarget,
    Runner,
    default_runner,
    load_profiles,
    reject_forbidden,
    run_tool,
    tool_error,
    validate_target,
)
from harness.adapters.recon_output import Record, parse_lines, status_of
from harness.contracts import Action, Phase, ScopeToken, _is_ip, normalize_target


def build_argv(domain: str, profile: dict[str, Any] | None = None) -> list[str]:
    p = profile or load_profiles()["subfinder"]
    d = validate_target(domain)
    if _is_ip(d):
        raise InvalidTarget(f"subfinder solo acepta dominios: {domain!r}")
    argv = [p["binary"], "-d", d, *p["fixed_args"]]
    reject_forbidden(argv, p["forbidden_args"])
    return argv


def _host(obj: dict[str, Any]) -> Record | None:
    raw = obj.get("host")
    if not isinstance(raw, str):
        return None
    host = normalize_target(raw)
    if host is None or _is_ip(host):           # un subdominio nunca es una IP
        return None
    return {"host": host}


def parse_output(raw: str) -> dict[str, Any]:
    valid, invalid = parse_lines(raw, _host)
    hosts = sorted({r["host"] for r in valid})
    return {"status": status_of(len(valid), invalid), "hosts": hosts, "invalid_lines": invalid}


class SubfinderEnum:
    """Pasivo: consulta fuentes públicas y no se conecta al objetivo, por eso no usa
    `addresses` (no hay IP que fijar). En el laboratorio, sin internet, devuelve vacío."""
    name: str = "subfinder.enum"
    allowed_phases: tuple[Phase, ...] = (Phase.RECON,)
    destructive: bool = False

    def __init__(self, runner: Runner = default_runner,
                 profile: dict[str, Any] | None = None) -> None:
        self._runner = runner
        self._profile = profile or load_profiles()["subfinder"]

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        argv = build_argv(target, self._profile)
        raw, error = run_tool(self._runner, argv, self._profile["timeout_s"])
        if raw is None:
            return tool_error("subfinder", target, str(error))
        return {"tool": "subfinder", "target": target, **parse_output(raw)}
