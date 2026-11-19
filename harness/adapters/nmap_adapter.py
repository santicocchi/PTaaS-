"""Adaptador nmap.service_scan: detección de servicios acotada y sin scripts."""
from __future__ import annotations

from collections.abc import Sequence

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
from harness.contracts import Action, Phase, ScopeToken


def build_argv(targets: str | Sequence[str], profile: dict | None = None) -> list[str]:
    p = profile or load_profiles()["nmap"]
    items = [targets] if isinstance(targets, str) else list(targets)
    if not items:
        raise InvalidTarget("nmap sin objetivos")
    ts = [validate_target(t, allow_cidr=True) for t in items]
    argv = [p["binary"], *p["fixed_args"], "--max-rate", str(p["max_rate_pps"]),
            "-oX", "-", *ts]
    reject_forbidden(argv, p["forbidden_args"])
    return argv


class NmapServiceScan:
    name = "nmap.service_scan"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner = default_runner, profile: dict | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["nmap"]

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict:
        # Escanea las IP que validó el Harness, nunca el nombre (DNS rebinding, 004).
        argv = build_argv(addresses, self._profile)
        raw, error = run_tool(self._runner, argv, self._profile["timeout_s"])
        if raw is None:
            return tool_error("nmap", target, str(error))
        return {"tool": "nmap", "target": target, "format": "xml", "raw": raw}
