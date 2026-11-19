"""Adaptador nmap.service_scan: detección de servicios acotada y sin scripts."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Sequence
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
from harness.adapters.recon_output import clean_text, status_of
from harness.contracts import Action, Phase, ScopeToken, _is_ip, normalize_target


def build_argv(targets: str | Sequence[str], profile: dict[str, Any] | None = None) -> list[str]:
    p = profile or load_profiles()["nmap"]
    items = [targets] if isinstance(targets, str) else list(targets)
    if not items:
        raise InvalidTarget("nmap sin objetivos")
    ts = [validate_target(t, allow_cidr=True) for t in items]
    argv = [p["binary"], *p["fixed_args"], "--max-rate", str(p["max_rate_pps"]),
            "-oX", "-", *ts]
    reject_forbidden(argv, p["forbidden_args"])
    return argv


def _service(address: str, port: ET.Element) -> dict[str, Any] | None:
    try:
        portid = int(port.get("portid", ""))
    except ValueError:
        return None
    if not 1 <= portid <= 65535:
        return None
    svc = port.find("service")

    def get(key: str) -> str | None:
        return clean_text(svc.get(key), 100) if svc is not None else None

    product, version = get("product"), get("version")
    tech = f"{product}:{version}" if product and version else product or None
    return {"address": address, "port": portid, "protocol": port.get("protocol") or "tcp",
            "service": get("name"), "tech": tech}


def parse_output(raw: str) -> dict[str, Any]:
    """Puertos abiertos de la salida XML de nmap. Es salida de una herramienta: no confiable.

    `xml.etree` (expat) no resuelve entidades externas y expat ≥ 2.4 corta la expansión
    exponencial de entidades.
    """
    if not raw.strip():
        return {"status": "ok", "services": [], "invalid_lines": 0}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"status": "invalid_output", "services": [], "invalid_lines": 1}
    services: list[dict[str, Any]] = []
    invalid = 0
    for host in root.iter("host"):
        addr = host.find("address")
        address = normalize_target(addr.get("addr", "")) if addr is not None else None
        if address is None or not _is_ip(address):
            invalid += 1
            continue
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            rec = _service(address, port)
            if rec is None:
                invalid += 1
            else:
                services.append(rec)
    return {"status": status_of(len(services), invalid), "services": services,
            "invalid_lines": invalid}


class NmapServiceScan:
    name: str = "nmap.service_scan"
    allowed_phases: tuple[Phase, ...] = (Phase.RECON,)
    destructive: bool = False

    def __init__(self, runner: Runner = default_runner, profile: dict[str, Any] | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["nmap"]

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        # Escanea las IP que validó el Harness, nunca el nombre (DNS rebinding, 004).
        argv = build_argv(addresses, self._profile)
        raw, error = run_tool(self._runner, argv, self._profile["timeout_s"])
        if raw is None:
            return tool_error("nmap", target, str(error))
        return {"tool": "nmap", "target": target, "format": "xml", "raw": raw,
                **parse_output(raw)}
