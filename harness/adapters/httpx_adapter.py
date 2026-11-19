"""Adaptador httpx.probe: sondeo HTTP liviano contra la IP validada (change 004).

httpx no resuelve el nombre: se le pasa `http://<ip>` y el nombre va en `Host` (DNS
rebinding). No sigue redirecciones (A5): el `Location` vuelve como dato y el orquestador lo
trata como un descubrimiento más, que pasa por el filtro de alcance.
"""
from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

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
from harness.adapters.recon_output import Record, clean_text, parse_lines, status_of
from harness.contracts import Action, Phase, ScopeToken, _is_ip
from harness.policy_loader import load_policy


def _url_for(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return f"http://[{addr}]" if addr.version == 6 else f"http://{addr}"


def _validated_ips(addresses: tuple[str, ...]) -> list[str]:
    if not addresses:
        raise InvalidTarget("httpx sin IP validada: no se sondea")
    ips = []
    for a in addresses:
        try:
            ips.append(str(ipaddress.ip_address(a)))
        except ValueError as exc:
            raise InvalidTarget(f"dirección inválida: {a!r}") from exc
    return ips


def build_argv(target: str, addresses: tuple[str, ...], profile: dict[str, Any] | None = None,
               *, rps: int) -> list[str]:
    p = profile or load_profiles()["httpx"]
    host = validate_target(target)
    argv = [p["binary"]]
    for ip in _validated_ips(addresses):
        argv += ["-u", _url_for(ip)]
    if not _is_ip(host):
        argv += ["-H", f"Host: {host}"]
    argv += ["-rl", str(int(rps)), *p["fixed_args"]]
    reject_forbidden(argv, p["forbidden_args"])
    return argv


def _service(target: str, allowed: set[str] | None) -> Any:
    def parse(obj: dict[str, Any]) -> Record | None:
        try:
            url = obj["url"]
            status = obj["status_code"]
            port = int(str(obj.get("port") or 80))
            tech = obj.get("tech") or []
            if not isinstance(url, str) or type(status) is not int or not 100 <= status <= 599:
                return None
            if not 1 <= port <= 65535 or not isinstance(tech, list):
                return None
            parts = urlsplit(url)
            address = str(ipaddress.ip_address(parts.hostname or ""))
            if allowed is not None and address not in allowed:
                return None                 # contestó algo que no le pedimos
            scheme = parts.scheme if parts.scheme in ("http", "https") else "http"
            location = clean_text(obj.get("location"), 2048)
            return {
                "url": f"{scheme}://{target}:{port}",
                "address": address,
                "port": port,
                "status_code": status,
                "title": clean_text(obj.get("title")),
                "webserver": clean_text(obj.get("webserver")),
                "tech": [t for t in (clean_text(x) for x in tech) if t],
                "location": location or None,
            }
        except (KeyError, TypeError, ValueError):
            return None
    return parse


def parse_output(target: str, raw: str,
                 addresses: tuple[str, ...] | None = None) -> dict[str, Any]:
    allowed = None if addresses is None else {str(ipaddress.ip_address(a)) for a in addresses}
    valid, invalid = parse_lines(raw, _service(target, allowed))
    return {"status": status_of(len(valid), invalid), "services": valid,
            "invalid_lines": invalid}


class HttpxProbe:
    name = "httpx.probe"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner = default_runner, profile: dict[str, Any] | None = None,
                 rps: int | None = None) -> None:
        self._runner = runner
        self._profile = profile or load_profiles()["httpx"]
        self.rps = rps if rps is not None else int(
            load_policy()["limits"]["rate_limit_rps_per_target"])

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        argv = build_argv(target, addresses, self._profile, rps=self.rps)
        raw, error = run_tool(self._runner, argv, self._profile["timeout_s"])
        if raw is None:
            return tool_error("httpx", target, str(error))
        return {"tool": "httpx", "target": target, **parse_output(target, raw, addresses)}
