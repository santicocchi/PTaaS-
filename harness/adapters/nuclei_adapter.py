"""Adaptador nuclei.safe_templates (change 005, D7 y D9).

Recibe un host canónico (nunca una URL armada por el agente, red team 4.1). Sondea la IP que
validó el Harness con el nombre en `Host`, sin redirecciones, y solo con los templates del
manifiesto que tienen revisor y cuyo hash coincide. Verificado con nuclei v3.11.1.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
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
from harness.adapters.recon_output import clean_text, status_of
from harness.contracts import Action, Phase, ScopeToken, _is_ip
from harness.policy_loader import load_policy
from harness.templates import ALLOWLIST, runnable

_TEMPLATE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")
_CWE = re.compile(r"^cwe-(\d{1,5})$", re.IGNORECASE)
PortsOf = Callable[[str], Sequence[int]]


def _ips(addresses: tuple[str, ...]) -> list[str]:
    if not addresses:
        raise InvalidTarget("nuclei sin direcciones validadas")
    out = []
    for a in addresses:
        try:
            ip = ipaddress.ip_address(validate_target(a))
        except ValueError as exc:                         # un nombre no es una IP fijada
            raise InvalidTarget(f"dirección inválida: {a!r}") from exc
        out.append(f"[{ip}]" if ip.version == 6 else str(ip))
    return out


def build_argv(target: str, addresses: tuple[str, ...], templates: Sequence[Path],
               ports: Sequence[int] = (80,), profile: dict[str, Any] | None = None, *,
               rps: int) -> list[str]:
    p = profile or load_profiles()["nuclei"]
    host = validate_target(target)                        # un host, no una URL (4.1)
    if not templates:
        raise InvalidTarget("nuclei sin templates habilitados")
    if not ports or any(type(x) is not int or not 1 <= x <= 65535 for x in ports):
        raise InvalidTarget(f"puertos inválidos: {ports!r}")
    argv = [p["binary"]]
    for ip in _ips(addresses):
        for port in sorted(set(ports)):
            argv += ["-u", f"http://{ip}:{port}"]
    if not _is_ip(host):
        argv += ["-H", f"Host: {host}"]
    for t in templates:
        argv += ["-t", str(t)]
    argv += ["-tags", ",".join(p["include_tags"]), "-etags", ",".join(p["exclude_tags"]),
             "-rl", str(int(rps)), *p["fixed_args"]]
    overlap = set(p["include_tags"]) & set(p["exclude_tags"])
    if overlap:
        raise ValueError(f"tags incluidas y excluidas a la vez: {sorted(overlap)}")
    reject_forbidden(argv, p["forbidden_args"])
    return argv


def _finding(target: str, allowed_ips: set[str], allowed_ids: set[str],
             allowed_ports: set[int] | None = None) -> Any:
    def parse(obj: dict[str, Any]) -> dict[str, Any] | None:
        try:
            tid, ip, matched = obj["template-id"], obj["ip"], obj["matched-at"]
            if not isinstance(tid, str) or tid not in allowed_ids:
                return None                               # un template que no pedimos
            if str(ipaddress.ip_address(ip)) not in allowed_ips:
                return None                               # contestó otra IP
            parts = urlsplit(matched)
            if parts.hostname is None or str(ipaddress.ip_address(parts.hostname)) != str(
                    ipaddress.ip_address(ip)):
                return None
            port = parts.port or 80
            if allowed_ports is not None and port not in allowed_ports:
                return None                               # un puerto que no sondeamos
            raw_info = obj.get("info")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            raw_class = info.get("classification")
            classification: dict[str, Any] = raw_class if isinstance(raw_class, dict) else {}
            cwes = classification.get("cwe-id") or []
            cwe = next((f"CWE-{m.group(1)}" for c in (cwes if isinstance(cwes, list) else [])
                        if isinstance(c, str) and (m := _CWE.match(c))), "unknown")
            extracted = obj.get("extracted-results") or []
            evidence = [e for e in (clean_text(x, 120) for x in extracted[:5]) if e] \
                if isinstance(extracted, list) else []
            path = parts.path or "/"
            return {"template_id": tid, "cwe": cwe, "address": str(ipaddress.ip_address(ip)),
                    "port": port, "url": f"http://{target}:{port}{clean_text(path, 200)}",
                    "severity": clean_text(info.get("severity"), 20) or "unknown",
                    "evidence": evidence}
        except (KeyError, TypeError, ValueError):
            return None
    return parse


def parse_output(target: str, raw: str, addresses: tuple[str, ...],
                 template_ids: set[str], ports: Sequence[int] | None = None) -> dict[str, Any]:
    allowed = {str(ipaddress.ip_address(a)) for a in addresses}
    parse = _finding(target, allowed, template_ids, None if ports is None else set(ports))
    valid, invalid = [], 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        rec = parse(obj) if isinstance(obj, dict) else None
        if rec is None:
            invalid += 1
        else:
            valid.append(rec)
    return {"status": status_of(len(valid), invalid), "findings": valid, "invalid_lines": invalid}


class NucleiSafeTemplates:
    name: str = "nuclei.safe_templates"
    allowed_phases: tuple[Phase, ...] = (Phase.ANALYZE,)
    destructive: bool = False

    def __init__(self, runner: Runner = default_runner, profile: dict[str, Any] | None = None,
                 *, ports_of: PortsOf | None = None, templates_dir: Path = ALLOWLIST,
                 rps: int | None = None) -> None:
        self._runner = runner
        self._profile = profile or load_profiles()["nuclei"]
        self._ports_of = ports_of or (lambda host: (80,))
        self._templates_dir = templates_dir
        self.rps = rps if rps is not None else int(
            load_policy()["limits"]["rate_limit_rps_per_target"])

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        templates, skipped = runnable(self._templates_dir)   # hash y revisor, en cada corrida
        if not templates:
            return {"tool": "nuclei", "target": target, "status": "ok", "findings": [],
                    "invalid_lines": 0, "templates_run": [], "skipped": skipped}
        ports = tuple(self._ports_of(target))
        argv = build_argv(target, addresses, templates, ports, self._profile, rps=self.rps)
        raw, error = run_tool(self._runner, argv, self._profile["timeout_s"])
        if raw is None:
            return tool_error("nuclei", target, str(error))
        ids = {t.stem for t in templates if _TEMPLATE_ID.match(t.stem)}
        return {"tool": "nuclei", "target": target, "templates_run": sorted(ids),
                "skipped": skipped, **parse_output(target, raw, addresses, ids, ports)}
