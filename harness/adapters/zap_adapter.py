"""Adaptador zap.baseline_scan (change 005, D7). Verificado con ZAP 2.17.0 en modo daemon.

ZAP corre como servicio del laboratorio. El adaptador no lanza procesos: le habla a la API con un
conjunto FIJO de endpoints, sin ninguno de escaneo activo. Por cada invocación:

1. modo `protect`;
2. contexto que incluye solo `http://<ip>(:<puerto>)?/`;
3. regla del replacer que fija `Host: <nombre>` (la conexión va a la IP que validó el Harness);
4. rate limit de ZAP con el valor de policy.yaml;
5. spider acotado (hilos, profundidad, duración), limitado al contexto;
6. espera del escaneo pasivo;
7. lectura de alertas de esa IP;
8. limpieza (contexto y reglas), pase lo que pase.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from typing import Any, Protocol
from urllib.parse import urlsplit

from harness.adapters.common import InvalidTarget, load_profiles, tool_error, validate_target
from harness.adapters.recon_output import clean_text, status_of
from harness.contracts import Action, Phase, ScopeToken, _is_ip
from harness.policy_loader import load_policy

# Lo único que el adaptador puede pedirle a ZAP. Ningún `/ascan/` (lo verifica un test).
ENDPOINTS = frozenset({
    "/JSON/core/action/setMode/",
    "/JSON/context/action/newContext/",
    "/JSON/context/action/includeInContext/",
    "/JSON/context/action/removeContext/",
    "/JSON/replacer/action/addRule/",
    "/JSON/replacer/action/removeRule/",
    "/JSON/network/action/addRateLimitRule/",
    "/JSON/network/action/removeRateLimitRule/",
    "/JSON/spider/action/setOptionThreadCount/",
    "/JSON/spider/action/setOptionMaxDepth/",
    "/JSON/spider/action/setOptionMaxDuration/",
    "/JSON/spider/action/setOptionMaxChildren/",
    "/JSON/spider/action/scan/",
    "/JSON/spider/action/stop/",
    "/JSON/spider/view/status/",
    "/JSON/pscan/view/recordsToScan/",
    "/JSON/core/view/alerts/",
})
RISKS = ("Informational", "Low", "Medium", "High")
CONFIDENCES = ("False Positive", "Low", "Medium", "High", "Confirmed")
PortsOf = Callable[[str], Sequence[int]]


class ZapError(Exception):
    def __init__(self, kind: str) -> None:       # exec_error | timeout | invalid_output
        super().__init__(kind)
        self.kind = kind


class ZapClient(Protocol):
    def call(self, path: str, params: dict[str, str]) -> dict[str, Any]: ...


class HttpZapClient:
    """Cliente mínimo de la API de ZAP: sin proxy, con clave, y solo endpoints permitidos."""

    def __init__(self, base_url: str, api_key: str, timeout_s: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._timeout = timeout_s
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        if path not in ENDPOINTS:
            raise ValueError(f"endpoint de ZAP no permitido: {path}")
        query = urllib.parse.urlencode({**params, "apikey": self._key})
        try:
            with self._opener.open(f"{self._base}{path}?{query}", timeout=self._timeout) as r:
                data = json.loads(r.read(5_000_000).decode("utf-8", "replace"))
        except TimeoutError as exc:
            raise ZapError("timeout") from exc
        except urllib.error.HTTPError as exc:
            raise ZapError("exec_error") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ZapError("exec_error") from exc
        except json.JSONDecodeError as exc:
            raise ZapError("invalid_output") from exc
        if not isinstance(data, dict) or "code" in data:   # ZAP contesta errores con "code"
            raise ZapError("exec_error")
        return data


def _regex_escape(text: str) -> str:
    return "".join("\\" + c if c in ".^$*+?{}[]\\|()" else c for c in text)


def _netloc(ip: str, port: int) -> str:
    host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    return host if port == 80 else f"{host}:{port}"


def parse_alerts(target: str, ip: str, port: int, alerts: Any) -> tuple[list[dict[str, Any]],
                                                                       int]:
    """Alertas de ZAP → registros validados. Lo que no es de la IP y el puerto analizados se
    descarta y se cuenta como inválido."""
    if not isinstance(alerts, list):
        return [], 1
    out: dict[tuple[str, str], dict[str, Any]] = {}
    invalid = 0
    for a in alerts:
        try:
            url = urlsplit(a["url"])
            if url.scheme != "http" or url.hostname is None or \
                    str(ipaddress.ip_address(url.hostname)) != ip or (url.port or 80) != port:
                invalid += 1
                continue
            plugin, risk, conf = str(a["pluginId"]), a["risk"], a["confidence"]
            if not plugin.isdigit() or risk not in RISKS or conf not in CONFIDENCES:
                invalid += 1
                continue
            cweid = int(a.get("cweid", -1))
            path = clean_text(url.path or "/", 200) or "/"
            rec = {"plugin_id": plugin, "alert": clean_text(a.get("alert"), 120) or plugin,
                   "risk": risk, "confidence": conf,
                   "cwe": f"CWE-{cweid}" if 0 < cweid < 100000 else "unknown",
                   "url": f"http://{target}:{port}{path}", "address": ip, "port": port,
                   "evidence": clean_text(a.get("evidence"), 200),
                   "param": clean_text(a.get("param"), 80)}
            out.setdefault((plugin, path), rec)
        except (KeyError, TypeError, ValueError, AttributeError):
            invalid += 1
    return list(out.values()), invalid


class ZapBaselineScan:
    name: str = "zap.baseline_scan"
    allowed_phases: tuple[Phase, ...] = (Phase.ANALYZE,)
    destructive: bool = False

    def __init__(self, client: ZapClient | None = None, profile: dict[str, Any] | None = None,
                 *, ports_of: PortsOf | None = None, rps: int | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._profile = profile or load_profiles()["zap"]
        self._client = client
        self._ports_of = ports_of or (lambda host: (80,))
        self._sleep, self._clock = sleep, clock
        self.rps = rps if rps is not None else int(
            load_policy()["limits"]["rate_limit_rps_per_target"])

    def _get_client(self) -> ZapClient | None:
        if self._client is not None:
            return self._client
        key = os.environ.get(self._profile["api_key_env"], "")
        if not key:
            return None                    # sin clave no se manda nada
        return HttpZapClient(self._profile["api_url"], key)

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        host = validate_target(target)
        try:
            ips = [str(ipaddress.ip_address(validate_target(a))) for a in addresses]
        except ValueError as exc:
            raise InvalidTarget(f"direcciones inválidas: {addresses!r}") from exc
        ports = sorted(set(self._ports_of(host)))
        if not ips or not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise InvalidTarget("ZAP sin IP o puertos válidos")
        client = self._get_client()
        if client is None:
            return tool_error("zap", target, "exec_error")
        alerts: list[dict[str, Any]] = []
        invalid = 0
        try:
            for ip in ips:
                for port in ports:
                    found, bad = self._scan(client, host, ip, port)
                    alerts += found
                    invalid += bad
        except ZapError as exc:
            return tool_error("zap", target, exc.kind)
        return {"tool": "zap", "target": target, "status": status_of(len(alerts), invalid)
                if alerts or invalid else "ok", "alerts": alerts, "invalid_lines": invalid}

    def _scan(self, client: ZapClient, host: str, ip: str, port: int) -> tuple[
            list[dict[str, Any]], int]:
        p, spider = self._profile, self._profile["spider"]
        name = f"ptaas-{uuid.uuid4().hex[:12]}"
        netloc = _netloc(ip, port)
        base = f"http://{netloc}/"
        port_re = "(:80)?" if port == 80 else f":{port}"
        host_re = _regex_escape(f"[{ip}]" if ":" in ip else ip)
        try:
            client.call("/JSON/core/action/setMode/", {"mode": "protect"})
            client.call("/JSON/context/action/newContext/", {"contextName": name})
            client.call("/JSON/context/action/includeInContext/",
                        {"contextName": name, "regex": f"^http://{host_re}{port_re}/.*"})
            if not _is_ip(host):
                client.call("/JSON/replacer/action/addRule/", {
                    "description": name, "enabled": "true", "matchType": "REQ_HEADER",
                    "matchRegex": "false", "matchString": "Host", "replacement": host,
                    "initiators": ""})
            client.call("/JSON/network/action/addRateLimitRule/", {
                "description": name, "enabled": "true", "matchString": ip,
                "matchRegex": "false", "requestsPerSecond": str(self.rps), "groupBy": "host"})
            client.call("/JSON/spider/action/setOptionThreadCount/",
                        {"Integer": str(spider["threads"])})
            client.call("/JSON/spider/action/setOptionMaxDepth/",
                        {"Integer": str(spider["max_depth"])})
            client.call("/JSON/spider/action/setOptionMaxDuration/",
                        {"Integer": str(spider["max_duration_min"])})
            client.call("/JSON/spider/action/setOptionMaxChildren/",
                        {"Integer": str(spider["max_children"])})
            scan = client.call("/JSON/spider/action/scan/", {
                "url": base, "contextName": name, "subtreeOnly": "true", "recurse": "true",
                "maxChildren": str(spider["max_children"])})
            scan_id = str(scan.get("scan", ""))
            if not scan_id.isdigit():
                raise ZapError("invalid_output")
            deadline = self._clock() + p["max_wait_s"]
            self._wait(lambda: client.call("/JSON/spider/view/status/",
                                           {"scanId": scan_id}).get("status") == "100",
                       deadline)
            self._wait(lambda: str(client.call("/JSON/pscan/view/recordsToScan/", {}).get(
                "recordsToScan")) == "0", deadline)
            raw = client.call("/JSON/core/view/alerts/", {"baseurl": base.rstrip("/")})
            return parse_alerts(host, ip, port, raw.get("alerts"))
        finally:
            self._cleanup(client, name, host)

    def _wait(self, done: Callable[[], bool], deadline: float) -> None:
        while not done():
            if self._clock() >= deadline:
                raise ZapError("timeout")
            self._sleep(self._profile["poll_s"])

    @staticmethod
    def _cleanup(client: ZapClient, name: str, host: str) -> None:
        steps = [("/JSON/spider/action/stop/", {}),
                 ("/JSON/context/action/removeContext/", {"contextName": name}),
                 ("/JSON/network/action/removeRateLimitRule/", {"description": name})]
        if not _is_ip(host):
            steps.append(("/JSON/replacer/action/removeRule/", {"description": name}))
        for path, params in steps:
            try:
                client.call(path, params)
            except ZapError:
                pass                       # limpiar es lo mejor posible; el error real ya salió
