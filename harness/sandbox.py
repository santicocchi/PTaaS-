"""Sandbox efímero del loop C (change 006, D3 y D4): un contenedor por solicitud.

`DockerSandbox` implementa el `Sender` del catálogo. Por cada envío:

1. barre los contenedores huérfanos del engagement (`ptaas.sandbox=<engagement>`);
2. verifica que la red del laboratorio sea `Internal: true` (si no, no envía);
3. lanza `docker run --rm` con opciones fijas armadas acá, no configurables por el agente;
4. le pasa la solicitud por stdin y lee la respuesta por stdout (`lab/sandbox/send.py`);
5. en un `finally` destruye el contenedor y comprueba que ya no exista.

Solo se apunta a la IP que validó el Harness (`addresses`), con el nombre en `Host`. Docker se
ejecuta con un runner inyectable: los tests nunca necesitan docker.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

from harness.adapters.common import safe_env
from harness.poc.catalog import ResponseRecord
from harness.policy_loader import load_policy

DOCKER = "docker"
LAB_NETWORK = "lab_lab"            # red `lab` de lab/docker-compose.yml (proyecto `lab`)
LABEL = "ptaas.sandbox"
NAME_PREFIX = "ptaas-sbx-"
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
_NETWORK_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\Z")
_IMAGE_RE = re.compile(r"^(ptaas-sandbox@)?sha256:[0-9a-f]{64}\Z")
_CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_FORBIDDEN_NETWORKS = frozenset({"host", "bridge", "none", "default"})
_METHODS = frozenset({"GET", "HEAD"})
_MAX_HEADERS = 100

# Opciones fijas del contenedor (D3). Sin volúmenes, sin variables de entorno, sin puertos.
_RUN_OPTIONS = (
    "--rm", "-i", "--read-only", "--tmpfs", "/tmp:size=1m", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--user", "65534:65534", "--memory", "128m",
    "--pids-limit", "32", "--cpus", "0.5",
)


class SandboxTimeout(Exception):
    """El runner cortó el comando por tiempo."""


class SandboxFailure(Exception):
    """El envío no produjo una respuesta. `kind` es `sandbox_error` o `timeout`."""

    def __init__(self, kind: str, detail: str, sandbox_id: str | None = None,
                 request: SandboxRequest | None = None) -> None:
        if kind not in ("sandbox_error", "timeout"):
            raise ValueError(f"tipo de fallo desconocido: {kind}")
        super().__init__(f"{kind}: {detail}")
        self.kind, self.detail = kind, detail
        self.sandbox_id, self.request = sandbox_id, request


class SandboxCleanupFailed(SandboxFailure):
    """Quedó un contenedor vivo: el loop C se detiene para todo el engagement (D8)."""

    def __init__(self, detail: str, sandbox_id: str | None = None,
                 request: SandboxRequest | None = None) -> None:
        super().__init__("sandbox_error", detail, sandbox_id, request)


@dataclass(frozen=True)
class SandboxLimits:
    request_timeout_s: int
    container_timeout_s: int
    max_response_bytes: int
    max_requests_per_finding: int
    max_requests_per_engagement: int


def load_limits(policy: dict[str, Any] | None = None) -> SandboxLimits:
    raw = (policy or load_policy())["sandbox"]["limits"]
    values = {}
    for name in SandboxLimits.__dataclass_fields__:
        value = raw.get(name)
        if type(value) is not int or value < 1:
            raise ValueError(f"sandbox.limits.{name} inválido: {value!r}")
        values[name] = value
    return SandboxLimits(**values)


@dataclass(frozen=True)
class SandboxRequest:
    method: str
    path: str
    host: str          # encabezado Host
    ip: str            # IP fijada por el Harness
    port: int


@dataclass(frozen=True)
class SandboxResponse:
    sandbox_id: str
    request: SandboxRequest
    record: ResponseRecord
    truncated: bool


# runner(argv, stdin, timeout_s) -> (código de salida, stdout). Lanza SandboxTimeout.
DockerRunner = Callable[[list[str], str | None, int], tuple[int, str]]


def default_docker_runner(argv: list[str], stdin: str | None, timeout_s: int) -> tuple[int, str]:
    """Ejecuta el CLI de docker SIN shell, con timeout y sin los secretos del entorno."""
    try:
        proc = subprocess.run(argv, shell=False, input=stdin or "", capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout_s, check=False, env=safe_env())
    except subprocess.TimeoutExpired as exc:
        raise SandboxTimeout() from exc
    except OSError:                                      # docker no instalado, sin permiso
        return 127, ""
    return proc.returncode, proc.stdout


def build_request(method: str, params: dict[str, str], address: str) -> SandboxRequest:
    """La solicitud sale de los parámetros declarados y de la IP fijada. Lanza ValueError."""
    if method not in _METHODS:
        raise ValueError(f"método no permitido: {method!r}")
    url = urlsplit(params["base_url"])
    if url.scheme != "http" or not url.hostname or url.username or url.password \
            or url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("base_url inválida")
    path = params["path"]
    # Tiene que empezar con "/": sin eso, "@otro.host/x" cambiaría el destino.
    if not path.startswith("/") or path.startswith("//") or any(c <= " " or c == "\x7f"
                                                                 for c in path):
        raise ValueError(f"ruta inválida: {path!r}")
    if "param_name" in params and "canary" in params:
        path += ("&" if "?" in path else "?") + urlencode({params["param_name"]:
                                                           params["canary"]})
    ip = str(ipaddress.ip_address(address))               # un nombre no es una IP fijada
    port = url.port or 80
    host = url.hostname if port == 80 else f"{url.hostname}:{port}"
    return SandboxRequest(method, path, host, ip, port)


class BoundSender:
    """`Sender` atado a una IP fijada. Guarda la última respuesta para la evidencia."""

    def __init__(self, sandbox: DockerSandbox, address: str) -> None:
        self.sandbox, self.address = sandbox, address
        self.last: SandboxResponse | None = None
        self.last_params: dict[str, str] = {}       # con el canario de este intento

    def __call__(self, poc_id: str, params: dict[str, str]) -> ResponseRecord:
        self.last, self.last_params = None, dict(params)
        self.last = self.sandbox.send(poc_id, params, self.address)
        return self.last.record


class DockerSandbox:
    def __init__(self, engagement_id: str, catalog: dict[str, dict[str, Any]], *, image: str,
                 network: str = LAB_NETWORK, limits: SandboxLimits | None = None,
                 runner: DockerRunner = default_docker_runner) -> None:
        if not _ENGAGEMENT_RE.match(engagement_id):
            raise ValueError(f"engagement_id inválido: {engagement_id!r}")
        if not _NETWORK_RE.match(network) or network.lower() in _FORBIDDEN_NETWORKS:
            raise ValueError(f"red no permitida para el sandbox: {network!r}")
        if not _IMAGE_RE.match(image):
            raise ValueError("la imagen del sandbox va fijada por digest (sha256)")
        self.engagement_id, self.catalog = engagement_id, catalog
        self.image, self.network = image, network
        self.limits = limits or load_limits()
        self.runner = runner

    # -- argv fijos ----------------------------------------------------------------------
    @staticmethod
    def new_name() -> str:
        return f"{NAME_PREFIX}{uuid.uuid4().hex}"

    def run_argv(self, name: str, *, diagnostic: bool = False) -> list[str]:
        argv = [DOCKER, "run", *_RUN_OPTIONS, "--network", self.network,
                "--label", f"{LABEL}={self.engagement_id}", "--name", name, self.image]
        if diagnostic:                 # solo el test de red del laboratorio (D3)
            argv.append("--diagnostic")
        return argv

    def _docker(self, argv: list[str], stdin: str | None = None,
                timeout_s: int | None = None) -> tuple[int, str]:
        return self.runner(argv, stdin, timeout_s or self.limits.container_timeout_s)

    # -- ciclo de vida -------------------------------------------------------------------
    def _listed(self, filter_: str) -> list[str]:
        code, out = self._docker([DOCKER, "ps", "-aq", "--filter", filter_])
        if code != 0:
            raise SandboxCleanupFailed("no se pudo listar contenedores")
        return [line.strip() for line in out.splitlines() if line.strip()]

    def sweep(self) -> None:
        """Destruye los contenedores del engagement que quedaron de una corrida anterior."""
        label = f"label={LABEL}={self.engagement_id}"
        for container in self._listed(label):
            if _CONTAINER_RE.match(container):
                self._docker([DOCKER, "rm", "-f", container])
        left = self._listed(label)
        if left:
            raise SandboxCleanupFailed("huérfanos vivos", sandbox_id=left[0])

    def _destroy(self, name: str, request: SandboxRequest | None) -> None:
        try:
            self._docker([DOCKER, "rm", "-f", name])
            alive = self._listed(f"name=^/{name}$")
        except SandboxTimeout:
            alive = [name]
        except SandboxCleanupFailed:
            alive = [name]
        if alive:
            raise SandboxCleanupFailed("el contenedor sigue vivo", name, request)

    def _network_internal(self) -> bool:
        code, out = self._docker([DOCKER, "network", "inspect", "--format",
                                  "{{json .Internal}}", self.network])
        return code == 0 and out.strip() == "true"

    def bind(self, address: str) -> BoundSender:
        return BoundSender(self, address)

    def send(self, poc_id: str, params: dict[str, str], address: str) -> SandboxResponse:
        entry = self.catalog.get(poc_id)
        if entry is None:
            raise SandboxFailure("sandbox_error", "poc fuera del catálogo")
        try:
            request = build_request(str(entry["method"]), params, address)
        except (ValueError, KeyError) as exc:
            raise SandboxFailure("sandbox_error", f"solicitud inválida: {exc}") from exc
        try:
            self.sweep()
        except SandboxTimeout as exc:
            raise SandboxCleanupFailed("barrido de huérfanos sin respuesta") from exc
        try:
            internal = self._network_internal()
        except SandboxTimeout:
            internal = False
        if not internal:
            raise SandboxFailure("sandbox_error", "network_not_internal", request=request)
        name = self.new_name()
        payload = json.dumps({"method": request.method, "path": request.path,
                              "host": request.host, "ip": request.ip, "port": request.port,
                              "timeout_s": self.limits.request_timeout_s,
                              "max_bytes": self.limits.max_response_bytes})
        try:
            try:
                code, out = self._docker(self.run_argv(name), payload,
                                         self.limits.container_timeout_s)
            except SandboxTimeout as exc:
                raise SandboxFailure("timeout", "container_timeout", name, request) from exc
            record, truncated = self._parse(code, out, name, request)
        finally:
            self._destroy(name, request)       # haya salido bien o mal (D3, paso 5)
        return SandboxResponse(name, request, record, truncated)

    def _parse(self, code: int, out: str, name: str,
               request: SandboxRequest) -> tuple[ResponseRecord, bool]:
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = None
        if not isinstance(data, dict):
            raise SandboxFailure("sandbox_error", f"salida inválida (código {code})", name,
                                 request)
        if data.get("ok") is not True or code != 0:
            kind = "timeout" if data.get("error") == "timeout" else "sandbox_error"
            raise SandboxFailure(kind, str(data.get("error") or f"código {code}"), name,
                                 request)
        status, headers, body = data.get("status"), data.get("headers"), data.get("body")
        if type(status) is not int or not isinstance(headers, list) \
                or not isinstance(body, str) or len(headers) > _MAX_HEADERS:
            raise SandboxFailure("sandbox_error", "respuesta mal formada", name, request)
        plain: dict[str, str] = {}
        cookies: list[str] = []
        for h in headers:
            if not (isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h)):
                raise SandboxFailure("sandbox_error", "encabezado mal formado", name, request)
            if h[0].lower() == "set-cookie":
                cookies.append(h[1])
            else:
                plain[h[0]] = h[1]
        raw = body.encode("utf-8")
        truncated = data.get("truncated") is True or len(raw) > self.limits.max_response_bytes
        if len(raw) > self.limits.max_response_bytes:          # truncar nunca suma un positivo
            body = raw[:self.limits.max_response_bytes].decode("utf-8", "ignore")
        return ResponseRecord(status, plain, body, tuple(cookies)), truncated
