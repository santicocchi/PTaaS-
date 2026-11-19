"""Utilidades comunes de adaptadores: validación de target y ejecución sin shell."""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import yaml

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_PROFILES = Path(__file__).resolve().parent.parent / "profiles.yaml"


class InvalidTarget(ValueError): ...
class ForbiddenArgument(ValueError): ...


TOOL_ERRORS = frozenset({"timeout", "binary_missing", "exit_code", "invalid_output"})


class ToolFailure(Exception):
    """La herramienta no terminó bien. `kind` es uno de TOOL_ERRORS."""

    def __init__(self, kind: str) -> None:
        if kind not in TOOL_ERRORS:
            raise ValueError(f"tipo de error desconocido: {kind}")
        super().__init__(kind)
        self.kind = kind


def load_profiles(path: Path = _PROFILES) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_target(target: str, allow_cidr: bool = False) -> str:
    """Acepta IP, CIDR (si allow_cidr) o hostname FQDN. Rechaza todo lo demás
    (espacios, flags que empiecen con '-', metacaracteres de shell, esquemas)."""
    t = target.strip().lower()
    if not t or t.startswith("-"):
        raise InvalidTarget(f"target inválido: {target!r}")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if allow_cidr:
        try:
            ipaddress.ip_network(t, strict=False)
            return t
        except ValueError:
            pass
    if _HOST_RE.match(t):
        return t
    raise InvalidTarget(f"target inválido: {target!r}")


def validate_url(url: str) -> str:
    """Solo http(s)://host[:puerto][/ruta] sin credenciales embebidas."""
    m = re.match(r"^(https?)://([^/:@\s]+)(:\d{1,5})?(/[^\s]*)?$", url.strip())
    if not m:
        raise InvalidTarget(f"URL inválida: {url!r}")
    validate_target(m.group(2))
    return url.strip()


def reject_forbidden(argv: list[str], forbidden: list[str]) -> None:
    for a in argv:
        for f in forbidden:
            if a == f or a.startswith(f + "="):
                raise ForbiddenArgument(f"argumento prohibido: {a}")


Runner = Callable[[list[str], int], str]

_SECRET_PREFIXES = ("PTAAS_", "ANTHROPIC_", "AWS_", "GITHUB_", "GH_")


def safe_env() -> dict[str, str]:
    """Entorno para las herramientas: sin secretos del harness, sin credenciales y sin proxy
    (el tráfico al laboratorio nunca sale por un proxy; httpx lo tomaría del entorno)."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(_SECRET_PREFIXES) and not _is_proxy_var(k)}


def _is_proxy_var(name: str) -> bool:
    """HTTPS_PROXY, http_proxy, ALL_PROXY y variantes (npm_config_https_proxy…), menos NO_PROXY."""
    low = name.lower()
    return low.endswith("_proxy") and low != "no_proxy"


def default_runner(argv: list[str], timeout_s: int) -> str:
    """Ejecuta SIN shell, con timeout. Se inyecta un fake en los tests.

    Lanza ToolFailure si el binario no está, si se pasa del timeout o si sale con error.
    """
    try:
        # stdin vacío: httpx (y otras) leen objetivos de stdin si es un pipe.
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout_s, check=False,
                              env=safe_env())
    except FileNotFoundError as exc:
        raise ToolFailure("binary_missing") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolFailure("timeout") from exc
    if proc.returncode != 0:
        raise ToolFailure("exit_code")
    return proc.stdout


def run_tool(runner: Runner, argv: list[str], timeout_s: int) -> tuple[str, None] | tuple[
        None, str]:
    """(salida, None) si anduvo; (None, tipo de error) si no. Nunca lanza por la herramienta."""
    try:
        return runner(argv, timeout_s), None
    except ToolFailure as exc:
        return None, exc.kind
    except FileNotFoundError:
        return None, "binary_missing"
    except subprocess.TimeoutExpired:
        return None, "timeout"


def tool_error(tool: str, target: str, kind: str) -> dict[str, str]:
    return {"tool": tool, "target": target, "status": "error", "error": kind}
