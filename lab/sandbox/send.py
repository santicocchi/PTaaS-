"""Script del sandbox (change 006, D3): UNA solicitud HTTP a una IP del laboratorio y termina.

Lee por stdin un JSON con la solicitud (método, path, Host, IP fijada, puerto y límites) y
escribe por stdout un JSON con la respuesta. Sin dependencias externas (`http.client`), sin
proxy, sin redirecciones y sin escribir a disco.

`--diagnostic` omite la lista de IP del laboratorio. Solo lo usa el test de red
(tests/validation/test_sandbox.py, marcado `lab`) para probar que la RED no deja salir.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import sys
from typing import Any

LAB_NETWORK = ipaddress.ip_network("10.99.0.0/24")      # lab/docker-compose.yml, red `lab`
_FIELDS = {"method", "path", "host", "ip", "port", "timeout_s", "max_bytes"}
_HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}(:\d{1,5})?$")
_MAX_BYTES = 1024 * 1024


class RequestError(ValueError):
    pass


def parse_request(raw: str, *, diagnostic: bool) -> dict[str, Any]:
    try:
        req = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RequestError("no es JSON") from exc
    if not isinstance(req, dict) or set(req) != _FIELDS:
        raise RequestError("campos inesperados")
    if req["method"] not in ("GET", "HEAD"):
        raise RequestError("método no permitido")
    path = req["path"]
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") \
            or any(c <= " " or c == "\x7f" for c in path) or len(path) > 2048:
        raise RequestError("ruta inválida")
    if not isinstance(req["host"], str) or not _HOST_RE.match(req["host"]):
        raise RequestError("Host inválido")
    try:
        ip = ipaddress.ip_address(req["ip"])
    except (ValueError, TypeError) as exc:
        raise RequestError("IP inválida") from exc
    if not diagnostic and ip not in LAB_NETWORK:            # defensa en profundidad
        raise RequestError("IP fuera del laboratorio")
    for key, top in (("port", 65535), ("timeout_s", 30), ("max_bytes", _MAX_BYTES)):
        if type(req[key]) is not int or not 1 <= req[key] <= top:
            raise RequestError(f"{key} inválido")
    return req


def send(req: dict[str, Any]) -> dict[str, Any]:
    conn = http.client.HTTPConnection(req["ip"], req["port"], timeout=req["timeout_s"])
    try:
        conn.request(req["method"], req["path"], headers={
            "Host": req["host"], "User-Agent": "ptaas-sandbox", "Accept": "*/*",
            "Connection": "close"})
        resp = conn.getresponse()
        data = resp.read(req["max_bytes"] + 1)
    except TimeoutError:
        return {"ok": False, "error": "timeout"}
    except (OSError, http.client.HTTPException):
        return {"ok": False, "error": "connect_error"}
    finally:
        conn.close()
    truncated = len(data) > req["max_bytes"]
    return {"ok": True, "status": resp.status,
            "headers": [[k, v] for k, v in resp.getheaders()],
            "body": data[:req["max_bytes"]].decode("utf-8", "replace"),
            "truncated": truncated}


def main(argv: list[str]) -> int:
    try:
        req = parse_request(sys.stdin.read(), diagnostic="--diagnostic" in argv)
    except RequestError as exc:
        print(json.dumps({"ok": False, "error": "invalid_request", "detail": str(exc)}))
        return 2
    out = send(req)
    print(json.dumps(out))
    return 0 if out["ok"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
