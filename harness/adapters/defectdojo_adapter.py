"""Adaptador `defectdojo.export` (change 007, D15): una sola llamada fija a DefectDojo.

Lo invoca el orquestador de entrega por `Harness.invoke`, con `subject` = `report_id`, después
del gate humano. Solo envía lo que el orquestador preparó para ESE informe (`stage`): vuelve a
leer el archivo, verifica el SHA-256 aprobado y arma la exportación desde ese archivo.

- `POST /api/v2/import-scan/` con `scan_type=Generic Findings Import`, el engagement de
  DefectDojo del RoE y `close_old_findings=false`;
- a la IP que validó el Harness, con `Host: <nombre>`, sin seguir redirecciones (http.client
  no las sigue), con timeout, respuesta acotada y sin variables de proxy;
- la clave sale de `PTAAS_DEFECTDOJO_API_KEY`, sin valor por defecto, y viaja solo en
  `Authorization: Token <clave>`: nunca en la URL, la bitácora, la evidencia ni los errores.

Los errores vuelven tipados (`timeout`, `exec_error`, `invalid_output`, `adapter_error`), sin
excepción ni detalle que pueda llevar la clave.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.contracts import Action, Phase, ScopeToken
from harness.defectdojo import SCAN_TYPE, ExportError, build_export, serialize
from harness.evidence import verify_evidence
from harness.policy_loader import defectdojo_limits

API_PATH = "/api/v2/import-scan/"
KEY_ENV = "PTAAS_DEFECTDOJO_API_KEY"


@dataclass(frozen=True)
class ExportRequest:
    report_id: str
    report_ref: str              # `reports/<eng>/report-v<N>.json#sha256=<hex>` aprobado
    port: int
    dd_engagement_id: int


@dataclass(frozen=True)
class HttpRequest:
    """La solicitud armada, para poder probarla sin red."""
    ip: str
    port: int
    host: str
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


Connector = Callable[[str, int, float], http.client.HTTPConnection]


def _connect(ip: str, port: int, timeout: float) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(ip, port, timeout=timeout)


def _error(kind: str) -> dict[str, Any]:
    return {"tool": "defectdojo", "status": "error", "error": kind}


def multipart(fields: dict[str, str], filename: str, payload: bytes) -> tuple[str, bytes]:
    boundary = "ptaas-" + secrets.token_hex(12)
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                     f"{value}\r\n".encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                 f'filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'.encode()
                 + payload + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", b"".join(parts)


class DefectDojoExport:
    name: str = "defectdojo.export"
    allowed_phases: tuple[Phase, ...] = (Phase.REPORT,)
    destructive: bool = False

    def __init__(self, *, state_dir: Path | str, connector: Connector = _connect,
                 limits: tuple[float, int] | None = None) -> None:
        self.state_dir = Path(state_dir)
        self.connector = connector
        self.timeout_s, self.max_response_bytes = limits or defectdojo_limits()
        self._staged: dict[str, ExportRequest] = {}

    def stage(self, request: ExportRequest) -> None:
        """Prepara el próximo envío de un informe. No envía nada."""
        self._staged[request.report_id] = request

    def unstage(self, report_id: str) -> None:
        self._staged.pop(report_id, None)

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        raise ValueError("la exportación siempre se invoca con un informe (subject)")

    def prepare(self, req: ExportRequest, target: str, addresses: tuple[str, ...],
                engagement_id: str, key: str) -> tuple[HttpRequest, bytes, dict[str, Any]]:
        """Arma la solicitud desde el archivo aprobado. Lanza ExportError o ValueError."""
        rel, sha = req.report_ref.split("#sha256=", 1)
        if rel != f"reports/{engagement_id}/{req.report_id}.json" or not addresses:
            raise ValueError("la solicitud no corresponde al informe ni al destino validados")
        if not verify_evidence(self.state_dir, req.report_ref):
            raise ExportError("evidence_mismatch", "el informe cambió después de aprobarse")
        report = json.loads((self.state_dir / rel).read_bytes())
        document = build_export(report, sha)
        payload = serialize(document)
        ctype, body = multipart({"scan_type": SCAN_TYPE,
                                 "engagement": str(req.dd_engagement_id),
                                 "close_old_findings": "false", "active": "true",
                                 "verified": "false"},
                                f"{req.report_id}.json", payload)
        headers = {"Host": target, "Authorization": f"Token {key}", "Content-Type": ctype,
                   "Content-Length": str(len(body)), "Accept": "application/json",
                   "Connection": "close"}
        return (HttpRequest(addresses[0], req.port, target, "POST", API_PATH, headers, body),
                payload, document)

    def run_subject(self, action: Action, target: str, token: ScopeToken,
                    addresses: tuple[str, ...], subject: str) -> dict[str, Any]:
        req = self._staged.pop(subject, None)
        if req is None:
            raise ValueError(f"sin exportación preparada para {subject}")
        key = os.environ.get(KEY_ENV, "")
        if not key:
            return _error("adapter_error")             # sin clave no se abre ninguna conexión
        try:
            http_req, payload, document = self.prepare(req, target, addresses,
                                                       token.engagement_id, key)
        except ExportError as exc:                     # se conserva el motivo real
            return _error(exc.reason if exc.reason in ("sensitive_data", "evidence_mismatch")
                          else "adapter_error")
        except (ValueError, OSError):
            return _error("adapter_error")
        status, test_id = self._send(http_req)
        if isinstance(status, str):
            return _error(status)
        counts = {"findings": len(document["findings"]),
                  "verified": sum(1 for f in document["findings"] if f["verified"])}
        summary = {"report_id": req.report_id,
                   "report_sha256": req.report_ref.split("#sha256=", 1)[1],
                   "document_sha256": hashlib.sha256(payload).hexdigest(),
                   "destination": target, "http_status": status, "test_id": test_id,
                   "counts": counts}
        rel = f"reports/{token.engagement_id}/export-{req.report_id}.json"
        data = json.dumps(summary, sort_keys=True, indent=2).encode("utf-8")
        try:
            path = self.state_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as fh:
                fh.write(data)
        except OSError:
            return _error("adapter_error")
        return {"tool": "defectdojo", "target": target, "status": "ok",
                "evidence": f"{rel}#sha256={hashlib.sha256(data).hexdigest()}",
                "http_status": status, "test_id": test_id, "counts": counts}

    def _send(self, r: HttpRequest) -> tuple[int | str, int | None]:
        """(código HTTP, id de test) o (motivo de error, None). Nunca lanza."""
        conn = self.connector(r.ip, r.port, self.timeout_s)
        try:
            conn.putrequest(r.method, r.path, skip_host=True, skip_accept_encoding=True)
            for name, value in r.headers.items():
                conn.putheader(name, value)
            conn.endheaders(r.body)
            resp = conn.getresponse()
            raw = resp.read(self.max_response_bytes + 1)
        except TimeoutError:
            return "timeout", None
        except (OSError, http.client.HTTPException):
            return "exec_error", None
        finally:
            conn.close()
        if not 200 <= resp.status < 300 or len(raw) > self.max_response_bytes:
            return "invalid_output", None                # 3xx incluido: no se sigue
        try:
            body = json.loads(raw)
        except ValueError:
            return "invalid_output", None
        test = body.get("test", body.get("test_id")) if isinstance(body, dict) else None
        if type(test) is not int:
            return "invalid_output", None
        return resp.status, test
