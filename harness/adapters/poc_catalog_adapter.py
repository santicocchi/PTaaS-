"""Adaptador `poc_catalog.run_parametrized` (change 006): catálogo + sandbox efímero + evidencia.

El Harness lo invoca con `subject` (el hallazgo) después de pasar el gate humano. Solo ejecuta
la solicitud que el orquestador preparó para ESE hallazgo (`stage`), sobre el host que validó
el Guard y con la IP fijada que le pasa el Harness. Cada intento deja un archivo de evidencia
redactado (D7); el orquestador registra su referencia en la bitácora.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from harness.contracts import Action, Phase, ScopeToken
from harness.evidence import build_evidence, write_evidence
from harness.poc.catalog import ResponseRecord, run_parametrized
from harness.sandbox import (
    DockerSandbox,
    SandboxCleanupFailed,
    SandboxFailure,
    SandboxRequest,
)


@dataclass(frozen=True)
class PocRequest:
    finding_id: str
    attempt: int
    poc_id: str
    params: dict[str, str]


class PocCatalogRun:
    name: str = "poc_catalog.run_parametrized"
    allowed_phases: tuple[Phase, ...] = (Phase.VALIDATE,)
    destructive: bool = False

    def __init__(self, sandbox: DockerSandbox, catalog: dict[str, dict[str, Any]], *,
                 state_dir: Path | str, catalog_version: str) -> None:
        self.sandbox, self.catalog = sandbox, catalog
        self.state_dir, self.catalog_version = Path(state_dir), catalog_version
        self._staged: dict[str, PocRequest] = {}

    def stage(self, request: PocRequest) -> None:
        """Prepara el próximo envío de un hallazgo. No envía nada."""
        self._staged[request.finding_id] = request

    def unstage(self, finding_id: str) -> None:
        self._staged.pop(finding_id, None)

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        raise ValueError("la validación siempre se invoca con un hallazgo (subject)")

    def run_subject(self, action: Action, target: str, token: ScopeToken,
                    addresses: tuple[str, ...], subject: str) -> dict[str, Any]:
        req = self._staged.pop(subject, None)
        if req is None:
            raise ValueError(f"sin solicitud preparada para {subject}")
        if token.engagement_id != self.sandbox.engagement_id:
            raise ValueError("el sandbox es de otro engagement")
        if urlsplit(req.params.get("base_url", "")).hostname != target or not addresses:
            raise ValueError("la solicitud no apunta al objetivo validado por el Guard")
        entry = self.catalog[req.poc_id]
        bound = self.sandbox.bind(addresses[0])
        record: ResponseRecord | None = None
        request: SandboxRequest | None = None
        sandbox_id: str | None = None
        error: str | None = None
        cleanup_failed, truncated = False, False
        try:
            # El gate humano ya pasó: si este método corre, el Harness verificó la aprobación.
            evidence = run_parametrized(self.catalog, req.poc_id, req.params, approved=True,
                                        sender=bound)
            assert bound.last is not None
            record, request = bound.last.record, bound.last.request
            sandbox_id, truncated = bound.last.sandbox_id, bound.last.truncated
            result, detail = evidence.status, evidence.detail
            if truncated and result == "validated":   # superar un límite nunca da positivo
                result = "not_validated"
                detail = f"{detail}; respuesta truncada: no cuenta como positivo"
        except SandboxFailure as exc:
            error, cleanup_failed = exc.kind, isinstance(exc, SandboxCleanupFailed)
            request, sandbox_id = exc.request, exc.sandbox_id
            result, detail = "failed", f"{exc.kind}: {exc.detail}"
        document = build_evidence(
            finding_id=req.finding_id, attempt=req.attempt, poc_id=req.poc_id,
            poc_version=str(entry["version"]), catalog_version=self.catalog_version,
            parameters=req.params, sandbox_id=sandbox_id, request=request, record=record,
            evaluator=str(entry["evaluator"]), canary=bound.last_params.get("canary"),
            result=result, detail=detail, truncated=truncated)
        ref = write_evidence(self.state_dir, token.engagement_id, req.finding_id, req.attempt,
                             document)
        out: dict[str, Any] = {
            "tool": "poc_catalog", "target": target, "poc_id": req.poc_id,
            "poc_version": str(entry["version"]), "status": result, "detail": detail,
            "sandbox_id": sandbox_id, "evidence": ref, "truncated": truncated}
        if error is not None:
            out.update(status="error", error=error, cleanup_failed=cleanup_failed)
        return out
