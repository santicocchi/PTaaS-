"""Entrega del informe (change 007, D14, D16, D17): gate humano, exportación y cierre.

    deliver(ctx)  →  report.delivered + REPORT → DELIVERED, o una excepción y el engagement
                     queda en REPORT (o en ABORTED, con kill switch o cadena rota).

Pasos, en orden, y cada uno detiene la entrega si falla:
1. la cadena de la bitácora verifica (si no: `AuditIntegrityError` y ABORTED);
2. el kill switch no está activo (si no: `report.delivery` ABORTED `killswitch` y ABORTED);
3. hay una aprobación auditada (`hitl.approve_delivery` más nuevo, con su fila) vigente, de
   la ÚLTIMA versión y de su SHA-256; si no: `report.delivery` PENDING_HITL y
   `DeliveryNotApproved`. Ningún llamador puede declarar la aprobación con un booleano;
4. el archivo del informe verifica contra su `report.generated`;
5. la exportación: por `Harness.invoke` al destino del RoE (D15) o, si el RoE no tiene
   destinos, como archivo local `defectdojo-<report_id>.json` (D16), sin abrir conexiones;
6. `report.delivered` OK con el resumen de la entrega y recién ahí `before_deliver`.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.adapters.defectdojo_adapter import DefectDojoExport, ExportRequest
from harness.approvals import (
    REVIEWER_RE,
    ApprovalStore,
    DeliveryDecision,
    ReviewError,
    audited_delivery,
    delivery_ref,
)
from harness.contracts import (
    APPROVE_DELIVERY_ACTION,
    REJECT_DELIVERY_ACTION,
    REPORT_DELIVERED_ACTION,
    REPORT_DELIVERY_ACTION,
    REPORT_GENERATED_ACTION,
    Action,
    AuditIntegrityError,
    AuditSink,
    Entry,
    Harness,
    KillSwitchEngaged,
    Phase,
    Result,
    ScopeViolation,
)
from harness.defectdojo import ExportError, build_export, serialize
from harness.engagement import _DELIVERY_GRANT, Engagement, State
from harness.evidence import verify_evidence
from harness.roe import RoE
from harness.tokens import TokenIssuer

AGENT = "report-delivery"
CAPABILITY = "defectdojo.export"
DELIVERY_CONTROLS = {"approved": APPROVE_DELIVERY_ACTION, "rejected": REJECT_DELIVERY_ACTION}


class DeliveryNotApproved(Exception):
    """La última versión no tiene una aprobación de entrega vigente y auditada (D14)."""


class DeliveryError(Exception):
    """La entrega no se hizo. `reason` es uno de DELIVERY_FAILURE_REASONS."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


# ---- la última versión del informe ---------------------------------------------------------

@dataclass(frozen=True)
class LatestReport:
    report_id: str
    ref: str
    sha256: str
    doc: dict[str, Any]

    @property
    def short(self) -> str:
        return self.sha256[:12]

    @property
    def unvalidated_high(self) -> list[str]:
        return [f["fingerprint"] for f in self.doc["findings"] if f["manual_check"]]


def _engagement_entries(entries: list[Entry], engagement_id: str) -> list[Entry]:
    return [e for e in entries if e.get("engagement") == engagement_id]


def _last_generated(entries: list[Entry], engagement_id: str) -> tuple[str, str] | None:
    """(report_id, referencia) de la última versión registrada, sin tocar el archivo."""
    generated = [e for e in _engagement_entries(entries, engagement_id)
                 if e["phase"] == "control" and e["action"] == REPORT_GENERATED_ACTION
                 and e["result"] == Result.OK.value]
    if not generated:
        return None
    return str(generated[-1]["subject"]), str(generated[-1]["evidence"])


def _load(state_dir: Path, report_id: str, ref: str) -> LatestReport:
    if not verify_evidence(state_dir, ref):
        raise DeliveryError("evidence_mismatch", f"{ref}: el informe no coincide con la bitácora")
    doc = json.loads((state_dir / ref.split("#sha256=", 1)[0]).read_bytes())
    return LatestReport(report_id, ref, ref.split("#sha256=", 1)[1], doc)


def latest_report(entries: list[Entry], engagement_id: str,
                  state_dir: Path) -> LatestReport | None:
    """La última versión registrada y su archivo, solo si verifica contra la bitácora."""
    last = _last_generated(entries, engagement_id)
    return None if last is None else _load(state_dir, *last)


def delivered(entries: list[Entry], engagement_id: str) -> bool:
    return any(e["phase"] == "control" and e["action"] == REPORT_DELIVERED_ACTION
               and e["result"] == Result.OK.value
               for e in _engagement_entries(entries, engagement_id))


def current_approval(store: ApprovalStore, entries: list[Entry], engagement_id: str,
                     latest: LatestReport, now: float) -> DeliveryDecision | None:
    """La aprobación que habilita la entrega: auditada, de esta versión y su hash, sin vencer."""
    d = audited_delivery(store, entries, engagement_id, latest.report_id)
    if d is None or d.decision != "approved" or d.report_sha256 != latest.sha256:
        return None
    if d.expires_at is None or now >= d.expires_at:
        return None
    return d


def delivery_status(store: ApprovalStore, entries: list[Entry], engagement_id: str,
                    latest: LatestReport, now: float) -> str:
    if delivered(entries, engagement_id):
        return "delivered"
    d = audited_delivery(store, entries, engagement_id, latest.report_id)
    if d is None:
        return "pending"
    if d.decision == "rejected":
        return "rejected"
    return "approved" if current_approval(store, entries, engagement_id, latest, now) \
        else "expired"


# ---- decisión del Reviewer (la usa la CLI) -------------------------------------------------

def check_delivery_decision(entries: list[Entry], engagement_id: str, state_dir: Path,
                            report_id: str, decision: str, reviewer: str, reason: str,
                            sha256: str | None, ack_unvalidated_high: bool) -> LatestReport:
    """Valida una decisión de entrega sin escribir. Lanza ReviewError."""
    if decision not in DELIVERY_CONTROLS:
        raise ReviewError(f"decisión inválida: {decision!r}")
    if not REVIEWER_RE.match(reviewer or ""):
        raise ReviewError("reviewer inválido o vacío")
    if not (reason or "").strip():
        raise ReviewError("el motivo es obligatorio")
    if delivered(entries, engagement_id):
        raise ReviewError("el engagement ya se entregó")
    try:
        latest = latest_report(entries, engagement_id, state_dir)
    except DeliveryError as exc:
        raise ReviewError(str(exc)) from exc
    if latest is None:
        raise ReviewError("no hay ningún informe generado")
    if report_id != latest.report_id:
        raise ReviewError(f"{report_id} no es la última versión ({latest.report_id})")
    if decision == "approved":
        if sha256 != latest.short:
            raise ReviewError(f"{report_id}: el --sha256 {sha256} no es el del archivo "
                              f"({latest.short}); volvé a correr `report list`")
        if latest.unvalidated_high and not ack_unvalidated_high:
            raise ReviewError(f"{report_id} tiene {len(latest.unvalidated_high)} hallazgos de "
                              "severidad alta o crítica sin validar: falta "
                              "--ack-unvalidated-high")
    return latest


def record_delivery_decision(store: ApprovalStore, audit: AuditSink, engagement_id: str,
                             state_dir: Path, report_id: str, decision: str, reviewer: str,
                             reason: str, now: float, sha256: str | None = None,
                             ack_unvalidated_high: bool = False) -> DeliveryDecision:
    """Fila del registro y control en la bitácora, juntos o ninguno (006 M5)."""
    holder: dict[str, LatestReport] = {}

    def check() -> None:                                 # dentro de la transacción
        holder["latest"] = check_delivery_decision(
            audit.entries, engagement_id, state_dir, report_id, decision, reviewer, reason,
            sha256, ack_unvalidated_high)

    def write(d: DeliveryDecision) -> None:
        audit.record_control(engagement_id, f"reviewer:{reviewer}", DELIVERY_CONTROLS[decision],
                             engagement_id, Result.OK, evidence=delivery_ref(engagement_id, d),
                             subject=report_id)

    latest = check_delivery_decision(audit.entries, engagement_id, state_dir, report_id,
                                     decision, reviewer, reason, sha256, ack_unvalidated_high)
    return store.decide_delivery(report_id, decision, reviewer, reason, now, latest.sha256,
                                 bool(ack_unvalidated_high), check, write)


# ---- entrega -------------------------------------------------------------------------------

@dataclass
class DeliveryContext:
    engagement: Engagement
    roe: RoE
    harness: Harness
    issuer: TokenIssuer
    state_dir: Path
    approvals: ApprovalStore
    clock: Callable[[], float] = field(default=time.time)


@dataclass(frozen=True)
class DeliveryResult:
    report_id: str
    mode: str                      # "api" u "offline"
    receipt: str                   # referencia del resumen de la entrega
    export: str                    # referencia de la exportación (archivo o resumen del envío)


def _write(state_dir: Path, rel: str, data: bytes) -> str:
    path = state_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as fh:                         # nunca se sobrescribe
        fh.write(data)
    return f"{rel}#sha256={hashlib.sha256(data).hexdigest()}"


def _abort(ctx: DeliveryContext, report_id: str, reason: str) -> None:
    ctx.harness.audit.record_control(ctx.roe.engagement_id, AGENT, REPORT_DELIVERY_ACTION,
                                     ctx.roe.engagement_id, Result.ABORTED, reason,
                                     subject=report_id)


def deliver(ctx: DeliveryContext) -> DeliveryResult:
    """Precondiciones sin intento de entrega (estado, ya entregado, sin informe) lanzan
    `DeliveryError` sin registro: no hubo acción. Todo lo demás queda en la bitácora."""
    eng = ctx.roe.engagement_id
    audit = ctx.harness.audit
    if ctx.engagement.state != State.REPORT:
        raise DeliveryError("engagement_not_in_report", f"estado {ctx.engagement.state.value}")
    try:
        audit.verify_integrity()
    except AuditIntegrityError:
        ctx.engagement.kill()                            # 008: con la cadena rota se aborta
        raise
    entries = _engagement_entries(audit.entries, eng)
    if delivered(entries, eng):                      # la bitácora manda, no el estado en memoria
        raise DeliveryError("already_delivered", "el engagement ya tiene report.delivered")
    last = _last_generated(entries, eng)
    if last is None:
        raise DeliveryError("no_report", "no hay ningún informe generado")
    report_id, ref = last
    if ctx.harness.killswitch.is_engaged(eng):
        _abort(ctx, report_id, "killswitch")
        ctx.engagement.kill()
        raise KillSwitchEngaged()
    now = ctx.clock()
    shallow = LatestReport(report_id, ref, ref.split("#sha256=", 1)[1], {})
    approval = current_approval(ctx.approvals, entries, eng, shallow, now)
    if approval is None:
        audit.record_control(eng, AGENT, REPORT_DELIVERY_ACTION, eng, Result.PENDING_HITL,
                             subject=report_id)
        raise DeliveryNotApproved(f"{report_id} no tiene una aprobación de entrega "
                                  "vigente: `python -m harness.review report list`")
    try:
        latest = _load(ctx.state_dir, report_id, ref)
    except DeliveryError as exc:
        _abort(ctx, report_id, exc.reason)
        raise
    if ctx.roe.report_destinations:
        mode, export = "api", _export_api(ctx, latest)
    else:
        mode, export = "offline", _export_offline(ctx, latest)
    receipt = {"report_id": latest.report_id, "report_sha256": latest.sha256, "mode": mode,
               "destination": (ctx.roe.report_destinations[0].host
                               if ctx.roe.report_destinations else None),
               "export": export, "approval": delivery_ref(eng, approval)}
    ref = _write(ctx.state_dir, f"reports/{eng}/delivered-{latest.report_id}.json",
                 json.dumps(receipt, sort_keys=True, indent=2).encode("utf-8"))
    audit.record_control(eng, AGENT, REPORT_DELIVERED_ACTION, mode, Result.OK, evidence=ref,
                         subject=latest.report_id)
    ctx.engagement.grant_delivery(_DELIVERY_GRANT)
    ctx.engagement.advance()
    return DeliveryResult(latest.report_id, mode, ref, export)


def _export_offline(ctx: DeliveryContext, latest: LatestReport) -> str:
    """D16: archivo Generic Findings Import local. No abre conexiones ni pasa por el Harness."""
    try:
        doc = build_export(latest.doc, latest.sha256)
    except ExportError as exc:
        _abort(ctx, latest.report_id, exc.reason)
        raise DeliveryError(exc.reason, exc.detail) from exc
    return _write(ctx.state_dir,
                  f"reports/{ctx.roe.engagement_id}/defectdojo-{latest.report_id}.json",
                  serialize(doc))


def _export_api(ctx: DeliveryContext, latest: LatestReport) -> str:
    """D15: por `Harness.invoke`, con un token de REPORT que solo alcanza el destino."""
    eng = ctx.roe.engagement_id
    dest = ctx.roe.report_destinations[0]
    try:                                       # se arma antes: si falla, no hay envío
        build_export(latest.doc, latest.sha256)
    except ExportError as exc:
        _abort(ctx, latest.report_id, exc.reason)
        raise DeliveryError(exc.reason, exc.detail) from exc
    adapter = ctx.harness.tools.get(CAPABILITY)
    if not isinstance(adapter, DefectDojoExport):
        _abort(ctx, latest.report_id, "adapter_error")
        raise DeliveryError("adapter_error", f"falta el adaptador {CAPABILITY}")
    try:
        token = ctx.issuer.issue(ctx.roe, Phase.REPORT, agent=AGENT)
    except ScopeViolation as exc:                    # token.issue BLOCKED ya quedó registrado
        _abort(ctx, latest.report_id, "out_of_scope")
        raise DeliveryError("out_of_scope", str(exc)) from exc
    guard = ctx.harness.guard
    adapter.stage(ExportRequest(latest.report_id, latest.ref, dest.port, dest.dd_engagement_id))
    guard.approve(CAPABILITY, dest.host, engagement_id=eng, phase=Phase.REPORT,
                  subject=latest.report_id)
    try:
        out = ctx.harness.invoke(AGENT, Action(CAPABILITY, Phase.REPORT), dest.host, token,
                                 subject=latest.report_id)
    except KillSwitchEngaged:
        ctx.engagement.kill()
        raise
    except AuditIntegrityError:
        ctx.engagement.kill()
        raise
    except ScopeViolation as exc:                    # el Harness ya registró el BLOCKED
        _abort(ctx, latest.report_id, "out_of_scope")
        raise DeliveryError("out_of_scope", str(exc)) from exc
    finally:
        guard.withdraw(CAPABILITY, dest.host, engagement_id=eng, phase=Phase.REPORT,
                       subject=latest.report_id)
        adapter.unstage(latest.report_id)
    if ctx.harness.killswitch.is_engaged(eng):       # se activó durante el envío
        _abort(ctx, latest.report_id, "killswitch")
        ctx.engagement.kill()
        raise KillSwitchEngaged()
    if out.get("status") != "ok" or not isinstance(out.get("evidence"), str):
        reason = str(out.get("error") or "adapter_error")
        _abort(ctx, latest.report_id, reason if reason in _API_ERRORS else "adapter_error")
        raise DeliveryError(reason, "DefectDojo no aceptó la exportación")
    return str(out["evidence"])


_API_ERRORS = frozenset({"timeout", "exec_error", "invalid_output", "adapter_error",
                         "sensitive_data", "evidence_mismatch"})
