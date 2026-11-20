"""Loop C (validación) del change 006: determinista, por hallazgo y con gate humano propio.

Mismo diseño que el loop B (`harness/analysis.py`). Por cada `PrioritizedVuln`:

- solo entran `confirmed` e `inconclusive`; un `discarded` no se valida (D1);
- la entrada del catálogo se elige por reglas: mismo CWE y host dentro de `lab_targets`. Los
  parámetros salen de lo que observó el loop B (host, puerto, endpoint), no de texto libre;
- sin entrada: `not_validated` con `no_catalog_entry`, sin invocar nada;
- la aprobación es del Reviewer para ESE hallazgo (D2, D5). Sin decisión: `PENDING_HITL`;
  pasado `validation_timeout_minutes`: `reviewer_timeout`; rechazado: `reviewer_rejected`;
- con aprobación vigente: hasta dos intentos (`decide_validation`), cada uno con un canario
  nuevo, y un positivo detiene el loop (D9). Cada intento deja evidencia en la bitácora (D7);
- el presupuesto del engagement se cuenta en la bitácora (D4) y un contenedor que no se pudo
  destruir detiene el loop para todo el engagement (D8).

Todo envío pasa por `Harness.invoke` con `subject=finding_id`.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from harness.adapters.poc_catalog_adapter import PocCatalogRun, PocRequest
from harness.analysis import FindingStore
from harness.approvals import ApprovalStore, QueueItem, load_review_limits
from harness.contracts import (
    Action,
    AuditIntegrityError,
    Harness,
    KillSwitchEngaged,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
)
from harness.engagement import Engagement, State
from harness.loops import decide_validation
from harness.poc.catalog import host_in_lab_targets
from harness.policy_loader import load_policy
from harness.sandbox import SandboxLimits, load_limits
from harness.schemas import CandidateFinding, PrioritizedVuln

AGENT = "validation-orchestrator"
CAPABILITY = "poc_catalog.run_parametrized"
ATTEMPT_ACTION = "validation.attempt"
CLOSED_ACTION = "validation.closed"
CLEANUP_FAILED_ACTION = "sandbox.cleanup_failed"
ELIGIBLE = ("confirmed", "inconclusive")
_FATAL = frozenset({"token_expired", "token_invalid", "token_revoked"})


@dataclass
class FindingOutcome:
    finding_id: str
    status: str                  # validated | not_validated | failed | pending_hitl | skipped
    reason: str | None = None
    poc_id: str | None = None
    attempts: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    sandbox_ids: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    outcomes: dict[str, FindingOutcome] = field(default_factory=dict)
    reason: str = "ok"


class _Stop(Exception):
    """Detiene el loop para todo el engagement."""


class ValidationLoop:
    def __init__(self, harness: Harness, token: ScopeToken, store: FindingStore, *,
                 engagement: Engagement, catalog: dict[str, dict[str, Any]],
                 approvals: ApprovalStore, limits: SandboxLimits | None = None,
                 max_attempts: int | None = None, timeout_minutes: int | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        if token.phase is not Phase.VALIDATE:
            raise ValueError("la validación necesita un token de fase VALIDATE")
        adapter = harness.tools.get(CAPABILITY)
        if not isinstance(adapter, PocCatalogRun):
            raise ValueError(  # noqa: TRY004
                f"el loop C necesita el adaptador {CAPABILITY} del catálogo")
        self.harness: Harness = harness
        self.token: ScopeToken = token
        self.store: FindingStore = store
        self.adapter: PocCatalogRun = adapter
        self.engagement: Engagement = engagement
        self.catalog: dict[str, dict[str, Any]] = catalog
        self.approvals: ApprovalStore = approvals
        self.limits: SandboxLimits = limits or load_limits()
        limit = (max_attempts if max_attempts is not None
                 else load_policy()["limits"]["max_loop_iterations"]["validation"])
        if type(limit) is not int or limit < 1:
            raise ValueError("tope de intentos inválido")
        self.max_attempts: int = min(limit, self.limits.max_requests_per_finding)
        self.timeout_s: int = 60 * (load_review_limits()[0] if timeout_minutes is None
                               else timeout_minutes)
        self.clock: Callable[[], float] = clock

    # -- ejecución -------------------------------------------------------------------------
    def run(self, vulns: list[PrioritizedVuln],
            candidates: list[CandidateFinding]) -> ValidationResult:
        # Sin el engagement en VALIDATE (al que se llega por el gate before_validate) o con el
        # kill switch activo no se invoca nada, igual que en el loop B.
        if self.engagement.state != State.VALIDATE:
            return ValidationResult(reason="engagement fuera de VALIDATE")
        if self.harness.killswitch.is_engaged(self.token.engagement_id):
            return ValidationResult(reason="abortado: kill switch")
        by_id = {c.id: c for c in candidates}
        result = ValidationResult()
        try:
            for vuln in vulns:
                candidate = by_id.get(vuln.finding_id)
                if vuln.status not in ELIGIBLE or candidate is None or not candidate.host:
                    result.outcomes[vuln.finding_id] = FindingOutcome(vuln.finding_id,
                                                                      "skipped", vuln.status)
                    continue
                outcome = self._process(vuln, candidate)
                result.outcomes[vuln.finding_id] = outcome
                if outcome.reason == "request_budget_exhausted":
                    raise _Stop("request_budget_exhausted")
        except _Stop as exc:
            result.reason = str(exc)
        return result

    def _process(self, vuln: PrioritizedVuln, c: CandidateFinding) -> FindingOutcome:
        fid = vuln.finding_id
        closure = self.approvals.closure(fid)
        if closure is not None:                    # ya cerrado en una corrida anterior
            return FindingOutcome(fid, closure.outcome, closure.reason)
        now = self.clock()
        choice = self._choose(c)
        poc_id, params = choice if choice else (None, {})
        self.approvals.enqueue(QueueItem(fid, c.cwe, c.host, vuln.priority, poc_id, params, now))
        if poc_id is None:
            return self._close(fid, c.host, "no_catalog_entry")
        item = self.approvals.item(fid)
        assert item is not None
        decisions = self.approvals.decisions(fid)
        current = self.approvals.current(fid, now)
        if decisions and decisions[-1].decision == "rejected":
            return self._close(fid, c.host, "reviewer_rejected", poc_id)
        if current is None:
            if not decisions and now - item.enqueued_at > self.timeout_s:
                return self._close(fid, c.host, "reviewer_timeout", poc_id)
            # Sin aprobación vigente se invoca igual: el Harness registra PENDING_HITL y el
            # adaptador no corre (la aprobación no está cargada en el Guard).
            self._invoke(fid, c.host, None)
            return FindingOutcome(fid, "pending_hitl", "falta aprobación del Reviewer", poc_id)
        return self._validate(fid, c.host, poc_id, params)

    def _validate(self, fid: str, host: str, poc_id: str,
                  params: dict[str, str]) -> FindingOutcome:
        outcome = FindingOutcome(fid, "not_validated", None, poc_id)
        done = self._prior_attempts(fid)
        errors_only, validated = True, False
        while decide_validation(done, validated, self.max_attempts).decision == "continue":
            if self._engagement_requests() >= self.limits.max_requests_per_engagement:
                closed = self._close(fid, host, "request_budget_exhausted", poc_id)
                closed.attempts = outcome.attempts
                closed.evidence_refs, closed.sandbox_ids = (outcome.evidence_refs,
                                                            outcome.sandbox_ids)
                return closed                      # run() detiene el loop con este motivo
            done += 1
            out = self._invoke(fid, host, PocRequest(fid, done, poc_id, params))
            if out is None or out.get("status") == "PENDING_HITL":
                outcome.status, outcome.reason = "pending_hitl", "falta aprobación del Reviewer"
                return outcome
            outcome.attempts += 1
            ref, sandbox_id = out.get("evidence"), out.get("sandbox_id")
            if isinstance(sandbox_id, str):
                outcome.sandbox_ids.append(sandbox_id)
            if isinstance(ref, str):
                outcome.evidence_refs.append(ref)
            status = out.get("status")
            if status == "error":
                error = str(out.get("error"))
                if error in ("sandbox_error", "timeout"):
                    self._control(ATTEMPT_ACTION, fid, Result.ABORTED, error,
                                  ref if isinstance(ref, str) else None)
                if out.get("cleanup_failed"):
                    self._control(CLEANUP_FAILED_ACTION, str(sandbox_id or host),
                                  Result.ABORTED, "sandbox_error")
                    raise _Stop("sandbox.cleanup_failed")
                continue
            errors_only = False
            self._control(ATTEMPT_ACTION, fid, Result.OK, None,
                          ref if isinstance(ref, str) else None)
            validated = status == "validated"
        if validated:
            outcome.status = "validated"
        elif outcome.attempts and errors_only:
            outcome.status = "failed"
        self.approvals.close(fid, outcome.status, None, self.clock())
        return outcome

    # -- elección de la verificación (reglas, sin LLM) ---------------------------------------
    def _choose(self, c: CandidateFinding) -> tuple[str, dict[str, str]] | None:
        for poc_id, entry in sorted(self.catalog.items()):
            if entry["cwe"] != c.cwe:
                continue
            if not host_in_lab_targets(c.host, list(entry.get("lab_targets") or [])):
                continue
            params = self._params(c, list(entry["parameters"]))
            if params is not None:
                return poc_id, params
        return None

    def _params(self, c: CandidateFinding, declared: list[str]) -> dict[str, str] | None:
        """host, puerto y endpoint de lo que observó el loop B para ese host y CWE."""
        urls = sorted({o.url for o in self.store.observations(c.host) if o.cwe == c.cwe})
        for url in urls or [f"http://{c.host}/"]:
            parts = urlsplit(url)
            if parts.scheme != "http" or parts.hostname != c.host:
                continue
            values = {"base_url": f"http://{parts.netloc}", "path": parts.path or "/"}
            query = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
            if query:
                values["param_name"] = query[0]
            if set(declared) <= set(values):
                return {k: values[k] for k in declared}
        return None

    # -- harness y bitácora ------------------------------------------------------------------
    def _invoke(self, fid: str, host: str, request: PocRequest | None) -> dict[str, Any] | None:
        action = Action(CAPABILITY, Phase.VALIDATE, requires_human_approval=True)
        guard = self.harness.guard
        if request is not None:            # aprobación vigente: se carga solo para este envío
            self.adapter.stage(request)
            guard.approve(CAPABILITY, host, engagement_id=self.token.engagement_id,
                          phase=Phase.VALIDATE, subject=fid)
        try:
            return self.harness.invoke(AGENT, action, host, self.token, subject=fid)
        except KillSwitchEngaged as exc:
            raise _Stop("abortado: kill switch") from exc
        except AuditIntegrityError as exc:
            raise _Stop("abortado: bitácora rota") from exc
        except ScopeViolation as exc:
            if exc.reason in _FATAL:
                raise _Stop(f"abortado: {exc.reason}") from exc
            return None
        finally:
            if request is not None:
                guard.withdraw(CAPABILITY, host, engagement_id=self.token.engagement_id,
                               phase=Phase.VALIDATE, subject=fid)
                self.adapter.unstage(fid)

    def _close(self, fid: str, host: str, reason: str,
               poc_id: str | None = None) -> FindingOutcome:
        self._control(CLOSED_ACTION, fid, Result.ABORTED, reason)
        self.approvals.close(fid, "not_validated", reason, self.clock())
        return FindingOutcome(fid, "not_validated", reason, poc_id)

    def _control(self, action: str, target: str, result: Result, reason: str | None,
                 evidence: str | None = None) -> None:
        self.harness.audit.record_control(self.token.engagement_id, AGENT, action, target,
                                          result, reason, evidence)

    def _entries(self) -> list[dict[str, Any]]:
        return [e for e in self.harness.audit.entries
                if e.get("engagement") == self.token.engagement_id]

    def _engagement_requests(self) -> int:
        """Envíos del engagement: los OK de la capability en la bitácora (sobrevive reinicios)."""
        return sum(1 for e in self._entries() if e["action"] == CAPABILITY
                   and e["phase"] == Phase.VALIDATE.value and e["result"] == Result.OK.value)

    def _prior_attempts(self, fid: str) -> int:
        return sum(1 for e in self._entries() if e["action"] == ATTEMPT_ACTION
                   and e["phase"] == "control" and e["target"] == fid)
