"""Contratos del harness PTaaS (esqueleto). El contrato, no el exploit.

Invariantes:
  I1. Toda acción que toca un activo pasa por Harness.invoke.
  I2. El Guard es determinista (sin LLM).
  I3. Toda decisión (OK, BLOCKED, PENDING_HITL, ABORTED) queda en bitácora.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from harness.ratelimit import RateLimiter


class Phase(str, Enum):
    RECON = "recon"
    CORRELATE = "correlate"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    REPORT = "report"


class Result(str, Enum):
    OK = "OK"
    BLOCKED = "BLOCKED"
    PENDING_HITL = "PENDING_HITL"
    ABORTED = "ABORTED"


class ScopeViolation(Exception):
    """Acción bloqueada. `reason` es uno de BLOCK_REASONS (lo usa el orquestador del 004)."""

    def __init__(self, message: str, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason

class KillSwitchEngaged(Exception): ...
class AuditIntegrityError(Exception): ...


@dataclass(frozen=True)
class ScopeToken:
    engagement_id: str
    allowed_cidrs: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    window_start: float
    window_end: float
    phase: Phase
    excluded: tuple[str, ...] = ()       # exclusiones del RoE: prevalecen sobre el alcance
    mac: str = ""                         # HMAC del emisor (harness/tokens.py)

    def is_live(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.window_start <= now <= self.window_end


@dataclass(frozen=True)
class Action:
    name: str                      # capability declarada, p.ej. "httpx.probe"
    phase: Phase
    destructive: bool = False
    requires_human_approval: bool = False


class ToolAdapter(Protocol):
    name: str
    allowed_phases: tuple[Phase, ...]
    destructive: bool

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        """Debe devolver JSON parseable. Nunca ejecuta fuera de `target`.

        `addresses` son las IP que validó el Harness. Un adaptador que se conecta al objetivo
        DEBE usarlas en lugar de dejar que la herramienta resuelva el nombre otra vez (004).
        """
        ...


BLOCK_REASONS = frozenset({
    "out_of_scope", "token_expired", "token_invalid", "wrong_phase",
    "not_allowlisted", "destructive", "no_adapter", "adapter_phase",
    "token_revoked", "excluded", "roe_invalid", "roe_tampered", "phase_not_in_roe",
    "outside_window", "dns_out_of_scope", "dns_unresolved",
    "missing_subject",                    # 006: acción con gate humano sin `subject`
})

# Motivos de un registro no BLOCKED: solo errores de herramienta (change 004).
TOOL_ERROR_REASONS = frozenset({"timeout", "binary_missing", "exec_error", "exit_code",
                                "invalid_output", "adapter_error", "sandbox_error"})

# 006: cierre de un hallazgo en VALIDATE sin tráfico (o sin más tráfico). Solo en el registro
# de control `validation.closed`, siempre ABORTED.
VALIDATION_CLOSED_ACTION = "validation.closed"
VALIDATION_CLOSE_REASONS = frozenset({"no_catalog_entry", "reviewer_rejected",
                                      "reviewer_timeout", "request_budget_exhausted"})

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    """Todas las IP (A y AAAA) de `host`. Lista vacía si no resuelve."""
    try:
        # Con punto final: sin dominios de búsqueda de resolv.conf.
        infos = socket.getaddrinfo(host.rstrip(".") + ".", None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({str(info[4][0]) for info in infos})


def normalize_target(target: str) -> str | None:
    """Devuelve el objetivo canónico (host en minúsculas o IP) o None si no es interpretable.

    Solo se aceptan hosts o IPs: nada de esquema, puerto, ruta ni espacios internos.
    Una IPv4 mapeada a IPv6 (::ffff:a.b.c.d) se canoniza como IPv4.
    """
    t = target.strip()
    try:
        ip = ipaddress.ip_address(t)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return str(ip)
    except ValueError:
        pass
    host = t.lower().rstrip(".")
    if not host or len(host) > 253 or not host.isascii():
        return None
    if not all(c.isalnum() or c in "-." for c in host):   # sin ':', '/', '%', espacios…
        return None
    labels = host.split(".")
    if any(not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-")
           for lbl in labels):
        return None
    return host


# 006: el sujeto de una aprobación es un `finding_id` (también nombra archivos de evidencia).
SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ApprovalKey = tuple[str, Phase, str, str, str]   # (engagement, fase, acción, objetivo, sujeto)


class Guard:
    """Autorización determinista. Sin LLM, sin heurísticas."""

    def __init__(self, phase_allowlist: dict[Phase, set[str]],
                 approvals: set[ApprovalKey] | None = None,
                 hitl_phases: set[Phase] | None = None):
        from harness.policy_loader import hitl_phases as policy_hitl_phases
        self.phase_allowlist = phase_allowlist
        self._approvals: set[ApprovalKey] = approvals or set()
        # Lo decide la política, no el agente que arma la Action (red team R13).
        self.hitl_phases = policy_hitl_phases() if hitl_phases is None else hitl_phases

    def needs_approval(self, action: Action, token: ScopeToken) -> bool:
        return action.requires_human_approval or token.phase in self.hitl_phases

    @staticmethod
    def _key(action_name: str, target: str, engagement_id: str, phase: Phase,
             subject: str) -> ApprovalKey:
        canon = normalize_target(target)
        if canon is None:
            raise ValueError(f"objetivo no interpretable: {target!r}")
        if not SUBJECT_RE.match(subject):
            raise ValueError(f"sujeto inválido: {subject!r}")
        return (engagement_id, phase, action_name, canon, subject)

    def approve(self, action_name: str, target: str, *, engagement_id: str, phase: Phase,
                subject: str) -> None:
        """Registra una aprobación humana para (engagement, fase, acción, objetivo, sujeto).

        El sujeto es el hallazgo (006, D2): aprobar uno no aprueba otro del mismo host.
        """
        self._approvals.add(self._key(action_name, target, engagement_id, phase, subject))

    def withdraw(self, action_name: str, target: str, *, engagement_id: str, phase: Phase,
                 subject: str) -> None:
        """Retira una aprobación (vencida o ya usada). Retirar una que no existe no falla."""
        self._approvals.discard(self._key(action_name, target, engagement_id, phase, subject))

    def approved(self, action: Action, target: str, token: ScopeToken,
                 subject: str | None) -> bool:
        if subject is None:
            return False
        canon = normalize_target(target)
        return (token.engagement_id, token.phase, action.name, canon,
                subject) in self._approvals

    def check(self, action: Action, target: str, token: ScopeToken) -> str | None:
        """None si la acción está permitida; si no, el motivo (de BLOCK_REASONS)."""
        if action.destructive:        # acciones destructivas prohibidas en el MVP
            return "destructive"
        if action.phase != token.phase:
            return "wrong_phase"
        if action.name not in self.phase_allowlist.get(token.phase, set()):
            return "not_allowlisted"
        canon = normalize_target(target)
        if canon is None or not self._in_scope(canon, token):
            return "out_of_scope"
        if self._excluded(canon, token):
            return "excluded"
        return None

    @staticmethod
    def _excluded(canon: str, token: ScopeToken) -> bool:
        for ex in token.excluded:
            try:
                net = ipaddress.ip_network(ex)
            except ValueError:
                if canon == ex or canon.endswith("." + ex):
                    return True
                continue
            try:
                if ipaddress.ip_address(canon) in net:
                    return True
            except ValueError:
                continue
        return False

    def check_resolved(self, canon: str, ips: list[str], token: ScopeToken) -> str | None:
        """Red team A4: un hostname autorizado debe resolver SOLO a IP en alcance."""
        if not ips:
            return "dns_unresolved"
        for raw in ips:
            ip = normalize_target(raw)
            try:
                addr = ipaddress.ip_address(ip or "")
            except ValueError:
                return "dns_out_of_scope"
            if not any(addr in ipaddress.ip_network(c) for c in token.allowed_cidrs):
                return "dns_out_of_scope"
            if self._excluded(str(addr), token):
                return "excluded"
        return None

    def is_allowed(self, action: Action, target: str, token: ScopeToken) -> bool:
        return self.check(action, target, token) is None

    @staticmethod
    def _in_scope(canon: str, token: ScopeToken) -> bool:
        try:
            ip = ipaddress.ip_address(canon)
            return any(ip in ipaddress.ip_network(c) for c in token.allowed_cidrs)
        except ValueError:
            return any(
                canon == d or canon.endswith("." + d) for d in token.allowed_domains
            )


Entry = dict[str, Any]
EVIDENCE_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*#sha256=[0-9a-f]{64}$")
KILLSWITCH_ACTION = "killswitch.engage"


def phase_label(token: ScopeToken) -> str:
    """Fase para la bitácora, aun si el token trae un tipo inesperado (se registra igual)."""
    return token.phase.value if isinstance(token.phase, Phase) else str(token.phase)


def entry_hash(entry: Entry) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def make_entry(*, prev: str, engagement: str, agent: str, action: str, target: str,
               phase: str, result: Result, reason: str | None = None,
               evidence: str | None = None, subject: str | None = None) -> Entry:
    """Arma un registro con su hash. Valida motivo de bloqueo y forma de la evidencia."""
    body: Entry = {
        "ts": time.time(), "engagement": engagement, "agent": agent,
        "action": action, "target": target, "phase": phase,
        "result": result.value, "prev": prev,
    }
    if action == VALIDATION_CLOSED_ACTION:
        if result is not Result.ABORTED or reason not in VALIDATION_CLOSE_REASONS:
            raise ValueError(f"cierre de validación inválido: {result.value} {reason!r}")
        body["reason"] = reason
    elif result is Result.BLOCKED:
        if reason not in BLOCK_REASONS:
            raise ValueError(f"motivo de bloqueo inválido: {reason!r}")
        body["reason"] = reason
    elif reason is not None:
        if result not in (Result.ABORTED, Result.PENDING_HITL) or reason not in TOOL_ERROR_REASONS:
            raise ValueError(f"motivo inválido para {result.value}: {reason!r}")
        body["reason"] = reason
    if evidence is not None:
        if not EVIDENCE_RE.match(evidence) or ".." in evidence.split("/"):
            raise ValueError("la evidencia debe ser una referencia '<ruta>#sha256=<hex>'")
        body["evidence"] = evidence
    if subject is not None:              # 006 (revisión M2): el hallazgo, si lo hay
        if not SUBJECT_RE.match(subject):
            raise ValueError(f"sujeto inválido: {subject!r}")
        body["subject"] = subject
    body["hash"] = entry_hash(body)
    return body


def verify_chain(entries: Iterable[Entry], genesis: str,
                 engagement: str | None = None) -> str | None:
    """None si la cadena es íntegra; si no, la descripción del primer registro roto."""
    prev = genesis
    for i, e in enumerate(entries, start=1):
        where = f"seq={e.get('seq', i)}"
        if engagement is not None and e.get("engagement") != engagement:
            return f"{where}: registro de otro engagement ({e.get('engagement')!r})"
        if e.get("prev") != prev:
            return f"{where}: el hash previo no coincide"
        if entry_hash({k: v for k, v in e.items() if k != "seq"}) != e.get("hash"):
            return f"{where}: el contenido no coincide con su hash"
        prev = e["hash"]
    return None


@dataclass
class AuditLog:
    """Append-only con hash encadenado (detecta manipulación). Versión en memoria."""

    entries: list[Entry] = field(default_factory=list)
    genesis: str = "GENESIS"

    def _append(self, **fields: object) -> Entry:
        prev = self.entries[-1]["hash"] if self.entries else self.genesis
        entry = make_entry(prev=prev, **fields)  # type: ignore[arg-type]
        self.entries.append(entry)
        return entry

    def record(self, agent: str, action: Action, target: str, token: ScopeToken,
               result: Result, reason: str | None = None,
               evidence: str | None = None, subject: str | None = None) -> Entry:
        return self._append(engagement=token.engagement_id, agent=agent, action=action.name,
                            target=target, phase=phase_label(token), result=result,
                            reason=reason, evidence=evidence, subject=subject)

    def record_control(self, engagement_id: str, agent: str, action: str, target: str,
                       result: Result, reason: str | None = None,
                       evidence: str | None = None, subject: str | None = None) -> Entry:
        """Registro de control (emisión, revocación, kill switch): fase `control`."""
        return self._append(engagement=engagement_id, agent=agent, action=action,
                            target=target, phase="control", result=result, reason=reason,
                            evidence=evidence, subject=subject)

    def record_kill(self, engagement_id: str, agent: str) -> Entry:
        return self.record_control(engagement_id, agent, KILLSWITCH_ACTION, engagement_id,
                                   Result.ABORTED)

    def control_engagements(self, action: str, result: Result = Result.ABORTED) -> set[str]:
        return {e["engagement"] for e in self.entries if e["action"] == action
                and e["phase"] == "control" and e["result"] == result.value}

    def killed_engagements(self) -> set[str]:
        return self.control_engagements(KILLSWITCH_ACTION)

    def verify_integrity(self) -> None:
        error = verify_chain(self.entries, self.genesis)
        if error:
            raise AuditIntegrityError(error)


class AuditSink(Protocol):
    """Lo que el Harness necesita de una bitácora (en memoria o persistente)."""

    def record(self, agent: str, action: Action, target: str, token: ScopeToken,
               result: Result, reason: str | None = None,
               evidence: str | None = None, subject: str | None = None) -> Entry: ...
    def record_control(self, engagement_id: str, agent: str, action: str, target: str,
                       result: Result, reason: str | None = None,
                       evidence: str | None = None, subject: str | None = None) -> Entry: ...
    @property
    def entries(self) -> list[Entry]: ...
    def record_kill(self, engagement_id: str, agent: str) -> Entry: ...
    def control_engagements(self, action: str, result: Result = ...) -> set[str]: ...
    def killed_engagements(self) -> set[str]: ...
    def verify_integrity(self) -> None: ...


class KillSwitch:
    """Kill switch por engagement. Activarlo es irreversible: no hay forma de desactivarlo."""

    __slots__ = ("_engaged",)
    _engaged: set[str]

    def __init__(self) -> None:
        object.__setattr__(self, "_engaged", set())

    def engage(self, engagement_id: str) -> None:
        self._engaged.add(engagement_id)

    def disengage(self, engagement_id: str) -> None:
        raise PermissionError("el kill switch es irreversible: abrí un engagement nuevo")

    def is_engaged(self, engagement_id: str) -> bool:
        return engagement_id in self._engaged

    @property
    def engaged(self) -> frozenset[str]:
        return frozenset(self._engaged)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("el kill switch no se modifica por atributo; usá engage()")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class TokenVerifier(Protocol):
    def verify(self, token: ScopeToken) -> str | None: ...


class Harness:
    def __init__(self, guard: Guard, audit: AuditSink,
                 tools: dict[str, ToolAdapter], killswitch: KillSwitch,
                 issuer: TokenVerifier, resolver: Resolver = system_resolver,
                 limiter: RateLimiter | None = None):
        self.guard, self.audit, self.tools, self.killswitch = guard, audit, tools, killswitch
        self.issuer = issuer
        self.resolver = resolver
        # 004: rate limit por IP de destino para todo llamador (no solo el orquestador).
        if limiter is None:
            from harness.policy_loader import load_policy
            limiter = RateLimiter(int(load_policy()["limits"]["rate_limit_rps_per_target"]))
        self.limiter = limiter
        for engagement_id in audit.killed_engagements():   # kill switch persistente
            killswitch.engage(engagement_id)

    def kill(self, engagement_id: str, agent: str) -> None:
        """Activa el kill switch: primero queda en bitácora, después en memoria."""
        self.audit.record_kill(engagement_id, agent)
        self.killswitch.engage(engagement_id)

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken,
               subject: str | None = None) -> dict[str, Any]:
        """`subject` es el hallazgo al que se ata el gate humano (006, D2)."""
        try:
            self.audit.verify_integrity()       # con la cadena rota no se actúa
        except AuditIntegrityError:
            self.killswitch.engage(token.engagement_id)
            try:                                # dejar rastro, aunque la cadena ya esté rota
                self.audit.record_kill(token.engagement_id, agent="harness")
            except Exception:  # noqa: BLE001, S110 - lo importante es no ejecutar
                pass
            raise
        if self.killswitch.is_engaged(token.engagement_id):
            self.audit.record(agent, action, target, token, Result.ABORTED,
                              subject=subject)
            raise KillSwitchEngaged()
        reason = (self.issuer.verify(token)
                  or ("token_expired" if not token.is_live() else None)
                  or self.guard.check(action, target, token))
        if reason is not None:
            self.audit.record(agent, action, target, token, Result.BLOCKED, reason,
                              subject=subject)
            raise ScopeViolation(f"{action.name} sobre {target} bloqueada: {reason}", reason)
        canon = normalize_target(target)
        assert canon is not None          # garantizado por guard.check
        adapter = self.tools.get(action.name)
        if adapter is None:
            self.audit.record(agent, action, canon, token, Result.BLOCKED, "no_adapter",
                              subject=subject)
            raise ScopeViolation(f"capability sin adaptador registrado: {action.name}",
                                 "no_adapter")
        if token.phase not in adapter.allowed_phases:
            self.audit.record(agent, action, canon, token, Result.BLOCKED, "adapter_phase",
                              subject=subject)
            raise ScopeViolation(f"adaptador {adapter.name} no habilitado en {token.phase}",
                                 "adapter_phase")
        if getattr(adapter, "destructive", True) is not False:   # R14: lo declara el adaptador
            self.audit.record(agent, action, canon, token, Result.BLOCKED, "destructive",
                              subject=subject)
            raise ScopeViolation(f"adaptador {adapter.name} es destructivo", "destructive")
        addresses: tuple[str, ...] = (canon,)
        if not _is_ip(canon):             # A4: el nombre debe resolver solo a IP en alcance
            try:
                ips = self.resolver(canon)
            except Exception:  # noqa: BLE001 - un resolver que falla es "no resuelve"
                ips = []
            reason = self.guard.check_resolved(canon, ips, token)
            if reason is not None:
                self.audit.record(agent, action, canon, token, Result.BLOCKED, reason,
                              subject=subject)
                raise ScopeViolation(f"{canon} resuelve fuera de alcance: {reason}", reason)
            # 004: la herramienta usa estas IP y no vuelve a resolver (DNS rebinding).
            addresses = tuple(sorted({str(normalize_target(ip)) for ip in ips}))
        if self.guard.needs_approval(action, token):
            if subject is None:               # 006: nadie valida "en general", solo un hallazgo
                self.audit.record(agent, action, canon, token, Result.BLOCKED, "missing_subject")
                raise ScopeViolation(f"{action.name} con gate humano sin sujeto",
                                     "missing_subject")
            if not self.guard.approved(action, canon, token, subject):
                self.audit.record(agent, action, canon, token, Result.PENDING_HITL,
                              subject=subject)
                return {"status": "PENDING_HITL"}
        for address in addresses:             # puede esperar: el kill switch se mira después
            self.limiter.acquire(address)
        if self.killswitch.is_engaged(token.engagement_id):   # pudo activarse mientras tanto
            self.audit.record(agent, action, canon, token, Result.ABORTED,
                              subject=subject)
            raise KillSwitchEngaged()
        # Write-ahead: la decisión OK queda en bitácora ANTES de ejecutar. Si no se puede
        # registrar (otro engagement, base bloqueada, disco lleno), la herramienta no corre.
        self.audit.record(agent, action, canon, token, Result.OK,
                              subject=subject)
        try:
            run_subject = getattr(adapter, "run_subject", None)
            if subject is not None and callable(run_subject):   # adaptador atado al hallazgo
                out: dict[str, Any] = run_subject(action, canon, token, addresses, subject)
                return out
            return adapter.run(action, canon, token, addresses)
        except Exception:  # noqa: BLE001 - el OK ya está escrito: se cierra con ABORTED
            self.audit.record(agent, action, canon, token, Result.ABORTED, "adapter_error",
                              subject=subject)
            return {"tool": action.name, "target": canon, "status": "error",
                    "error": "adapter_error"}
