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
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


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


class ScopeViolation(Exception): ...
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

    def run(self, action: Action, target: str, token: ScopeToken) -> dict:
        """Debe devolver JSON parseable. Nunca ejecuta fuera de `target`."""
        ...


BLOCK_REASONS = frozenset({
    "out_of_scope", "token_expired", "token_invalid", "wrong_phase",
    "not_allowlisted", "destructive", "no_adapter", "adapter_phase",
})


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
    if any(not lbl or len(lbl) > 63 or lbl.startswith("-") for lbl in labels):
        return None
    return host


class Guard:
    """Autorización determinista. Sin LLM, sin heurísticas."""

    def __init__(self, phase_allowlist: dict[Phase, set[str]],
                 approvals: set[tuple[str, Phase, str, str]] | None = None):
        self.phase_allowlist = phase_allowlist
        self._approvals: set[tuple[str, Phase, str, str]] = approvals or set()

    def approve(self, action_name: str, target: str, *, engagement_id: str, phase: Phase) -> None:
        """Registra una aprobación humana para (engagement, fase, acción, objetivo)."""
        canon = normalize_target(target)
        if canon is None:
            raise ValueError(f"objetivo no interpretable: {target!r}")
        self._approvals.add((engagement_id, phase, action_name, canon))

    def approved(self, action: Action, target: str, token: ScopeToken) -> bool:
        canon = normalize_target(target)
        return (token.engagement_id, token.phase, action.name, canon) in self._approvals

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


def entry_hash(entry: Entry) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def make_entry(*, prev: str, engagement: str, agent: str, action: str, target: str,
               phase: str, result: Result, reason: str | None = None,
               evidence: str | None = None) -> Entry:
    """Arma un registro con su hash. Valida motivo de bloqueo y forma de la evidencia."""
    body: Entry = {
        "ts": time.time(), "engagement": engagement, "agent": agent,
        "action": action, "target": target, "phase": phase,
        "result": result.value, "prev": prev,
    }
    if result is Result.BLOCKED:
        if reason not in BLOCK_REASONS:
            raise ValueError(f"motivo de bloqueo inválido: {reason!r}")
        body["reason"] = reason
    if evidence is not None:
        if not EVIDENCE_RE.match(evidence) or ".." in evidence.split("/"):
            raise ValueError("la evidencia debe ser una referencia '<ruta>#sha256=<hex>'")
        body["evidence"] = evidence
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
               evidence: str | None = None) -> Entry:
        return self._append(engagement=token.engagement_id, agent=agent, action=action.name,
                            target=target, phase=token.phase.value, result=result,
                            reason=reason, evidence=evidence)

    def record_kill(self, engagement_id: str, agent: str) -> Entry:
        return self._append(engagement=engagement_id, agent=agent, action=KILLSWITCH_ACTION,
                            target=engagement_id, phase="control", result=Result.ABORTED)

    def killed_engagements(self) -> set[str]:
        return {e["engagement"] for e in self.entries
                if e["action"] == KILLSWITCH_ACTION and e["phase"] == "control"}

    def verify_integrity(self) -> None:
        error = verify_chain(self.entries, self.genesis)
        if error:
            raise AuditIntegrityError(error)


class AuditSink(Protocol):
    """Lo que el Harness necesita de una bitácora (en memoria o persistente)."""

    def record(self, agent: str, action: Action, target: str, token: ScopeToken,
               result: Result, reason: str | None = None,
               evidence: str | None = None) -> Entry: ...
    def record_kill(self, engagement_id: str, agent: str) -> Entry: ...
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


class Harness:
    def __init__(self, guard: Guard, audit: AuditSink,
                 tools: dict[str, ToolAdapter], killswitch: KillSwitch):
        self.guard, self.audit, self.tools, self.killswitch = guard, audit, tools, killswitch
        for engagement_id in audit.killed_engagements():   # kill switch persistente
            killswitch.engage(engagement_id)

    def kill(self, engagement_id: str, agent: str) -> None:
        """Activa el kill switch: primero queda en bitácora, después en memoria."""
        self.audit.record_kill(engagement_id, agent)
        self.killswitch.engage(engagement_id)

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken) -> dict:
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
            self.audit.record(agent, action, target, token, Result.ABORTED)
            raise KillSwitchEngaged()
        reason = "token_expired" if not token.is_live() else self.guard.check(action, target, token)
        if reason is not None:
            self.audit.record(agent, action, target, token, Result.BLOCKED, reason)
            raise ScopeViolation(f"{action.name} sobre {target} bloqueada: {reason}")
        canon = normalize_target(target)
        assert canon is not None          # garantizado por guard.check
        if action.requires_human_approval and not self.guard.approved(action, canon, token):
            self.audit.record(agent, action, canon, token, Result.PENDING_HITL)
            return {"status": "PENDING_HITL"}
        adapter = self.tools.get(action.name)
        if adapter is None:
            self.audit.record(agent, action, canon, token, Result.BLOCKED, "no_adapter")
            raise ScopeViolation(f"capability sin adaptador registrado: {action.name}")
        if token.phase not in adapter.allowed_phases:
            self.audit.record(agent, action, canon, token, Result.BLOCKED, "adapter_phase")
            raise ScopeViolation(f"adaptador {adapter.name} no habilitado en {token.phase}")
        # Write-ahead: la decisión OK queda en bitácora ANTES de ejecutar. Si no se puede
        # registrar (otro engagement, base bloqueada, disco lleno), la herramienta no corre.
        self.audit.record(agent, action, canon, token, Result.OK)
        return adapter.run(action, canon, token)
