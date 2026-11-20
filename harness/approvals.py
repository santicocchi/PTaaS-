"""Registro de aprobaciones del loop C (change 006, D5): SQLite append-only por engagement.

`state/<engagement>.approvals.sqlite3` guarda tres cosas, ninguna se actualiza ni se borra:

- `queue`: cada versión (revisión) de lo que se enviaría por hallazgo: host, entrada del
  catálogo y parámetros. Si cambia algo, es otra revisión y necesita otra decisión (B1);
- `decisions`: cada decisión del Reviewer, atada a una revisión. La vigente es la última fila
  del hallazgo: un rechazo posterior revoca una aprobación (M3);
- `closures`: el cierre de cada hallazgo en VALIDATE (no se vuelve a procesar).

Nunca se aprueba por defecto: sin decisión, el hallazgo queda pendiente. Una aprobación vence
a los `approval_ttl_minutes` y una vencida vale lo mismo que ninguna. Una aprobación solo
habilita tráfico si además está en la bitácora (`hitl.approve` con su referencia, M1).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.contracts import SUBJECT_RE, AuditSink, Entry, Result
from harness.policy_loader import load_policy

DECISIONS = ("approved", "rejected")
OUTCOMES = ("validated", "not_validated", "failed")
CONTROLS = {"approved": "hitl.approve", "rejected": "hitl.reject"}
REVIEWER_RE = re.compile(r"^[\w.@-]{1,64}$")
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queue (
  finding_id TEXT NOT NULL, cwe TEXT NOT NULL, host TEXT NOT NULL, priority REAL,
  poc_id TEXT NOT NULL, params TEXT NOT NULL, enqueued_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
  finding_id TEXT NOT NULL, decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
  reviewer TEXT NOT NULL, reason TEXT NOT NULL, decided_at REAL NOT NULL, expires_at REAL,
  revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS closures (
  finding_id TEXT NOT NULL UNIQUE,
  outcome TEXT NOT NULL CHECK (outcome IN ('validated','not_validated','failed')),
  reason TEXT, closed_at REAL NOT NULL);
"""
_TRIGGERS = "".join(
    f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
    f"BEGIN SELECT RAISE(ABORT, 'append-only: {op} prohibido'); END;\n"
    for t in ("queue", "decisions", "closures") for op in ("UPDATE", "DELETE"))


class ReviewError(ValueError):
    """Decisión inválida: no se escribe nada."""


def load_review_limits(policy: dict[str, Any] | None = None) -> tuple[int, int]:
    """(validation_timeout_minutes, approval_ttl_minutes) del gate `before: validate`."""
    gates = (policy or load_policy()).get("gates_hitl") or []
    (gate,) = [g for g in gates if g.get("before") == "validate"]
    values = (gate.get("validation_timeout_minutes"), gate.get("approval_ttl_minutes"))
    if any(type(v) is not int or v < 1 for v in values):
        raise ValueError(f"tiempos del gate de validación inválidos: {values!r}")
    return values[0], values[1]


@dataclass(frozen=True)
class QueueItem:
    finding_id: str
    cwe: str
    host: str
    priority: float | None
    poc_id: str | None               # entrada del catálogo que se usaría (None: no hay)
    params: dict[str, str]
    enqueued_at: float
    revision: int = 0                # la asigna el registro al leer

    def same_request(self, host: str, poc_id: str | None, params: dict[str, str]) -> bool:
        return (self.host, self.poc_id, self.params) == (host, poc_id, params)


@dataclass(frozen=True)
class Decision:
    finding_id: str
    decision: str
    reviewer: str
    reason: str
    decided_at: float
    expires_at: float | None
    revision: int


@dataclass(frozen=True)
class Closure:
    finding_id: str
    outcome: str
    reason: str | None
    closed_at: float


def decision_ref(engagement_id: str, d: Decision) -> str:
    """Referencia de la decisión para la bitácora: su contenido completo, hasheado."""
    body = json.dumps(dataclasses.asdict(d), sort_keys=True).encode("utf-8")
    return f"approvals/{engagement_id}/{d.finding_id}#sha256={hashlib.sha256(body).hexdigest()}"


def decision_audited(entries: Iterable[Entry], engagement_id: str, d: Decision) -> bool:
    """M1: una fila del registro solo vale si la CLI la dejó también en la bitácora."""
    ref = decision_ref(engagement_id, d)
    control = CONTROLS[d.decision]
    return any(e.get("engagement") == engagement_id and e.get("phase") == "control"
               and e.get("action") == control and e.get("result") == Result.OK.value
               and e.get("subject") == d.finding_id
               and e.get("agent") == f"reviewer:{d.reviewer}" and e.get("evidence") == ref
               for e in entries)


class ApprovalStore:
    def __init__(self, path: Path, ttl_minutes: int | None = None) -> None:
        self.path = path
        self.ttl_s = 60 * (load_review_limits()[1] if ttl_minutes is None else ttl_minutes)
        self._con = sqlite3.connect(path, isolation_level=None, timeout=30)
        self._con.executescript(_SCHEMA + _TRIGGERS)

    @classmethod
    def open(cls, engagement_id: str, base_dir: Path | str = "state",
             ttl_minutes: int | None = None) -> ApprovalStore:
        if not _ENGAGEMENT_RE.match(engagement_id):
            raise ValueError(f"engagement_id inválido: {engagement_id!r}")
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        return cls(base / f"{engagement_id}.approvals.sqlite3", ttl_minutes)

    def close_connection(self) -> None:
        self._con.close()

    # -- cola --------------------------------------------------------------------------
    def enqueue(self, item: QueueItem) -> bool:
        """Agrega una revisión si la solicitud difiere de la última del hallazgo (si es la
        misma, no cambia nada, ni su hora de entrada). Volver a una solicitud anterior también
        es una revisión nueva: la aprobación vieja no la habilita."""
        if not SUBJECT_RE.match(item.finding_id):
            raise ValueError(f"finding_id inválido: {item.finding_id!r}")
        self._con.execute("BEGIN IMMEDIATE")
        try:
            latest = self.item(item.finding_id)
            if latest is not None and latest.same_request(item.host, item.poc_id, item.params):
                self._con.execute("COMMIT")
                return False
            self._con.execute(
                "INSERT INTO queue VALUES (?, ?, ?, ?, ?, ?, ?)",
                (item.finding_id, item.cwe, item.host, item.priority, item.poc_id or "",
                 json.dumps(item.params, sort_keys=True), item.enqueued_at))
            self._con.execute("COMMIT")
        except BaseException:
            self._con.execute("ROLLBACK")
            raise
        return True

    def item(self, finding_id: str) -> QueueItem | None:
        """La revisión más reciente del hallazgo."""
        row = self._con.execute(
            "SELECT rowid, * FROM queue WHERE finding_id = ? ORDER BY rowid DESC LIMIT 1",
            (finding_id,)).fetchone()
        if row is None:
            return None
        return QueueItem(row[1], row[2], row[3], row[4], row[5] or None, json.loads(row[6]),
                         row[7], row[0])

    def queue(self) -> list[QueueItem]:
        """Hallazgos en cola y todavía sin cerrar, en orden de llegada."""
        ids = [r[0] for r in self._con.execute(
            "SELECT finding_id FROM queue WHERE finding_id NOT IN "
            "(SELECT finding_id FROM closures) GROUP BY finding_id ORDER BY MIN(rowid)")]
        return [i for i in map(self.item, ids) if i is not None]

    # -- decisiones --------------------------------------------------------------------
    def decisions(self, finding_id: str) -> list[Decision]:
        rows = self._con.execute("SELECT * FROM decisions WHERE finding_id = ? ORDER BY rowid",
                                 (finding_id,)).fetchall()
        return [Decision(*r) for r in rows]

    def current(self, finding_id: str, now: float) -> Decision | None:
        """La decisión vigente: la última. Un rechazo vale siempre; una aprobación, solo para
        la revisión actual y antes de vencer (si no, vale como ninguna)."""
        found = self.decisions(finding_id)
        if not found:
            return None
        last = found[-1]
        if last.decision == "rejected":
            return last
        latest = self.item(finding_id)
        if latest is None or last.revision != latest.revision:
            return None
        if last.expires_at is None or now >= last.expires_at:
            return None
        return last

    def status(self, finding_id: str, now: float) -> str:
        found = self.decisions(finding_id)
        if not found:
            return "pending"
        current = self.current(finding_id, now)
        if current is not None:
            return current.decision
        latest = self.item(finding_id)
        if latest is not None and found[-1].revision != latest.revision:
            return "pending"                     # la verificación cambió: otra decisión
        return "expired"

    def check_decision(self, finding_id: str, decision: str, reviewer: str, reason: str,
                       now: float) -> QueueItem:
        """Valida una decisión sin escribir. Devuelve la revisión actual del hallazgo."""
        if decision not in DECISIONS:
            raise ReviewError(f"decisión inválida: {decision!r}")
        if not REVIEWER_RE.match(reviewer or ""):
            raise ReviewError("reviewer inválido o vacío")
        if not (reason or "").strip():
            raise ReviewError("el motivo es obligatorio")
        item = self.item(finding_id)
        if item is None or self.closure(finding_id) is not None:
            raise ReviewError(f"{finding_id} no está en la cola de revisión")
        current = self.current(finding_id, now)
        if current is not None and current.decision == "rejected":
            raise ReviewError(f"{finding_id} ya fue rechazado en este engagement")
        if current is not None and decision == "approved":
            raise ReviewError(f"{finding_id} ya tiene una aprobación vigente")
        return item                               # un rechazo revoca la aprobación (M3)

    def decide(self, finding_id: str, decision: str, reviewer: str, reason: str, now: float,
               on_record: Callable[[Decision, QueueItem], object] | None = None) -> Decision:
        """Valida y escribe en una transacción (M5). `on_record` corre antes del COMMIT: si
        falla, la fila no queda."""
        self._con.execute("BEGIN IMMEDIATE")      # nadie decide en el medio
        try:
            item = self.check_decision(finding_id, decision, reviewer, reason, now)
            expires = now + self.ttl_s if decision == "approved" else None
            d = Decision(finding_id, decision, reviewer, reason.strip(), now, expires,
                         item.revision)
            self._con.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                              dataclasses.astuple(d))
            if on_record is not None:
                on_record(d, item)
            self._con.execute("COMMIT")
        except BaseException:
            self._con.execute("ROLLBACK")
            raise
        return d

    # -- cierres -----------------------------------------------------------------------
    def close(self, finding_id: str, outcome: str, reason: str | None, now: float) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"resultado inválido: {outcome!r}")
        self._con.execute("INSERT INTO closures VALUES (?, ?, ?, ?)",
                          (finding_id, outcome, reason, now))

    def closure(self, finding_id: str) -> Closure | None:
        row = self._con.execute("SELECT * FROM closures WHERE finding_id = ?",
                                (finding_id,)).fetchone()
        return None if row is None else Closure(*row)


def record_decision(store: ApprovalStore, audit: AuditSink, engagement_id: str,
                    finding_id: str, decision: str, reviewer: str, reason: str,
                    now: float) -> Decision:
    """Decisión del Reviewer: fila del registro y control en la bitácora, juntos o ninguno.

    Orden (M5): la fila se inserta dentro de una transacción, después se escribe la bitácora y
    recién entonces COMMIT. Si la bitácora falla, ROLLBACK y no queda nada. Si falla el COMMIT
    después de la bitácora, queda un control sin fila: inerte (M1 exige las dos cosas) y el
    error sube.
    """
    def write(d: Decision, item: QueueItem) -> None:
        audit.record_control(engagement_id, f"reviewer:{reviewer}", CONTROLS[decision],
                             item.host, Result.OK, evidence=decision_ref(engagement_id, d),
                             subject=finding_id)
    return store.decide(finding_id, decision, reviewer, reason, now, write)
