"""Registro de aprobaciones del loop C (change 006, D5): SQLite append-only por engagement.

`state/<engagement>.approvals.sqlite3` guarda tres cosas, ninguna se actualiza ni se borra:

- `queue`: los hallazgos que entraron a revisión, con la verificación que se usaría;
- `decisions`: cada decisión del Reviewer. La vigente es la última fila del hallazgo;
- `closures`: el cierre de cada hallazgo en VALIDATE (no se vuelve a procesar).

Nunca se aprueba por defecto: sin decisión, el hallazgo queda pendiente. Una aprobación vence
a los `approval_ttl_minutes` y una vencida vale lo mismo que ninguna.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.contracts import SUBJECT_RE
from harness.policy_loader import load_policy

DECISIONS = ("approved", "rejected")
OUTCOMES = ("validated", "not_validated", "failed")
REVIEWER_RE = re.compile(r"^[\w.@-]{1,64}$")
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS queue (
  finding_id TEXT NOT NULL UNIQUE, cwe TEXT NOT NULL, host TEXT NOT NULL, priority REAL,
  poc_id TEXT, params TEXT NOT NULL, enqueued_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
  finding_id TEXT NOT NULL, decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')),
  reviewer TEXT NOT NULL, reason TEXT NOT NULL, decided_at REAL NOT NULL, expires_at REAL);
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


@dataclass(frozen=True)
class Decision:
    finding_id: str
    decision: str
    reviewer: str
    reason: str
    decided_at: float
    expires_at: float | None


@dataclass(frozen=True)
class Closure:
    finding_id: str
    outcome: str
    reason: str | None
    closed_at: float


class ApprovalStore:
    def __init__(self, path: Path, ttl_minutes: int | None = None) -> None:
        self.path = path
        self.ttl_s = 60 * (load_review_limits()[1] if ttl_minutes is None else ttl_minutes)
        self._con = sqlite3.connect(path, isolation_level=None)
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
        """Agrega el hallazgo a la cola. Si ya estaba, no cambia nada (ni su hora de entrada)."""
        if not SUBJECT_RE.match(item.finding_id):
            raise ValueError(f"finding_id inválido: {item.finding_id!r}")
        cur = self._con.execute(
            "INSERT OR IGNORE INTO queue VALUES (?, ?, ?, ?, ?, ?, ?)",
            (item.finding_id, item.cwe, item.host, item.priority, item.poc_id,
             json.dumps(item.params, sort_keys=True), item.enqueued_at))
        return cur.rowcount == 1

    def item(self, finding_id: str) -> QueueItem | None:
        row = self._con.execute("SELECT * FROM queue WHERE finding_id = ?",
                                (finding_id,)).fetchone()
        if row is None:
            return None
        return QueueItem(row[0], row[1], row[2], row[3], row[4], json.loads(row[5]), row[6])

    def queue(self) -> list[QueueItem]:
        """Hallazgos en cola y todavía sin cerrar, en orden de llegada."""
        ids = [r[0] for r in self._con.execute(
            "SELECT finding_id FROM queue WHERE finding_id NOT IN "
            "(SELECT finding_id FROM closures) ORDER BY rowid")]
        return [i for i in map(self.item, ids) if i is not None]

    # -- decisiones --------------------------------------------------------------------
    def decisions(self, finding_id: str) -> list[Decision]:
        rows = self._con.execute("SELECT * FROM decisions WHERE finding_id = ? ORDER BY rowid",
                                 (finding_id,)).fetchall()
        return [Decision(*r) for r in rows]

    def current(self, finding_id: str, now: float) -> Decision | None:
        """La decisión vigente: la última, salvo una aprobación vencida (vale como ninguna)."""
        found = self.decisions(finding_id)
        if not found:
            return None
        last = found[-1]
        if last.decision == "approved" and (last.expires_at is None or now >= last.expires_at):
            return None
        return last

    def status(self, finding_id: str, now: float) -> str:
        found = self.decisions(finding_id)
        if not found:
            return "pending"
        current = self.current(finding_id, now)
        return "expired" if current is None else current.decision

    def check_decision(self, finding_id: str, decision: str, reviewer: str, reason: str,
                       now: float) -> QueueItem:
        """Valida una decisión sin escribir. Devuelve el hallazgo en cola."""
        if decision not in DECISIONS:
            raise ReviewError(f"decisión inválida: {decision!r}")
        if not REVIEWER_RE.match(reviewer or ""):
            raise ReviewError("reviewer inválido o vacío")
        if not (reason or "").strip():
            raise ReviewError("el motivo es obligatorio")
        item = self.item(finding_id)
        if item is None or self.closure(finding_id) is not None:
            raise ReviewError(f"{finding_id} no está en la cola de revisión")
        if self.current(finding_id, now) is not None:
            raise ReviewError(f"{finding_id} ya tiene una decisión vigente")
        return item

    def decide(self, finding_id: str, decision: str, reviewer: str, reason: str,
               now: float) -> Decision:
        self.check_decision(finding_id, decision, reviewer, reason, now)
        expires = now + self.ttl_s if decision == "approved" else None
        d = Decision(finding_id, decision, reviewer, reason.strip(), now, expires)
        self._con.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?)",
                          (d.finding_id, d.decision, d.reviewer, d.reason, d.decided_at,
                           d.expires_at))
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
