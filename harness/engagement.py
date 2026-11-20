"""Máquina de estados del engagement. Las transiciones con gate exigen aprobación humana."""
from __future__ import annotations

from enum import Enum


class State(str, Enum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    RECON = "RECON"
    CORRELATE = "CORRELATE"
    ANALYZE = "ANALYZE"
    VALIDATE = "VALIDATE"
    REPORT = "REPORT"
    DELIVERED = "DELIVERED"
    ABORTED = "ABORTED"


_NEXT = {
    State.CREATED: State.AUTHORIZED,
    State.AUTHORIZED: State.RECON,
    State.RECON: State.CORRELATE,
    State.CORRELATE: State.ANALYZE,
    State.ANALYZE: State.VALIDATE,
    State.VALIDATE: State.REPORT,
    State.REPORT: State.DELIVERED,
}
# Gate HITL: destino -> nombre de la aprobación requerida
_GATES = {
    State.RECON: "first_active_action",
    State.VALIDATE: "before_validate",
    State.DELIVERED: "before_deliver",
}


class TransitionError(Exception): ...


# 007, D17: `before_deliver` no se otorga con `approve()`. Lo otorga `harness.delivery` después
# de verificar la cadena, el kill switch y la aprobación auditada, y de registrar
# `report.delivered`. Un test controla que nadie más en `harness/` use esta marca.
_DELIVERY_GRANT = object()


class Engagement:
    def __init__(self, roe_valid: bool):
        self.state = State.CREATED
        self.roe_valid = roe_valid
        self.approvals: set[str] = set()

    def approve(self, gate: str) -> None:
        if gate == "before_deliver":
            raise TransitionError("before_deliver lo otorga la entrega registrada "
                                  "(harness.delivery), no una aprobación suelta")
        self.approvals.add(gate)

    def grant_delivery(self, grant: object) -> None:
        if grant is not _DELIVERY_GRANT:
            raise TransitionError("before_deliver solo lo otorga harness.delivery")
        self.approvals.add("before_deliver")

    def advance(self) -> State:
        if self.state in (State.DELIVERED, State.ABORTED):
            raise TransitionError(f"estado terminal: {self.state}")
        target = _NEXT[self.state]
        if target == State.AUTHORIZED and not self.roe_valid:
            raise TransitionError("sin RoE válido no hay autorización")
        gate = _GATES.get(target)
        if gate and gate not in self.approvals:
            raise TransitionError(f"falta aprobación HITL: {gate}")
        self.state = target
        return self.state

    def kill(self) -> State:
        if self.state != State.DELIVERED:
            self.state = State.ABORTED
        return self.state
