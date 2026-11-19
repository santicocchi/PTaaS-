"""Orquestador del loop A (relevamiento), change 004.

Determinista: arma las acciones a partir del grafo y le pide permiso al Harness para cada
una. Orden por iteración: pasivo (subfinder) y después activo (httpx, nmap) sobre los activos
que aparecieron en la iteración anterior. Para por grafo estabilizado, por tope o porque el
Harness abortó (kill switch, bitácora rota, token vencido o revocado).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from harness.assets import AssetGraph, asset_id, canonical_address
from harness.contracts import (
    Action,
    AuditIntegrityError,
    Harness,
    KillSwitchEngaged,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
    _is_ip,
)
from harness.engagement import Engagement, State
from harness.loops import decide_recon
from harness.policy_loader import load_policy
from harness.ratelimit import RateLimiter
from harness.schemas import Asset, SchemaError, SchemaGate

AGENT = "recon-orchestrator"
PASSIVE = ("subfinder.enum",)
ACTIVE = ("httpx.probe", "nmap.service_scan")
_SCOPE_PROBE = Action("httpx.probe", Phase.RECON)   # para preguntarle al Guard por un activo
_FATAL = frozenset({"token_expired", "token_invalid", "token_revoked"})


class _Abort(Exception):
    pass


@dataclass(frozen=True)
class ReconResult:
    reason: str
    iterations: int
    handoff: tuple[Asset, ...] = field(default=())


class ReconLoop:
    def __init__(self, harness: Harness, engagement: Engagement, graph: AssetGraph,
                 token: ScopeToken, *, max_iterations: int | None = None,
                 limiter: RateLimiter | None = None,
                 policy: dict[str, Any] | None = None) -> None:
        policy = policy or load_policy()
        self.max_iterations = (int(policy["limits"]["max_loop_iterations"]["recon"])
                               if max_iterations is None else max_iterations)
        if self.max_iterations < 1:
            raise ValueError("el tope de iteraciones debe ser al menos 1")
        self.harness, self.engagement, self.graph, self.token = harness, engagement, graph, token
        self.limiter = limiter or RateLimiter(
            int(policy["limits"]["rate_limit_rps_per_target"]))
        self._gates: dict[str, SchemaGate] = {}
        self._disabled: set[str] = set()
        self._scope_filter = True         # solo los tests de defensa en profundidad lo apagan

    # -- loop -----------------------------------------------------------------------------
    def run(self) -> ReconResult:
        if self.engagement.state != State.RECON:
            return ReconResult("engagement fuera de RECON", 0)
        start = self.graph.last_iteration() + 1
        if start == 0:
            self._seed()
            start = 1
        iteration = start
        while True:
            frontier = [a for a in self.graph.new_in(iteration - 1)
                        if a.in_scope and a.type in ("domain", "ip")]
            try:
                for asset in frontier:                       # 1. pasivo
                    if asset.type == "domain":
                        self._step("subfinder.enum", asset, iteration)
                for asset in frontier:                       # 2. activo
                    for capability in ACTIVE:
                        self._step(capability, asset, iteration)
            except _Abort as stop:
                return ReconResult(f"abortado: {stop}", iteration)
            new = sum(1 for a in self.graph.new_in(iteration) if a.in_scope)
            decision = decide_recon(iteration, new, self.max_iterations)
            if decision.decision == "stop":
                return ReconResult(decision.reason, iteration, tuple(self.graph.handoff()))
            iteration += 1

    def _seed(self) -> None:
        """Semillas: dominios del token y, si hay, IP sueltas (/32 o /128). No se barren rangos."""
        for domain in self.token.allowed_domains:
            self._discover("domain", domain, "roe", 0)
        for cidr in self.token.allowed_cidrs:
            net = ipaddress.ip_network(cidr)
            if net.num_addresses == 1:
                self._discover("ip", str(net.network_address), "roe", 0)

    # -- una acción -----------------------------------------------------------------------
    def _step(self, capability: str, asset: Asset, iteration: int) -> None:
        if capability in self._disabled:
            return
        out = self._invoke(capability, asset.address)
        if out is None:
            return
        if capability == "subfinder.enum":
            for host in out.get("hosts", []):
                self._discover("domain", host, "subfinder", iteration)
        elif capability == "httpx.probe":
            for svc in out.get("services", []):
                self._http_service(svc, iteration)
        elif capability == "nmap.service_scan":
            for svc in out.get("services", []):
                if svc.get("tech"):
                    self.graph.add_tech(asset.id, svc["tech"], source_tool="nmap",
                                        iteration=iteration)

    def _invoke(self, capability: str, target: str) -> dict[str, Any] | None:
        self.limiter.acquire(target)
        try:
            out = self.harness.invoke(AGENT, Action(capability, Phase.RECON), target, self.token)
        except KillSwitchEngaged as exc:
            raise _Abort("kill switch") from exc
        except AuditIntegrityError as exc:
            raise _Abort("bitácora rota") from exc
        except ScopeViolation as exc:            # ya quedó en bitácora como BLOCKED
            if exc.reason in _FATAL:
                raise _Abort(str(exc.reason)) from exc
            return None
        status = out.get("status")
        if status == "error":
            self._control("tool.error", target, Result.ABORTED, str(out.get("error")))
            return None
        gate = self._gates.setdefault(capability, SchemaGate())
        if status == "invalid_output":
            self._control("tool.error", target, Result.ABORTED, "invalid_output")
            if gate.record(False) == "PENDING_HITL":
                self._disabled.add(capability)
                self._control("tool.escalated", capability, Result.PENDING_HITL,
                              "invalid_output")
            return None
        if status in ("PENDING_HITL",):
            return None
        gate.record(True)
        return out

    # -- descubrimientos ------------------------------------------------------------------
    def _http_service(self, svc: dict[str, Any], iteration: int) -> None:
        url = svc.get("url")
        if isinstance(url, str):
            added = self._discover("http_service", url, "httpx", iteration)
            try:
                aid = asset_id("http_service", url)
            except SchemaError:
                aid = None
            if aid and (added is None or added.in_scope):
                for tech in svc.get("tech") or []:
                    self.graph.add_tech(aid, tech, source_tool="httpx", iteration=iteration)
        location = svc.get("location")
        if isinstance(location, str):            # A5: el destino es un descubrimiento más
            host = urlsplit(location).hostname
            if host:
                self._discover("ip" if _is_ip(host) else "domain", host, "httpx", iteration)

    def _discover(self, kind: str, address: str, source: str, iteration: int) -> Asset | None:
        """Pasa el activo por el Guard antes de encolarlo (design.md D9)."""
        try:
            canon = canonical_address(kind, address)
        except SchemaError:
            return None                           # dato de la herramienta que no normaliza
        host = urlsplit(canon).hostname if kind == "http_service" else canon
        reason = self.harness.guard.check(_SCOPE_PROBE, host or "", self.token)
        if reason is not None and self._scope_filter:
            added = self.graph.add(kind, canon, source_tool=source, iteration=iteration,
                                   in_scope=False, reason=reason)
            if added is not None:
                self._control("asset.discovered", canon, Result.BLOCKED, reason)
            return added
        return self.graph.add(kind, canon, source_tool=source, iteration=iteration)

    def _control(self, action: str, target: str, result: Result, reason: str) -> None:
        self.harness.audit.record_control(self.token.engagement_id, AGENT, action, target,
                                          result, reason)
