"""Correlación determinista del change 005 (D1–D6): grafo + snapshots → CandidateFinding.

Las tres capabilities de datos (`cve.lookup`, `epss.lookup`, `cwe.map`) son adaptadores que leen
el grafo y los snapshots locales: no abren conexiones. Igual pasan por `Harness.invoke`, con un
token de fase CORRELATE y el host del activo como objetivo, así quedan en la bitácora y el Guard
decide si ese host está en alcance.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from harness.assets import AssetGraph
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
from harness.feeds import (
    UNKNOWN_CWE,
    Feeds,
    FeedUnavailable,
    is_distro_marker,
    load_attack_map,
    parse_version,
    split_tech,
)
from harness.schemas import Asset, CandidateFinding, dedupe

AGENT = "correlation-orchestrator"
FeedLoader = Callable[[], Feeds]


def host_of(asset: Asset) -> str:
    if asset.type == "http_service":
        return urlsplit(asset.address).hostname or ""
    return asset.address


@dataclass(frozen=True)
class HostView:
    """Todo lo que el grafo sabe de un host: activos en alcance y tecnologías con su fuente."""
    host: str
    asset_id: str                        # el activo dominio/IP (o el primer servicio)
    techs: tuple[tuple[str, str], ...]   # (tecnología, herramienta)


def host_view(graph: AssetGraph, host: str) -> HostView | None:
    assets = [a for a in graph.assets(in_scope=True) if host_of(a) == host]
    if not assets:
        return None
    main = next((a for a in assets if a.type in ("domain", "ip")), assets[0])
    techs: list[tuple[str, str]] = []
    for a in assets:
        techs += graph.tech_sources(a.id)
    return HostView(host, main.id, tuple(techs))


@dataclass(frozen=True)
class VersionMatch:
    product: str
    version: str
    tools: tuple[str, ...]
    techs: tuple[str, ...]


def versioned_products(view: HostView, feeds: Feeds) -> list[VersionMatch]:
    """Agrupa por (producto CPE, versión) las tecnologías que la tabla de alias reconoce."""
    groups: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
    for tech, tool in view.techs:
        name, version = split_tech(tech)
        product = feeds.product_of(name)
        if product is None or parse_version(version) is None:
            continue                     # sin alias o versión que no se entiende: no se busca
        assert version is not None
        tools, techs = groups.setdefault((product, version), (set(), set()))
        tools.add(tool)
        techs.add(tech)
    return [VersionMatch(p, v, tuple(sorted(t)), tuple(sorted(x)))
            for (p, v), (t, x) in sorted(groups.items())]


# -- adaptadores de datos ----------------------------------------------------------------
class _DataAdapter:
    allowed_phases: tuple[Phase, ...] = (Phase.CORRELATE,)
    destructive: bool = False
    tool = ""

    def __init__(self, graph: AssetGraph, feeds: FeedLoader) -> None:
        self._graph = graph
        self._feeds = feeds

    def _context(self, target: str) -> tuple[HostView | None, Feeds | None, str | None]:
        try:
            feeds = self._feeds()
        except FeedUnavailable as exc:
            return None, None, exc.reason
        return host_view(self._graph, target), feeds, None

    def _matches(self, view: HostView | None, feeds: Feeds) -> list[dict[str, Any]]:
        if view is None:
            return []
        out = []
        for vm in versioned_products(view, feeds):
            version = parse_version(vm.version)
            assert version is not None
            for rec in feeds.lookup(vm.product, version):
                out.append({"cve": rec.id, "product": vm.product, "version": vm.version,
                            "tools": list(vm.tools), "techs": list(vm.techs),
                            "cwes": list(rec.cwes), "cvss_score": rec.cvss_score,
                            "cvss_version": rec.cvss_version})
        return out

    def _base(self, target: str, feeds: Feeds) -> dict[str, Any]:
        return {"tool": self.tool, "target": target, "status": "ok", "stale": feeds.stale,
                "synthetic": feeds.synthetic,
                "retrieved_at": feeds.retrieved_at.isoformat()}


def _unavailable(tool: str, target: str, reason: str) -> dict[str, Any]:
    return {"tool": tool, "target": target, "status": "unavailable", "feed_error": reason}


class CveLookup(_DataAdapter):
    name: str = "cve.lookup"
    tool = "nvd_feed"

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        view, feeds, error = self._context(target)
        if feeds is None:
            return _unavailable(self.tool, target, str(error))
        return {**self._base(target, feeds), "matches": self._matches(view, feeds),
                "distro": view is not None and is_distro_marker(t for t, _ in view.techs),
                "asset_id": view.asset_id if view else None}


class EpssLookup(_DataAdapter):
    name: str = "epss.lookup"
    tool = "epss_feed"

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        view, feeds, error = self._context(target)
        if feeds is None:
            return _unavailable(self.tool, target, str(error))
        cves = sorted({m["cve"] for m in self._matches(view, feeds)})
        return {**self._base(target, feeds), "epss": {c: feeds.epss.get(c) for c in cves}}


class CweMap(_DataAdapter):
    name: str = "cwe.map"
    tool = "cwe_catalog"

    def __init__(self, graph: AssetGraph, feeds: FeedLoader,
                 attack_map: dict[str, str] | None = None) -> None:
        super().__init__(graph, feeds)
        self._attack = load_attack_map() if attack_map is None else attack_map

    def run(self, action: Action, target: str, token: ScopeToken,
            addresses: tuple[str, ...]) -> dict[str, Any]:
        view, feeds, error = self._context(target)
        if feeds is None:
            return _unavailable(self.tool, target, str(error))
        cwes = sorted({c for m in self._matches(view, feeds) for c in m["cwes"]})
        return {**self._base(target, feeds), "attack": {c: self._attack.get(c) for c in cwes}}


# -- correlador --------------------------------------------------------------------------
def candidate_id(asset_id: str, key: str) -> str:
    return "f-" + hashlib.sha256(f"{asset_id}|{key}".encode()).hexdigest()[:16]


def confidence_for(tools: list[str], *, distro: bool, cwe_known: bool, stale: bool) -> str:
    """Reglas fijas de D4 para un candidato que solo tiene evidencia de versión."""
    if len(set(tools)) >= 2 and not distro and cwe_known and not stale:
        return "medium"
    return "low"


@dataclass
class CorrelationResult:
    candidates: list[CandidateFinding] = field(default_factory=list)
    reason: str = "ok"                   # ok | feed_unavailable:<motivo> | abortado
    synthetic: bool = False


class _Abort(Exception):
    pass


class Correlator:
    def __init__(self, harness: Harness, token: ScopeToken, *, engagement: Engagement) -> None:
        if token.phase is not Phase.CORRELATE:
            raise ValueError("la correlación necesita un token de fase CORRELATE")
        self.harness, self.token, self.engagement = harness, token, engagement

    def _invoke(self, capability: str, host: str) -> dict[str, Any] | None:
        try:
            return self.harness.invoke(AGENT, Action(capability, Phase.CORRELATE), host,
                                       self.token)
        except (KillSwitchEngaged, AuditIntegrityError) as exc:
            raise _Abort from exc
        except ScopeViolation as exc:
            if exc.reason in ("token_expired", "token_invalid", "token_revoked"):
                raise _Abort from exc
            return None                      # host fuera de alcance: no se correlaciona

    def run(self, hosts: list[str]) -> CorrelationResult:
        if self.engagement.state != State.CORRELATE:     # la máquina de estados manda (B3)
            return CorrelationResult([], "engagement fuera de CORRELATE")
        found: list[CandidateFinding] = []
        synthetic = False
        try:
            for host in sorted(set(hosts)):
                cves = self._invoke("cve.lookup", host)
                if cves is None:
                    continue
                if cves.get("status") == "unavailable":
                    reason = str(cves.get("feed_error"))
                    self.harness.audit.record_control(self.token.engagement_id, AGENT,
                                              "feed.unavailable", f"data/feeds:{reason}",
                                              Result.ABORTED)
                    return CorrelationResult([], f"feed_unavailable:{reason}")
                if cves.get("status") != "ok" or not cves.get("matches"):
                    continue
                synthetic = synthetic or bool(cves.get("synthetic"))
                epss = (self._invoke("epss.lookup", host) or {}).get("epss", {})
                attack = (self._invoke("cwe.map", host) or {}).get("attack", {})
                found += self._candidates(host, cves, epss, attack)
        except _Abort:
            return CorrelationResult(dedupe(found), "abortado", synthetic)
        return CorrelationResult(dedupe(found), "ok", synthetic)

    @staticmethod
    def _candidates(host: str, cves: dict[str, Any], epss: dict[str, Any],
                    attack: dict[str, Any]) -> list[CandidateFinding]:
        asset = str(cves["asset_id"])
        stale, distro = bool(cves.get("stale")), bool(cves.get("distro"))
        out = []
        for m in cves["matches"]:
            cwe = m["cwes"][0] if m["cwes"] else UNKNOWN_CWE
            refs = [f"asset:{asset}", f"feed:nvd:{m['cve']}",
                    *(f"tech:{t}" for t in m["techs"]),
                    *(f"tool:{t}" for t in m["tools"])]
            if distro:
                refs.append("note:banner de distribución, puede haber backport")
            if stale:
                refs.append("note:snapshot desactualizado")
            score = epss.get(m["cve"])
            out.append(CandidateFinding(
                id=candidate_id(asset, m["cve"]), asset_id=asset, cwe=cwe, cve=m["cve"],
                epss=score if isinstance(score, float) else None,
                attack_technique=attack.get(cwe) if cwe != UNKNOWN_CWE else None,
                evidence_refs=refs,
                confidence=confidence_for(m["tools"], distro=distro,
                                          cwe_known=cwe != UNKNOWN_CWE, stale=stale),
                cvss_score=m["cvss_score"], cvss_version=m["cvss_version"], feed_stale=stale,
                host=host, title=f"{m['cve']} en {m['product']} {m['version']}"))
        return out
