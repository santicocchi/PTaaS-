"""Pipeline de punta a punta del change 005: relevamiento → correlación → análisis → bitácora.

    python -m demo.pipeline            # simulación: adaptadores reales, salidas grabadas
    python -m demo.pipeline --lab      # laboratorio real, desde el contenedor `runner`

Las tres fases usan el mismo Harness y el mismo engagement, con un token por fase. Cada token
sale del RoE de `demo/roe-pipeline.yaml`, que autoriza recon, correlate y analyze (y nada más).

- Relevamiento: el loop A de `demo/loop_a.py` (subfinder, httpx, nmap).
- Correlación: versiones del grafo contra los snapshots locales de `data/feeds/` (NVD y EPSS).
  No sale nada a internet. Hoy el snapshot es SINTÉTICO (CVE-2099-…): lo real lo genera el
  equipo con `tools/build_feeds.py`.
- Análisis: nuclei con los templates propios de `templates/allowlist/` y ZAP por su API, en
  modo protegido, solo con spider y escaneo pasivo. Un template sin revisor no corre: la demo
  lo dice y sigue con ZAP.

En simulación lo único falso es la salida de cada herramienta, la API de ZAP y el DNS.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from demo.checkpoint1 import _lab_reachable, bad, dim, ok, prepare_roe, warn
from demo.loop_a import SIM_DNS
from demo.loop_a import sim_runner as recon_sim_runner
from harness.adapters.common import Runner, default_runner
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.adapters.zap_adapter import ENDPOINTS, ZapBaselineScan, ZapClient
from harness.analysis import AnalysisLoop, FindingStore
from harness.assets import AssetGraph
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import Guard, Harness, KillSwitch, Phase, ToolAdapter, system_resolver
from harness.correlate import Correlator, CveLookup, CweMap, EpssLookup, host_of, host_view
from harness.engagement import Engagement
from harness.feeds import load_feeds_by_policy
from harness.policy_loader import phase_allowlist
from harness.recon import ReconLoop
from harness.roe import criticality_of, parse_roe
from harness.templates import ALLOWLIST, runnable
from harness.tokens import TokenIssuer

ROOT = Path(__file__).resolve().parent
ROE_TEMPLATE = ROOT / "roe-pipeline.yaml"
TEMPLATES = ALLOWLIST

# Salida de nuclei v3.11.1 (-jsonl) contra el DVWA del laboratorio, con la IP de la simulación.
# Solo se usa si hay templates aprobados; si no, nuclei no corre.
_IP = "10.99.0.10"
SIM_NUCLEI = "\n".join(json.dumps(line) for line in [
    {"template-id": "ptaas-server-version", "ip": _IP, "matched-at": f"http://{_IP}:80/",
     "info": {"severity": "info", "classification": {"cwe-id": ["cwe-497"]}},
     "extracted-results": ["Apache/2.4.25 (Debian)"]},
    {"template-id": "ptaas-missing-csp", "ip": _IP, "matched-at": f"http://{_IP}:80/",
     "info": {"severity": "info", "classification": {"cwe-id": ["cwe-693"]}}},
    {"template-id": "ptaas-dvwa-login-panel", "ip": _IP,
     "matched-at": f"http://{_IP}:80/login.php", "info": {"severity": "info"}},
])

# Alertas de ZAP 2.17.0 vistas en la prueba real contra el DVWA (D7), sin la IP: se completa
# con la que pide el adaptador, así una respuesta nunca "es" de otro host.
SIM_ZAP_ALERTS = [
    ("10038", "Content Security Policy (CSP) Header Not Set", "Medium", "High", "693", "/", ""),
    ("10020", "Missing Anti-clickjacking Header", "Medium", "Medium", "1021", "/login.php", ""),
    ("10036", "Server Leaks Version Information via \"Server\" HTTP Response Header Field",
     "Low", "High", "497", "/", "Apache/2.4.25 (Debian)"),
    ("10036", "Server Leaks Version Information via \"Server\" HTTP Response Header Field",
     "Low", "High", "497", "/robots.txt", "Apache/2.4.25 (Debian)"),
    ("10010", "Cookie No HttpOnly Flag", "Low", "Medium", "1004", "/login.php",
     "Set-Cookie: PHPSESSID"),
    ("10027", "Information Disclosure - Suspicious Comments", "Informational", "Low", "-1",
     "/dvwa/js/x.js", ""),
]


class SimZap:
    """API de ZAP simulada: contesta como ZAP 2.17.0 y solo acepta los endpoints del adaptador."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def call(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        if path not in ENDPOINTS:
            raise AssertionError(f"endpoint no permitido: {path}")
        self.calls.append(path)
        if path.endswith("/spider/action/scan/"):
            return {"scan": "0"}
        if path.endswith("/spider/view/status/"):
            return {"status": "100"}
        if path.endswith("/recordsToScan/"):
            return {"recordsToScan": "0"}
        if path.endswith("/core/view/alerts/"):
            base = params["baseurl"]
            return {"alerts": [{"pluginId": p, "alert": name, "risk": risk, "confidence": conf,
                                "cweid": cwe, "url": base + path_, "evidence": ev, "param": ""}
                               for p, name, risk, conf, cwe, path_, ev in SIM_ZAP_ALERTS]}
        return {"Result": "OK"}


def sim_runner(argv: list[str], timeout_s: int) -> str:
    """Recon como en loop A; nuclei con su salida grabada. No se ejecuta nada."""
    return SIM_NUCLEI if argv[0] == "nuclei" else recon_sim_runner(argv, timeout_s)


def ports_of(graph: AssetGraph) -> Any:
    """Puertos web del host según el grafo (servicios HTTP en alcance)."""
    def ports(host: str) -> list[int]:
        found = {urlsplit(a.address).port or 80 for a in graph.assets(in_scope=True)
                 if a.type == "http_service" and host_of(a) == host}
        return sorted(found) or [80]
    return ports


def build_tools(graph: AssetGraph, lab: bool, zap: ZapClient | None) -> dict[str, ToolAdapter]:
    runner: Runner = default_runner if lab else sim_runner
    web_ports = ports_of(graph)
    adapters: list[ToolAdapter] = [
        SubfinderEnum(runner), HttpxProbe(runner), NmapServiceScan(runner),
        CveLookup(graph, load_feeds_by_policy), EpssLookup(graph, load_feeds_by_policy),
        CweMap(graph, load_feeds_by_policy),
        NucleiSafeTemplates(runner, ports_of=web_ports, templates_dir=TEMPLATES),
        ZapBaselineScan(zap, ports_of=web_ports,
                        sleep=time.sleep if lab else (lambda s: None)),
    ]
    return {a.name: a for a in adapters}


def _phase(title: str) -> None:
    print(f"\n── {title}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Relevamiento → correlación → análisis")
    parser.add_argument("--lab", action="store_true", help="ejecutar contra el laboratorio")
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    args = parser.parse_args(argv)
    if args.lab and not _lab_reachable():
        print("No se resuelve dvwa.lab.test: --lab se corre dentro del contenedor runner:\n"
              "  docker compose -f lab/docker-compose.yml exec runner python -m demo.pipeline "
              "--lab", file=sys.stderr)
        return 2

    now = datetime.now(UTC)
    engagement_id = "demo-pipeline-" + now.strftime("%Y%m%d-%H%M%S")
    roe = parse_roe(prepare_roe(engagement_id, now, ROE_TEMPLATE))
    audit = SqliteAuditLog.open(engagement_id, args.out)
    issuer = TokenIssuer(audit)
    graph = AssetGraph.open(engagement_id, args.out)
    tools = build_tools(graph, args.lab, None if args.lab else SimZap())
    harness = Harness(Guard(phase_allowlist()), audit, tools, KillSwitch(), issuer,
                      resolver=system_resolver if args.lab else (lambda h: SIM_DNS.get(h, [])))
    engagement = Engagement(roe_valid=True)
    engagement.approve("first_active_action")       # el reviewer aprueba la primera acción activa
    engagement.advance()

    mode = "LABORATORIO REAL (red aislada)" if args.lab else "SIMULACIÓN (salidas grabadas)"
    print(f"Pipeline 005 · {engagement_id} · {mode}")
    if args.lab and not os.environ.get("PTAAS_ZAP_API_KEY"):
        print(warn("Falta PTAAS_ZAP_API_KEY: ZAP va a fallar (ver lab/README.md)."))

    # 1. Relevamiento ---------------------------------------------------------------------
    _phase(f"1. Relevamiento (estado {engagement.advance().value})")
    recon = ReconLoop(harness, engagement, graph, issuer.issue(roe, Phase.RECON)).run()
    web_hosts = sorted({host_of(a) for a in graph.assets(in_scope=True)
                        if a.type == "http_service"})
    print(f"   {recon.reason}; {len(recon.handoff)} activos con versión, "
          f"servicios web en: {', '.join(web_hosts) or 'ninguno'}")

    # 2. Correlación ----------------------------------------------------------------------
    _phase(f"2. Correlación (estado {engagement.advance().value})")
    corr = Correlator(harness, issuer.issue(roe, Phase.CORRELATE)).run(
        sorted({host_of(a) for a in recon.handoff}))
    if corr.synthetic:
        print(warn("   Snapshot SINTÉTICO: los CVE-2099-… son datos de prueba, no CVE reales."))
    print(f"   {corr.reason}; {len(corr.candidates)} candidatos por versión")
    for c in corr.candidates:
        print(f"   · {c.cve or c.cwe} en {c.host}: CVSS {c.cvss_version} {c.cvss_score}, "
              f"EPSS {'sin dato' if c.epss is None else c.epss}, confianza {c.confidence}")

    # 3. Análisis -------------------------------------------------------------------------
    _phase(f"3. Análisis (estado {engagement.advance().value})")
    ready, skipped = runnable(TEMPLATES)
    print(f"   nuclei: {len(ready)} templates aprobados, {len(skipped)} sin correr")
    for reason in skipped:
        print(dim(f"     - {reason}"))
    store = FindingStore.open(engagement_id, args.out)
    loop = AnalysisLoop(harness, issuer.issue(roe, Phase.ANALYZE), store,
                        asset_of=lambda h: (v.asset_id if (v := host_view(graph, h))
                                            else f"host:{h}"),
                        criticality_of=lambda h: criticality_of(roe, h))
    result = loop.run(corr.candidates, web_hosts)
    store.close()
    print(f"   {result.reason}; {len(result.vulns)} vulnerabilidades priorizadas\n")
    cands = {c.id: c for c in result.candidates}
    print(dim(f"   {'prioridad':>9}  {'estado':<12} {'qué':<16} {'host':<20} confianza"))
    for v in sorted(result.vulns, key=lambda v: (
            v.priority is None, -(v.priority or 0), cands[v.finding_id].host,
            cands[v.finding_id].cve or cands[v.finding_id].cwe)):
        c = cands[v.finding_id]
        state = {"confirmed": ok, "discarded": dim}.get(v.status, warn)(f"{v.status:<12}")
        prio = "—" if v.priority is None else f"{v.priority:.2f}"
        flag = bad("  revisar") if v.needs_review else ""
        print(f"   {prio:>9}  {state} {(c.cve or c.cwe):<16} {c.host:<20} {c.confidence}{flag}")

    # Bitácora ------------------------------------------------------------------------------
    entries = audit.entries
    by_phase: dict[str, int] = {}
    for e in entries:
        by_phase[e["phase"]] = by_phase.get(e["phase"], 0) + 1
    print("\nBitácora: " + ", ".join(f"{n} de {p}" for p, n in sorted(by_phase.items())))
    for e in entries:
        if e["phase"] == "control" and e["action"] != "asset.discovered":
            print(f"   {warn(e['action'])} {e['target']} → {e['result']} {e.get('reason') or ''}")
    audit.close()
    error = verify_file(audit.path)
    print(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))
    return 0 if error is None else 1


if __name__ == "__main__":
    sys.exit(main())
