"""Loop A (relevamiento) de punta a punta: RoE → token recon → loop → grafo → bitácora.

    python -m demo.loop_a            # simulación: adaptadores reales con salidas grabadas
    python -m demo.loop_a --lab      # laboratorio real, desde el contenedor `runner`

En los dos modos corren los adaptadores reales (subfinder, httpx, nmap) y el orquestador real,
todo por `Harness.invoke`. En simulación lo único falso es la salida de cada herramienta y el
DNS. En el laboratorio subfinder no encuentra nada (sus fuentes están en internet y el runner
no tiene salida), así que el loop sigue con las semillas del RoE.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from demo.checkpoint1 import _lab_reachable, bad, dim, ok, prepare_roe, warn
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.assets import AssetGraph
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import Guard, Harness, KillSwitch, Phase, ToolAdapter, system_resolver
from harness.engagement import Engagement
from harness.policy_loader import phase_allowlist
from harness.recon import ReconLoop
from harness.roe import parse_roe
from harness.tokens import TokenIssuer

ROOT = Path(__file__).resolve().parent
SIM_DNS = {"dvwa.lab.test": ["10.99.0.10"], "www.dvwa.lab.test": ["10.99.0.10"],
           "juiceshop.lab.test": ["10.99.0.11"]}
SIM_SUBFINDER = {
    "dvwa.lab.test": [
        '{"host":"www.dvwa.lab.test","input":"dvwa.lab.test","source":"crtsh"}',
        '{"host":"juiceshop.lab.test","input":"dvwa.lab.test","source":"crtsh"}',
        '{"host":"cdn.example.com","input":"dvwa.lab.test","source":"alienvault"}',
    ],
}
SIM_HTTPX = {
    "dvwa.lab.test": '{"port":"80","url":"http://10.99.0.10","status_code":200,'
                     '"title":"Login :: DVWA","webserver":"Apache/2.4.25 (Debian)",'
                     '"tech":["Apache HTTP Server:2.4.25","PHP"]}',
    "www.dvwa.lab.test": '{"port":"80","url":"http://10.99.0.10","status_code":302,'
                         '"location":"http://203.0.113.7/login","tech":[]}',
}
SIM_NMAP = ('<nmaprun><host><address addr="10.99.0.10" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="Apache httpd" version="2.4.25"/></port>'
            '</ports></host></nmaprun>')


def _arg(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1] if flag in argv else ""


def sim_runner(argv: list[str], timeout_s: int) -> str:
    """Salidas grabadas por herramienta y objetivo. No se ejecuta nada."""
    tool = argv[0]
    if tool == "subfinder":
        return "\n".join(SIM_SUBFINDER.get(_arg(argv, "-d"), []))
    if tool == "httpx":
        host = _arg(argv, "-H").removeprefix("Host: ")
        return SIM_HTTPX.get(host, "")
    return SIM_NMAP


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loop A de punta a punta")
    parser.add_argument("--lab", action="store_true", help="ejecutar contra el laboratorio")
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    args = parser.parse_args(argv)
    if args.lab and not _lab_reachable():
        print("No se resuelve dvwa.lab.test: --lab se corre dentro del contenedor runner:\n"
              "  docker compose -f lab/docker-compose.yml exec runner python -m demo.loop_a --lab",
              file=sys.stderr)
        return 2

    now = datetime.now(UTC)
    engagement_id = "demo-loopa-" + now.strftime("%Y%m%d-%H%M%S")
    roe = parse_roe(prepare_roe(engagement_id, now))
    audit = SqliteAuditLog.open(engagement_id, args.out)
    issuer = TokenIssuer(audit)
    token = issuer.issue(roe, Phase.RECON)
    runner = None if args.lab else sim_runner
    tools: dict[str, ToolAdapter] = {
        "subfinder.enum": SubfinderEnum() if runner is None else SubfinderEnum(runner),
        "httpx.probe": HttpxProbe() if runner is None else HttpxProbe(runner),
        "nmap.service_scan": NmapServiceScan() if runner is None else NmapServiceScan(runner),
    }
    harness = Harness(Guard(phase_allowlist()), audit, tools,
                      KillSwitch(), issuer,
                      resolver=system_resolver if args.lab else (lambda h: SIM_DNS.get(h, [])))
    engagement = Engagement(roe_valid=True)
    engagement.approve("first_active_action")      # el reviewer aprueba la primera acción activa
    engagement.advance()
    engagement.advance()
    graph = AssetGraph.open(engagement_id, args.out)

    mode = "LABORATORIO REAL (red aislada)" if args.lab else "SIMULACIÓN (salidas grabadas)"
    print(f"Loop A · {engagement_id} · {mode}")
    result = ReconLoop(harness, engagement, graph, token).run()
    print(f"\nTerminó: {result.reason} (iteraciones: {result.iterations})\n")

    print(dim(f"{'it':>2}  {'tipo':<12} {'activo':<32} {'origen':<9} estado / tecnologías"))
    for a in graph.assets():
        state = ok("en alcance") if a.in_scope else bad(f"FUERA ({a.reason})")
        techs = ", ".join(a.technologies)
        print(f"{a.iteration:>2}  {a.type:<12} {a.address:<32} {a.source_tool:<9} {state}"
              f"{'  ' + techs if techs else ''}")

    print(f"\nEntrega a correlación (005): {len(result.handoff)} activos con versión")
    for a in result.handoff:
        print(f"  · {a.address}: {', '.join(t for t in a.technologies if ':' in t)}")

    entries = audit.entries
    invoked = [e for e in entries if e["phase"] == "recon"]
    controls = [e for e in entries if e["action"] in ("asset.discovered", "tool.error",
                                                       "tool.escalated")]
    print(f"\nBitácora: {len(invoked)} invocaciones por el Harness, {len(controls)} registros de "
          f"control del orquestador")
    for e in controls:
        print(f"  {warn(e['action'])} {e['target']} → {e['result']} {e.get('reason') or ''}")
    audit.close()
    error = verify_file(audit.path)
    print(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))
    return 0 if error is None else 1


if __name__ == "__main__":
    sys.exit(main())
