"""Demo del change 007: informe y entrega, al final del recorrido del laboratorio.

    python -m demo.pipeline [--lab]                  # 1. relevamiento → correlación → análisis
    python -m demo.validation [--lab] ...            # 2. loop C, con los gates del Reviewer
    python -m demo.report --engagement <id>          # 3. genera report-v1 y pide la aprobación
    python -m harness.review ... report approve ...  # 4. el Reviewer aprueba ESA versión
    python -m demo.report --engagement <id>          # 5. entrega y REPORT → DELIVERED

Corre en el host, sobre `demo/state/` (lo que importó el loop C). No abre ninguna conexión:
el RoE de la demo no tiene `report_destinations`, así que la entrega es el archivo de
importación de DefectDojo (D16) más el resumen de la entrega.

**Qué se usa y de dónde.** Los hallazgos salen de la entrega importada por el loop C, que se
verifica contra su `handoff.imported` en la bitácora del host. El estado de validación sale de
la bitácora (D6), no de la entrega. Los activos de la sección 3 se arman con los hosts web de
esa entrega; el grafo del runner (`demo/out`) no se lee porque el runner lo puede escribir.

**Gates.** La demo nunca aprueba: imprime el comando de `harness.review` con el hash de la
versión y se detiene. Si se vuelve a correr sin aprobación, queda otro PENDING_HITL. Una vez
generada, la versión no cambia al volver a correr: `--new-version` genera la siguiente (y la
aprobación anterior deja de valer).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from demo.checkpoint1 import bad, dim, ok, warn
from demo.validation import (
    GATE,
    IMAGE_ACTION,
    SIM_IMAGE,
    STATE,
    HandoffError,
    _printable,
    _shown,
    engagement_in_validate,
    findings,
    gate_reviewer,
    load_imported,
)
from harness.analysis import FindingStore
from harness.approvals import ApprovalStore
from harness.assets import AssetGraph
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import (
    REPORT_GENERATED_ACTION,
    Guard,
    Harness,
    KillSwitch,
    KillSwitchEngaged,
    Result,
)
from harness.delivery import (
    DeliveryContext,
    DeliveryError,
    DeliveryNotApproved,
    deliver,
    delivered,
    delivery_status,
    latest_report,
)
from harness.engagement import Engagement
from harness.feeds import FEEDS_DIR, MANIFEST_FILE
from harness.policy_loader import phase_allowlist
from harness.report_catalog import REPORT_CATALOG, ReportCatalog
from harness.reporting import (
    MissingField,
    ReportContext,
    ReportError,
    _in_lab,
    _in_roe,
    _lab_targets,
    _roe_summary,
    generate_report,
)
from harness.roe import RoE, RoEError, parse_roe
from harness.tokens import TokenIssuer

SIM_CATALOG = Path(__file__).resolve().parent / "report_catalog_sim.yaml"
SYNTHETIC_RE = re.compile(r"^CVE-2099-[0-9]{4,}\Z")       # los CVE del feed de prueba
_ENGAGEMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
SHOWN = ("handoff.imported", "gate.approve", "validation.attempt", "report.generated",
         "report.generation_failed", "hitl.approve_delivery", "hitl.reject_delivery",
         "report.delivery", "report.delivered")


def _err(msg: str) -> int:
    print(bad(msg), file=sys.stderr)
    return 2


def engagement_in_report() -> Engagement:
    """VALIDATE → REPORT. El estado no se persiste en el TP: se recorre la máquina de estados.
    Un kill switch de la bitácora lo aplica `deliver()`, que deja el registro y aborta."""
    engagement = engagement_in_validate()
    engagement.advance()
    return engagement


def check_mode(audit: SqliteAuditLog, eng: str, mode: object) -> None:
    """El loop C corrió en el mismo modo que la entrega: en simulación todas las imágenes son
    la simulada; en el laboratorio, ninguna. Si no, el informe diría validado algo que no se
    ejecutó (o mezclaría la tabla de CVE sintéticos con un informe real)."""
    images = {str(e["target"]) for e in audit.entries
              if e["engagement"] == eng and e["action"] == IMAGE_ACTION}
    sim = {SIM_IMAGE}
    if mode not in ("sim", "lab") or (mode == "sim" and not images <= sim) \
            or (mode == "lab" and images & sim):
        raise HandoffError(f"la bitácora del loop C no corresponde al modo {mode!r} de la "
                           "entrega: no se mezcla simulación con laboratorio")


def asset_graph(state: Path, eng: str, roe: RoE, web_hosts: list[str],
                observed_urls: list[str]) -> tuple[AssetGraph, list[str]]:
    """Activos de la sección 3: los hosts web de la entrega que están en el laboratorio y en
    el RoE, con los puertos que se vieron en las observaciones. Devuelve también los que no
    entran, para mostrarlos."""
    lab, scope = _lab_targets(), _roe_summary(roe)
    graph = AssetGraph.open(eng, state)
    skipped = []
    for host in sorted(set(web_hosts)):
        if not (isinstance(host, str) and _in_lab(host, lab) and _in_roe(host, scope)):
            skipped.append(str(host))
            continue
        graph.add("domain", host, source_tool="handoff", iteration=1)
        for url in observed_urls:
            parts = urlsplit(url)
            if parts.hostname == host and parts.scheme in ("http", "https"):
                port = f":{parts.port}" if parts.port else ""
                graph.add("http_service", f"{parts.scheme}://{host}{port}/",
                          source_tool="handoff", iteration=1)
    return graph, skipped


def feeds_are_synthetic(base: Path = FEEDS_DIR) -> bool:
    """Los CVE-2099-… salen del snapshot sintético de data/feeds/, en simulación y también con
    --lab. Su tabla se suma solo mientras el manifiesto del feed (en el repo, que el runner no
    puede escribir) diga `synthetic: true`. Con el feed real no se lee."""
    try:
        manifest = json.loads((base / MANIFEST_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(manifest, dict) and manifest.get("synthetic") is True


def load_catalog(paths: list[Path], synthetic: Path | None = None) -> ReportCatalog:
    """La tabla del repo y, en simulación, la de los CVE sintéticos, que solo puede traer
    claves `CVE-2099-…` y no pisa ninguna. Con un solo archivo el SHA-256 es el del archivo."""
    files = [*paths, *([synthetic] if synthetic else [])]
    entries: dict[str, object] = {}
    raws = []
    for path in files:
        raw = path.read_bytes()
        raws.append(raw)
        more = (yaml.safe_load(raw) or {}).get("entries") or {}
        if not isinstance(more, dict):
            raise ValueError(f"{path.name}: `entries` no es un mapa")  # noqa: TRY004
        if path == synthetic and (bad_keys := sorted(k for k in more
                                                     if not SYNTHETIC_RE.match(str(k)))):
            raise ValueError(f"{path.name} solo puede traer CVE sintéticos: "
                             f"{', '.join(bad_keys)}")
        if overlap := sorted(set(entries) & set(more)):
            raise ValueError(f"{path.name} repite entradas: {', '.join(overlap)}")
        entries.update(more)
    if len(raws) == 1:
        digest = hashlib.sha256(raws[0]).hexdigest()
    else:
        digest = hashlib.sha256(b"".join(hashlib.sha256(r).digest() for r in raws)).hexdigest()
    return ReportCatalog.from_entries(entries, digest)


def _generated(audit: SqliteAuditLog, eng: str) -> int:
    return sum(1 for e in audit.entries if e["engagement"] == eng and e["phase"] == "control"
               and e["action"] == REPORT_GENERATED_ACTION and e["result"] == Result.OK.value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Informe y entrega (change 007)")
    parser.add_argument("--engagement", required=True)
    parser.add_argument("--state", type=Path, default=STATE,
                        help="estado del host que dejó el loop C (default demo/state)")
    parser.add_argument("--catalog", type=Path, default=REPORT_CATALOG,
                        help="tabla curada del informe (default data/report_catalog.yaml)")
    parser.add_argument("--sim-catalog", type=Path, default=SIM_CATALOG,
                        help="entradas de los CVE sintéticos; solo con el feed sintético "
                             "(default demo/report_catalog_sim.yaml)")
    parser.add_argument("--new-version", action="store_true",
                        help="generar la versión siguiente aunque ya haya una")
    args = parser.parse_args(argv)
    eng, state = args.engagement, args.state
    if not _ENGAGEMENT_RE.match(eng):
        return _err(f"engagement inválido: {eng!r}")
    audit_path = state / f"{eng}.sqlite3"
    if not audit_path.is_file():
        return _err(f"No hay bitácora del host para {eng}: corré antes demo.validation")
    if (error := verify_file(audit_path)) is not None:
        return _err(f"La bitácora del host no está íntegra, no se genera ni entrega nada: {error}")

    audit = SqliteAuditLog.open(eng, state)
    try:
        return _run(args, eng, state, audit)
    finally:
        audit.close()


def _run(args: argparse.Namespace, eng: str, state: Path, audit: SqliteAuditLog) -> int:
    try:
        data = load_imported(state, eng, audit)
        roe = parse_roe(data["roe"])
        candidates, vulns = findings(data)
    except (OSError, HandoffError, RoEError, KeyError, TypeError, ValueError) as exc:
        return _err(f"No se puede usar la entrega importada: {exc}")
    if gate_reviewer(audit, eng) is None:
        return _err(f"Falta el gate {GATE}: el loop C no corrió para {eng}")
    try:
        check_mode(audit, eng, data.get("mode"))
    except HandoffError as exc:
        return _err(f"No se genera el informe: {exc}")

    print(f"Informe y entrega · {eng}")
    if delivered(audit.entries, eng):
        print(ok("   ya entregado (report.delivered en la bitácora)"))
        _show_audit(audit, eng)
        return 0
    engagement = engagement_in_report()
    killswitch = KillSwitch()
    if eng in audit.killed_engagements():
        killswitch.engage(eng)
    issuer = TokenIssuer(audit)
    harness = Harness(Guard(phase_allowlist()), audit, {}, killswitch, issuer,
                      resolver=lambda host: [])              # offline: nadie resuelve nada
    approvals = ApprovalStore.open(eng, state)
    graph: AssetGraph | None = None
    try:
        if killswitch.is_engaged(eng):
            print(bad("   el kill switch está activo en la bitácora: no se genera ni entrega"))
            if _generated(audit, eng):               # deja el ABORTED killswitch y aborta
                _deliver(harness, engagement, roe, issuer, state, approvals, audit, eng)
            _show_audit(audit, eng)
            return 1

        # 1. Generar la versión, una sola vez salvo --new-version.
        if _generated(audit, eng) == 0 or args.new_version:
            synthetic = feeds_are_synthetic()
            paths = [args.catalog, *([args.sim_catalog] if synthetic else [])]
            try:
                catalog = load_catalog([args.catalog], args.sim_catalog if synthetic else None)
            except (OSError, ValueError) as exc:
                return _err(f"No se puede leer la tabla curada: {exc}")
            observed = [str(o.get("url", "")) for o in data.get("observations") or []
                        if isinstance(o, dict)]
            graph, skipped = asset_graph(state, eng, roe, list(data.get("web_hosts") or []),
                                         observed)
            for host in skipped:
                print(warn(f"   {_printable(host)}: fuera del laboratorio o del RoE, no va "
                           "al informe"))
            store = FindingStore.open(eng, state)
            ctx = ReportContext(engagement=engagement, roe=roe, audit=audit, state_dir=state,
                                store=store, catalog=catalog, graph=graph, approvals=approvals)
            try:
                rep = generate_report(ctx, vulns, candidates)
            except MissingField as exc:
                print(bad(f"   no se generó: {_printable(str(exc))}"))
                print(warn("   Falta completar o revisar la tabla curada ("
                           + " y ".join(_shown(p) for p in paths) + "): cada hallazgo "
                           "necesita una entrada con `reviewer` distinto del autor."))
                _show_audit(audit, eng)
                return 1
            except ReportError as exc:
                print(bad(f"   no se generó: {exc.reason}: {_printable(str(exc))}"))
                _show_audit(audit, eng)
                return 1
            finally:
                store.close()
            print(ok(f"   {rep.report_id} generado: {_shown(rep.path)} y "
                     f"{_shown(rep.markdown_path)}"))

        try:
            latest = latest_report(audit.entries, eng, state)
        except DeliveryError as exc:
            # El archivo no coincide con su report.generated. `deliver()` lo registra
            # (PENDING_HITL sin aprobación, o ABORTED evidence_mismatch con ella).
            print(bad(f"   {_printable(str(exc))}"))
            _deliver(harness, engagement, roe, issuer, state, approvals, audit, eng)
            _show_audit(audit, eng)
            return 1
        assert latest is not None
        counts = {"validated": 0, "not_validated": 0}
        for f in latest.doc["findings"]:
            counts[f["validation"]["status"]] += 1
        n = len(latest.doc["findings"])
        print(dim(f"   {latest.report_id} · SHA-256 {latest.short} · {n} hallazgos"
                  f" ({counts['validated']} validados, {counts['not_validated']} sin "
                  f"validar, {len(latest.unvalidated_high)} altos o críticos sin validar)"))

        # 2. Entregar: solo con la aprobación auditada de ESTA versión.
        try:
            result = deliver(DeliveryContext(engagement, roe, harness, issuer, state,
                                             approvals))
        except DeliveryNotApproved:
            print(warn(f"\n   {latest.report_id} espera la aprobación del Reviewer "
                       f"({delivery_status(approvals, audit.entries, eng, latest, time.time())}). "
                       "Mirá el informe y, si está bien:"))
            base = (f"python -m harness.review --engagement {eng} --state-dir {_shown(state)} "
                    f"--audit-dir {_shown(state)} report")
            print(f"     {base} list")
            ack = " --ack-unvalidated-high" if latest.unvalidated_high else ""
            print(f"     {base} approve {latest.report_id} --sha256 {latest.short}{ack} "
                  '--reviewer <tu-usuario> --reason "<por qué>"')
            print(dim("   Después volvé a correr este comando: se entrega solo esa versión."))
            _show_audit(audit, eng)
            return 0
        except (DeliveryError, KillSwitchEngaged) as exc:
            print(bad(f"   no se entregó: {_printable(str(exc)) or type(exc).__name__}"))
            _show_audit(audit, eng)
            return 1
        print(ok(f"\n   entregado ({result.mode}) · estado {engagement.state.value}"))
        print(dim(f"   exportación para DefectDojo: {result.export.split('#')[0]}"))
        print(dim(f"   resumen de la entrega:       {result.receipt.split('#')[0]}"))
        _show_audit(audit, eng)
        return 0
    finally:
        approvals.close_connection()
        if graph is not None:
            graph.close()


def _deliver(harness: Harness, engagement: Engagement, roe: RoE, issuer: TokenIssuer,
             state: Path, approvals: ApprovalStore, audit: SqliteAuditLog, eng: str) -> None:
    """Un intento de entrega que se sabe que no prospera: solo para que quede su registro."""
    try:
        deliver(DeliveryContext(engagement, roe, harness, issuer, state, approvals))
    except (DeliveryNotApproved, DeliveryError, KillSwitchEngaged):
        pass
    else:                                   # no debería pasar: se avisa fuerte
        print(bad("   se entregó una versión que no coincide con la bitácora"))


def _show_audit(audit: SqliteAuditLog, eng: str) -> None:
    print(f"\nBitácora del host ({len(audit.entries)} registros; los del informe y su camino):")
    for e in audit.entries:
        if e["action"] in SHOWN:
            who = f" [{e['subject']}]" if e.get("subject") else ""
            print(dim(f"   {e['action']:<26} {_printable(str(e['agent'])):<22} "
                      f"{e['result']:<12} {e.get('reason') or ''}{who}"))
    error = verify_file(audit.path)
    print(ok("OK: cadena íntegra") if error is None else bad(f"CADENA ROTA: {error}"))


if __name__ == "__main__":
    sys.exit(main())
