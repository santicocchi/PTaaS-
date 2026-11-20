"""CLI del Reviewer (change 006, D6). Solo escribe decisiones: no envía tráfico.

    python -m harness.review --engagement <id> --state-dir state list
    python -m harness.review --engagement <id> approve <finding_id> --request <hash> \
        --reviewer <n> --reason "<t>"
    python -m harness.review --engagement <id> reject  <finding_id> --reviewer <n> --reason "<t>"

Entrega del informe (change 007, D14):

    python -m harness.review --engagement <id> report list
    python -m harness.review --engagement <id> report approve <report_id> --sha256 <12 hex> \
        [--ack-unvalidated-high] --reviewer <n> --reason "<t>"
    python -m harness.review --engagement <id> report reject <report_id> --reviewer <n> \
        --reason "<t>"

Solo se aprueba la última versión y con el hash que mostró `report list`; si tiene hallazgos
altos o críticos sin validar, hay que reconocerlo con `--ack-unvalidated-high`. Queda en el
registro (`delivery_decisions`) y en la bitácora (`hitl.approve_delivery` /
`hitl.reject_delivery`, subject = report_id), juntos o ninguno.

`--request` es el hash corto que mostró `list`: si la solicitud en cola cambió, la aprobación
se rechaza. Un `reject` sobre una aprobación vigente la revoca. Cada decisión queda en el
registro de aprobaciones y en la bitácora (`hitl.approve` / `hitl.reject`, objetivo = host
del hallazgo, subject = finding_id). Primero se valida todo; si algo falla, no se
escribe nada. La fila del registro y el control de la bitácora se escriben en una sola
transacción del registro (ver `record_decision`): si la bitácora falla, no queda la fila.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from harness.approvals import ApprovalStore, ReviewError, record_decision
from harness.audit import SqliteAuditLog
from harness.contracts import AuditIntegrityError
from harness.delivery import (
    DeliveryError,
    check_delivery_decision,
    delivery_status,
    latest_report,
    record_delivery_decision,
)

ACTIONS = {"approve": "approved", "reject": "rejected"}


def now() -> float:
    return time.time()


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m harness.review")
    p.add_argument("--engagement", required=True)
    p.add_argument("--state-dir", default="state")
    p.add_argument("--audit-dir", default="audit")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="hallazgos en cola y su estado")
    for name in ACTIONS:
        s = sub.add_parser(name)
        s.add_argument("finding_id")
        if name == "approve":                # el hash que mostró `list`: se aprueba lo que se vio
            s.add_argument("--request", required=True)
        s.add_argument("--reviewer", required=True)
        s.add_argument("--reason", required=True)
    report = sub.add_parser("report", help="entrega del informe (007)")
    rsub = report.add_subparsers(dest="report_command", required=True)
    rsub.add_parser("list", help="última versión del informe y su estado de entrega")
    for name in ACTIONS:
        s = rsub.add_parser(name)
        s.add_argument("report_id")
        if name == "approve":
            s.add_argument("--sha256", required=True, help="el hash corto que mostró list")
            s.add_argument("--ack-unvalidated-high", action="store_true")
        s.add_argument("--reviewer", required=True)
        s.add_argument("--reason", required=True)
    return p


def _list(store: ApprovalStore, at: float) -> int:
    print("finding_id\tcwe\thost\tpriority\tpoc_id\tparams\trequest\tstatus")
    for item in store.queue():
        params = ",".join(f"{k}={v}" for k, v in sorted(item.params.items())) or "-"
        priority = "-" if item.priority is None else f"{item.priority:g}"
        print(f"{item.finding_id}\t{item.cwe}\t{item.host}\t{priority}\t"
              f"{item.poc_id or '-'}\t{params}\t{item.request_hash}\t"
              f"{store.status(item.finding_id, at)}")
    return 0


_BROKEN_CHAIN = "error: la cadena de la bitácora no verifica; no se lee ni se decide nada"


def _report(args: argparse.Namespace, store: ApprovalStore, at: float) -> int:
    state_dir = Path(args.state_dir)
    if not (Path(args.audit_dir) / f"{args.engagement}.sqlite3").is_file():
        print("error: no hay bitácora para ese engagement", file=sys.stderr)
        return 1
    try:
        audit = SqliteAuditLog.open(args.engagement, args.audit_dir)   # verifica la cadena
    except AuditIntegrityError:
        print(_BROKEN_CHAIN, file=sys.stderr)
        return 1
    try:
        try:
            audit.verify_integrity()
        except AuditIntegrityError:
            print(_BROKEN_CHAIN, file=sys.stderr)
            return 1
        if args.report_command == "list":
            try:
                latest = latest_report(audit.entries, args.engagement, state_dir)
            except DeliveryError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if latest is None:
                print("no hay ningún informe generado")
                return 0
            counts = {s: {"validated": 0, "not_validated": 0}
                      for s in ("Critical", "High", "Medium", "Low", "None")}
            for f in latest.doc["findings"]:
                counts[f["severity"]][f["validation"]["status"]] += 1
            print("report_id	sha256	status")
            print(f"{latest.report_id}	{latest.short}	"
                  f"{delivery_status(store, audit.entries, args.engagement, latest, at)}")
            for sev, n in counts.items():
                print(f"  {sev}: {n['validated']} validados, {n['not_validated']} no validados")
            print(f"  altos o críticos sin validar: {len(latest.unvalidated_high)}"
                  + (" (aprobar exige --ack-unvalidated-high)" if latest.unvalidated_high
                     else ""))
            for fp in latest.unvalidated_high:
                print(f"    {fp}")
            return 0
        decision = ACTIONS[args.report_command]
        sha = getattr(args, "sha256", None)
        ack = bool(getattr(args, "ack_unvalidated_high", False))
        try:
            check_delivery_decision(audit.entries, args.engagement, state_dir, args.report_id,
                                    decision, args.reviewer, args.reason, sha, ack)
        except ReviewError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        try:
            record_delivery_decision(store, audit, args.engagement, state_dir, args.report_id,
                                     decision, args.reviewer, args.reason, at, sha, ack)
        except ReviewError as exc:          # cambió entre la validación y la transacción
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001 - se informa fuerte: registro y bitácora
            print(f"ERROR: la decisión NO quedó registrada ({type(exc).__name__}). "
                  "Revisá la bitácora antes de reintentar.", file=sys.stderr)
            return 3
        print(f"{args.report_id}: {decision} por {args.reviewer}")
        return 0
    finally:
        audit.close()


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        store = ApprovalStore.open(args.engagement, args.state_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    at = now()
    if args.command == "report":
        return _report(args, store, at)
    if args.command == "list":
        return _list(store, at)
    decision = ACTIONS[args.command]
    try:
        store.check_decision(args.finding_id, decision, args.reviewer, args.reason, at,
                             getattr(args, "request", None))
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    audit = SqliteAuditLog.open(args.engagement, args.audit_dir)
    try:
        record_decision(store, audit, args.engagement, args.finding_id, decision,
                        args.reviewer, args.reason, at, getattr(args, "request", None))
    except ReviewError as exc:              # cambió entre la validación y la transacción
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - se informa fuerte: registro y bitácora
        print(f"ERROR: la decisión NO quedó registrada ({type(exc).__name__}: {exc}). "
              "Revisá la bitácora antes de reintentar.", file=sys.stderr)
        return 3
    finally:
        audit.close()
    print(f"{args.finding_id}: {decision} por {args.reviewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
