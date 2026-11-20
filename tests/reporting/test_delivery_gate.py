"""Change 007 · reporting: entrega con aprobación (D14). Task 2.6, 3.3."""
import ast
from pathlib import Path

import pytest

from harness.delivery import DeliveryNotApproved
from harness.engagement import State
from tests.reporting.helpers import Lab

ROOT = Path(__file__).resolve().parents[2]


def _pending(lab):
    return [(e["result"], e["subject"]) for e in lab.control("report.delivery")]


def _nothing_exported(lab):
    assert not any(n.startswith(("defectdojo-", "delivered-", "export-")) for n in lab.files())
    assert lab.control("report.delivered") == []
    assert lab.engagement.state == State.REPORT


def test_entrega_sin_aprobacion(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    assert _pending(lab) == [("PENDING_HITL", "report-v1")]
    _nothing_exported(lab)


def test_entrega_aprobada_en_modo_offline(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    result = lab.deliver()
    assert result.mode == "offline" and lab.engagement.state == State.DELIVERED
    (done,) = lab.control("report.delivered")
    assert (done["subject"], done["target"], done["evidence"]) == ("report-v1", "offline",
                                                                   result.receipt)


def test_aprobacion_de_una_version_anterior(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.entries["CWE-693"]["remediation"] = "Otra remediación. Con más detalle."
    lab.generate()
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    assert _pending(lab) == [("PENDING_HITL", "report-v2")]
    _nothing_exported(lab)


def test_aprobacion_vencida(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.now += 61 * 60                                 # approval_ttl_minutes = 60
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    _nothing_exported(lab)


def test_aprobacion_insertada_sin_la_cli(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    latest = lab.latest()
    lab.approvals.decide_delivery("report-v1", "approved", "beto", "a mano", lab.now,
                                  latest.sha256, False)     # fila sin control en la bitácora
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    assert _pending(lab) == [("PENDING_HITL", "report-v1")]
    _nothing_exported(lab)


def test_aprobacion_revocada(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    lab.decide_delivery(decision="rejected", reason="falta revisar el alcance")
    with pytest.raises(DeliveryNotApproved):
        lab.deliver()
    _nothing_exported(lab)


def test_informe_cambiado_despues_de_aprobar(tmp_path):
    from harness.delivery import DeliveryError
    lab = Lab(tmp_path)
    lab.finding("f-1")
    rep = lab.generate()
    lab.decide_delivery()
    rep.path.write_bytes(rep.path.read_bytes().replace(b"Falta", b"Sobra"))
    with pytest.raises(DeliveryError) as exc:
        lab.deliver()
    assert exc.value.reason == "evidence_mismatch"
    _nothing_exported(lab)


def test_api_anterior_con_booleano():
    """Ninguna función de entrega de harness/ recibe la aprobación como parámetro."""
    for path in (ROOT / "harness").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) \
                    and "deliver" in node.name:
                for a in (*node.args.args, *node.args.kwonlyargs):
                    assert "approv" not in a.arg, f"{path}:{node.name}({a.arg})"


def test_la_marca_de_entrega_solo_la_usa_la_entrega():
    users = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "harness").rglob("*.py")
                   if "_DELIVERY_GRANT" in p.read_text(encoding="utf-8"))
    assert users == ["harness/delivery.py", "harness/engagement.py"]


def test_aprobacion_de_otro_hash_o_rechazo_no_habilita(tmp_path):
    import dataclasses

    from harness.delivery import current_approval
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    lab.decide_delivery()
    latest = lab.latest()
    entries = lab.audit.entries
    assert current_approval(lab.approvals, entries, lab.eng, latest, lab.now) is not None
    other = dataclasses.replace(latest, sha256="0" * 64)
    assert current_approval(lab.approvals, entries, lab.eng, other, lab.now) is None
    lab.decide_delivery(decision="rejected", reason="no")
    from harness import approvals
    d = approvals.audited_delivery(lab.approvals, lab.audit.entries, lab.eng, "report-v1")
    forged = dataclasses.replace(d, expires_at=lab.now + 3600)   # un rechazo con vencimiento
    assert forged.decision == "rejected"
    from unittest import mock
    with mock.patch("harness.delivery.audited_delivery", return_value=forged):
        assert current_approval(lab.approvals, lab.audit.entries, lab.eng, latest,
                                lab.now) is None
