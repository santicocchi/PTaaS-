"""Change 007 · reporting: CLI de aprobación del informe (D14). Task 2.6."""
import pytest

from harness import review
from tests.reporting.helpers import Lab


def _cli(lab, *args):
    return review.main(["--engagement", lab.eng, "--state-dir", str(lab.state_dir),
                        "--audit-dir", str(lab.audit_dir), "report", *args])


@pytest.fixture
def high(tmp_path):
    """report-v1 con un hallazgo High sin validar."""
    lab = Lab(tmp_path)
    lab.finding("f-1", cwe="CWE-22", priority=9.0)
    lab.closed("f-1", "no_catalog_entry")
    lab.generate()
    lab.audit.close()                     # la CLI abre su propia conexión
    return lab


def _nothing_written(lab):
    from harness.audit import SqliteAuditLog
    log = SqliteAuditLog.open(lab.eng, lab.audit_dir)
    try:
        assert not [e for e in log.entries if e["action"].startswith("hitl.")]
    finally:
        log.close()
    assert lab.approvals.delivery_decisions("report-v1") == []


def _approve(lab, *extra, sha=None):
    return _cli(lab, "approve", "report-v1", "--sha256", sha or lab.latest().short,
                "--reviewer", "beto", "--reason", "revisado", *extra)


def test_list_muestra_hash_conteos_y_altos(high, capsys):
    assert _cli(high, "list") == 0
    out = capsys.readouterr().out
    assert f"report-v1\t{high.latest().short}\tpending" in out
    assert "High: 0 validados, 1 no validados" in out
    assert "--ack-unvalidated-high" in out


def test_aprobar_sin_reconocer_altos_no_validados(high, capsys):
    assert _approve(high) == 1
    assert "--ack-unvalidated-high" in capsys.readouterr().err
    _nothing_written(high)


def test_aprobar_con_reconocimiento(high):
    assert _approve(high, "--ack-unvalidated-high") == 0
    (row,) = high.approvals.delivery_decisions("report-v1")
    assert row.ack_unvalidated_high is True and row.decision == "approved"
    (ctrl,) = [e for e in high.audit.entries if e["action"] == "hitl.approve_delivery"]
    assert (ctrl["subject"], ctrl["agent"]) == ("report-v1", "reviewer:beto")


def test_aprobar_con_otro_hash(high, capsys):
    assert _approve(high, "--ack-unvalidated-high", sha="0" * 12) == 1
    assert "sha256" in capsys.readouterr().err
    _nothing_written(high)


def test_aprobar_una_version_que_no_es_la_ultima(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("f-1")
    lab.generate()
    v1 = lab.latest().short
    lab.entries["CWE-693"]["remediation"] = "Otra remediación. Con más detalle."
    lab.generate()
    lab.audit.close()
    assert _approve(lab, sha=v1) == 1
    _nothing_written(lab)


def test_aprobar_sin_motivo(high):
    assert _cli(high, "approve", "report-v1", "--sha256", high.latest().short,
                "--ack-unvalidated-high", "--reviewer", "beto", "--reason", "  ") == 1
    _nothing_written(high)


def test_rechazar_revoca(high):
    assert _approve(high, "--ack-unvalidated-high") == 0
    assert _cli(high, "reject", "report-v1", "--reviewer", "beto",
                "--reason", "falta el alcance") == 0
    assert [d.decision for d in high.approvals.delivery_decisions("report-v1")] == [
        "approved", "rejected"]


def test_la_bitacora_falla(high, monkeypatch, capsys):
    from harness.audit import SqliteAuditLog

    def broken(self, *a, **k):
        raise OSError("disco lleno")
    monkeypatch.setattr(SqliteAuditLog, "record_control", broken)
    assert _approve(high, "--ack-unvalidated-high") == 3
    assert "NO quedó registrada" in capsys.readouterr().err
    monkeypatch.undo()
    _nothing_written(high)
