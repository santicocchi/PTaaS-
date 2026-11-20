"""Demo del change 007 en simulación: pipeline → loop C → informe → aprobación → entrega.

Recorre el camino completo como lo haría el equipo. Las aprobaciones las da la CLI
(`harness.review`) con un Reviewer de prueba, igual que en tests/demo/test_validation.py: la
demo nunca aprueba sola.
"""
import json
import socket

import pytest
import yaml

from demo import report
from harness import review
from harness.contracts import Result
from harness.report_catalog import REPORT_CATALOG
from tests.demo.test_validation import approve, first_run, lab, queue, run  # noqa: F401


@pytest.fixture
def validated(lab, capsys):  # noqa: F811
    """Loop C con un hallazgo aprobado y validado. Devuelve (estado, engagement)."""
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    q = queue(capsys, state, eng)
    assert approve(state, eng, next(iter(q.values()))) == 0
    assert run(inbox, state, eng) == 0
    capsys.readouterr()
    return state, eng


def _reviewed(src, dst):
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    for entry in data["entries"].values():
        entry["reviewer"] = "revisor-de-prueba"
    dst.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return dst


@pytest.fixture
def catalog(tmp_path):
    """Las dos tablas con las entradas revisadas (en el repo esperan al Reviewer)."""
    return (_reviewed(REPORT_CATALOG, tmp_path / "report_catalog.yaml"),
            _reviewed(report.SIM_CATALOG, tmp_path / "report_catalog_sim.yaml"))


def demo(state, eng, catalog=None, *extra):
    args = ["--engagement", eng, "--state", str(state), *extra]
    if catalog:
        args += ["--catalog", str(catalog[0]), "--sim-catalog", str(catalog[1])]
    return report.main(args)


def cli(state, eng, *args):
    return review.main(["--engagement", eng, "--state-dir", str(state), "--audit-dir",
                        str(state), "report", *args])


def controls(state, eng, action):
    from harness.audit import SqliteAuditLog
    log = SqliteAuditLog.open(eng, state)
    try:
        return [e for e in log.entries if e["action"] == action]
    finally:
        log.close()


def approve_cmd(out):
    (line,) = [ln for ln in out.splitlines() if " report approve " in ln]
    words = line.split()
    return words[words.index("approve") + 1], words[words.index("--sha256") + 1], \
        "--ack-unvalidated-high" in words


def test_de_punta_a_punta(validated, catalog, capsys, monkeypatch):
    state, eng = validated
    assert demo(state, eng, catalog) == 0
    out = capsys.readouterr().out
    assert "report-v1 generado" in out and "espera la aprobación del Reviewer" in out
    assert [e["result"] for e in controls(state, eng, "report.delivery")] == ["PENDING_HITL"]
    rid, sha, ack = approve_cmd(out)
    assert rid == "report-v1"

    assert cli(state, eng, "approve", rid, "--sha256", sha, *(["--ack-unvalidated-high"]
               if ack else []), "--reviewer", "ana@lab", "--reason", "revisado") == 0

    def no_network(*a, **k):
        raise AssertionError("la entrega offline no abre conexiones")
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert demo(state, eng, catalog) == 0
    out = capsys.readouterr().out
    assert "entregado (offline) · estado DELIVERED" in out and "OK: cadena íntegra" in out
    (done,) = controls(state, eng, "report.delivered")
    assert done["subject"] == "report-v1"
    exported = json.loads((state / "reports" / eng / "defectdojo-report-v1.json").read_bytes())
    assert exported["findings"]
    assert [e["subject"] for e in controls(state, eng, "report.generated")] == ["report-v1"]

    assert demo(state, eng, catalog) == 0                   # otra vez: no entrega de nuevo
    assert "ya entregado" in capsys.readouterr().out
    assert len(controls(state, eng, "report.delivered")) == 1


def test_volver_a_correr_no_cambia_la_version(validated, catalog, capsys):
    state, eng = validated
    assert demo(state, eng, catalog) == 0
    assert demo(state, eng, catalog) == 0
    assert [e["subject"] for e in controls(state, eng, "report.generated")] == ["report-v1"]
    assert demo(state, eng, catalog, "--new-version") == 0
    out = capsys.readouterr().out
    assert approve_cmd(out.split("report-v2 generado", 1)[1])[0] == "report-v2"


def test_aprobar_v1_y_generar_v2_no_entrega(validated, catalog, capsys):
    state, eng = validated
    assert demo(state, eng, catalog) == 0
    rid, sha, _ack = approve_cmd(capsys.readouterr().out)
    assert cli(state, eng, "approve", rid, "--sha256", sha, "--ack-unvalidated-high",
               "--reviewer", "ana@lab", "--reason", "ok") == 0
    assert demo(state, eng, catalog, "--new-version") == 0
    assert "report-v2 espera la aprobación" in capsys.readouterr().out
    assert controls(state, eng, "report.delivered") == []


def test_tabla_curada_sin_revisar(validated, catalog, capsys):
    """Con entradas en `reviewer: pendiente` no se genera nada y se dice qué falta."""
    state, eng = validated
    for path in catalog:
        path.write_text(path.read_text().replace("revisor-de-prueba", "pendiente"))
    assert demo(state, eng, catalog) == 1
    out = capsys.readouterr().out
    assert "no se generó" in out and "reviewer" in out
    assert controls(state, eng, "report.generated") == []
    assert not (state / "reports" / eng).exists() or \
        not list((state / "reports" / eng).glob("report-v*"))


def test_sin_loop_c(lab, catalog, capsys):  # noqa: F811
    _inbox, state, eng = lab
    assert demo(state, eng, catalog) == 2
    assert "demo.validation" in capsys.readouterr().err


def test_bitacora_del_host_rota(validated, catalog, capsys):
    import sqlite3
    state, eng = validated
    con = sqlite3.connect(state / f"{eng}.sqlite3")
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        con.execute(f'DROP TRIGGER "{name}"')
    con.execute("UPDATE audit SET target='otro' WHERE seq=1")
    con.commit()
    con.close()
    assert demo(state, eng, catalog) == 2
    assert "no está íntegra" in capsys.readouterr().err


@pytest.mark.parametrize("eng", ["../x", "A", ""])
def test_engagement_invalido(tmp_path, eng):
    assert report.main(["--engagement", eng, "--state", str(tmp_path)]) == 2


def test_tabla_de_simulacion_no_pisa_la_del_repo(tmp_path):
    dup = tmp_path / "dup.yaml"
    dup.write_text("entries:\n  CWE-693: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="repite entradas: CWE-693"):
        report.load_catalog([REPORT_CATALOG, dup])
    with pytest.raises(ValueError, match="solo puede traer CVE sintéticos: CWE-693"):
        report.load_catalog([tmp_path / "vacia.yaml"], synthetic=dup) if \
            (tmp_path / "vacia.yaml").write_text("entries: {}\n") else None


def test_las_entradas_sinteticas_solo_en_simulacion():
    repo = report.load_catalog([REPORT_CATALOG])
    both = report.load_catalog([REPORT_CATALOG], synthetic=report.SIM_CATALOG)
    assert not any(k.startswith("CVE-2099-") for k in repo.raw)
    assert {"CVE-2099-0001", "CVE-2099-0002"} <= set(both.raw)
    import hashlib
    assert repo.sha256 == hashlib.sha256(REPORT_CATALOG.read_bytes()).hexdigest()
    assert repo.sha256 != both.sha256
    assert all(k.startswith("CVE-2099-") for k in set(both.raw) - set(repo.raw))


# ---- revisión de seguridad del PR 3 ----------------------------------------------------------

def _audit(state, eng):
    from harness.audit import SqliteAuditLog
    return SqliteAuditLog.open(eng, state)


def test_loop_c_de_otro_modo_no_se_informa(validated, catalog, capsys):
    """Una entrega de simulación cuyo loop C dice haber corrido una imagen real (o al revés)."""
    state, eng = validated
    log = _audit(state, eng)
    log.record_control(eng, "validation-demo", "sandbox.image", "sha256:" + "a" * 64, Result.OK)
    log.close()
    assert demo(state, eng, catalog) == 2
    assert "no se mezcla simulación con laboratorio" in capsys.readouterr().err
    assert controls(state, eng, "report.generated") == []


def test_validacion_en_otro_modo_despues_de_importar(lab, capsys, monkeypatch):  # noqa: F811
    from demo import validation
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    monkeypatch.setattr(validation, "lab_network_ok", lambda runner: True)
    monkeypatch.setattr(validation, "sandbox_image", lambda runner: "sha256:" + "a" * 64)
    assert run(inbox, state, eng, "--lab") == 2
    assert "no se mezcla simulación con laboratorio" in capsys.readouterr().err


def test_host_fuera_del_alcance_no_va_al_informe(validated, catalog, capsys, monkeypatch):
    """Una entrega (que escribe el runner) con hosts de más en `web_hosts`."""
    state, eng = validated
    real = report.load_imported

    def load(state_, eng_, audit_):
        data = real(state_, eng_, audit_)
        data["web_hosts"] += ["juiceshop.lab.test", "app.example.com"]
        return data
    monkeypatch.setattr(report, "load_imported", load)
    assert demo(state, eng, catalog) == 0
    out = capsys.readouterr().out
    assert "juiceshop.lab.test: fuera del laboratorio o del RoE" in out
    assert "app.example.com: fuera del laboratorio o del RoE" in out
    text = (state / "reports" / eng / "report-v1.md").read_text()
    assert "`juiceshop.lab.test`:" not in text and "app.example.com" not in text
    assert "`dvwa.lab.test`: puertos 80" in text


def test_kill_switch_en_la_bitacora(validated, catalog, capsys):
    state, eng = validated
    assert demo(state, eng, catalog) == 0
    log = _audit(state, eng)
    log.record_kill(eng, "operador")
    log.close()
    capsys.readouterr()
    assert demo(state, eng, catalog) == 1
    assert "kill switch" in capsys.readouterr().out
    aborted = [(e["result"], e.get("reason")) for e in controls(state, eng, "report.delivery")]
    assert aborted[-1] == ("ABORTED", "killswitch")
    assert controls(state, eng, "report.delivered") == []


def test_informe_alterado_despues_de_aprobar(validated, catalog, capsys):
    state, eng = validated
    assert demo(state, eng, catalog) == 0
    rid, sha, _ack = approve_cmd(capsys.readouterr().out)
    assert cli(state, eng, "approve", rid, "--sha256", sha, "--ack-unvalidated-high",
               "--reviewer", "ana@lab", "--reason", "ok") == 0
    md = state / "reports" / eng / "report-v1.json"
    md.write_bytes(md.read_bytes().replace(b"Actualizar", b"Ignorar"))
    assert demo(state, eng, catalog) == 1
    aborted = [(e["result"], e.get("reason")) for e in controls(state, eng, "report.delivery")]
    assert aborted[-1] == ("ABORTED", "evidence_mismatch")
    assert controls(state, eng, "report.delivered") == []


# ---- los CVE sintéticos vienen del feed, no del modo (corrida en el lab del 20/11) -----------

@pytest.mark.parametrize("manifest,expected", [
    ('{"synthetic": true, "files": {}}', True),
    ('{"synthetic": false, "files": {}}', False),
    ('{"files": {}}', False),
    ('{"synthetic": "true"}', False),
    ("no es json", False),
])
def test_tabla_sintetica_segun_el_feed(tmp_path, manifest, expected):
    (tmp_path / "manifest.json").write_text(manifest, encoding="utf-8")
    assert report.feeds_are_synthetic(tmp_path) is expected


def test_sin_manifiesto_no_hay_tabla_sintetica(tmp_path):
    assert report.feeds_are_synthetic(tmp_path) is False


def test_el_feed_del_repo_es_sintetico_hoy():
    """Si se sube el feed real, este test avisa que la tabla sintética deja de leerse."""
    assert report.feeds_are_synthetic() is True


def test_con_feed_real_no_se_suman_los_cve_sinteticos(validated, catalog, capsys, monkeypatch):
    state, eng = validated
    monkeypatch.setattr(report, "feeds_are_synthetic", lambda: False)
    assert demo(state, eng, catalog) == 1
    out = capsys.readouterr().out
    assert "no se generó" in out and "report_catalog_sim" not in out
    assert controls(state, eng, "report.generated") == []
