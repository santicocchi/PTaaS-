"""Demo del loop C (change 006) en simulación: pipeline → gate → cola del Reviewer → sandbox.

Se recorre el camino de la demo como lo haría el equipo:
1. el pipeline deja la entrega en la bandeja (`demo/out`);
2. la primera corrida la importa al estado del host, abre VALIDATE con el gate del Reviewer y
   deja los hallazgos en PENDING_HITL sin enviar nada;
3. el Reviewer aprueba UNO con `python -m harness.review`;
4. la segunda corrida envía solo ese.

El docker es el simulado de la demo: no se ejecuta nada. Los casos negativos son los de la
revisión de seguridad: la bandeja la puede escribir el runner, el estado del host no.
"""
import hashlib
import json
import shutil
import sqlite3
from datetime import datetime

import pytest

from demo import pipeline, validation
from harness import review
from harness.audit import SqliteAuditLog, verify_file
from harness.contracts import Result
from harness.evidence import verify_evidence
from harness.roe import roe_digest
from harness.validation import CAPABILITY


@pytest.fixture
def lab(tmp_path, capsys):
    """Pipeline en simulación. Devuelve (bandeja, estado del host, engagement_id)."""
    inbox, state = tmp_path / "out", tmp_path / "state"
    assert pipeline.main(["--out", str(inbox)]) == 0
    out = capsys.readouterr().out
    assert "--approve-phase --reviewer <tu-usuario>" in out
    (handoff,) = inbox.glob("demo-pipeline-*.handoff.json")
    validation.SimDocker.runs.clear()
    return inbox, state, handoff.name.split(".", 1)[0]


def run(inbox, state, eng, *extra):
    return validation.main(["--engagement", eng, "--inbox", str(inbox), "--state", str(state),
                            *extra])


def first_run(inbox, state, eng):
    return run(inbox, state, eng, "--approve-phase", "--reviewer", "ana@lab")


def rows(base, eng):
    with sqlite3.connect(base / f"{eng}.sqlite3") as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM audit ORDER BY rowid")]


def queue(capsys, base, eng):
    """La cola como la ve el Reviewer: `list` de la CLI."""
    capsys.readouterr()
    assert review.main(["--engagement", eng, "--state-dir", str(base), "--audit-dir",
                        str(base), "list"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    head = lines[0].split("\t")
    return {r[0]: dict(zip(head, r, strict=True)) for r in (ln.split("\t") for ln in lines[1:])}


def approve(base, eng, item):
    return review.main(["--engagement", eng, "--state-dir", str(base), "--audit-dir", str(base),
                        "approve", item["finding_id"], "--request", item["request"],
                        "--reviewer", "ana@lab", "--reason", "demo"])


def status(text, fid):
    """Estado de un hallazgo en la tabla que imprime la demo."""
    (line,) = [ln for ln in text.splitlines() if ln.split()[:1] == [fid]]
    return line.split()[1]


def sent(state, eng):
    return [r for r in rows(state, eng) if r["action"] == CAPABILITY and r["result"] == "OK"]


def by_cwe(q, cwe):
    return next(i for i in q.values() if i["cwe"] == cwe)


def now():
    return datetime.now().astimezone()


def forge_handoff(inbox, eng, change):
    """Lo que puede hacer alguien con el runner: editar la entrega, recalcular el hash del RoE
    y agregar a la bitácora (que también escribe) un `handoff.written` coherente."""
    path = inbox / f"{eng}.handoff.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    data["roe"]["approval"]["roe_sha256"] = roe_digest(data["roe"])
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    audit = SqliteAuditLog.open(eng, inbox)
    audit.record_control(eng, "orchestrator", pipeline.HANDOFF_ACTION, path.name, Result.OK,
                         evidence=f"{path.name}#sha256={hashlib.sha256(raw).hexdigest()}")
    audit.close()
    assert verify_file(inbox / f"{eng}.sqlite3") is None       # la cadena sigue "íntegra"


# --- camino feliz ---------------------------------------------------------------------------
def test_sin_aprobacion_no_se_envia_nada(lab, capsys):
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    text = capsys.readouterr().out
    assert "pending_hitl" in text and "no_catalog_entry" in text
    assert f"python -m harness.review --engagement {eng} --state-dir {state}" in text
    assert validation.SimDocker.runs == [] and sent(state, eng) == []
    pending = [r for r in rows(state, eng) if r["result"] == "PENDING_HITL"]
    assert pending and all(r["phase"] == "validate" and r["subject"] for r in pending)
    (gate,) = [r for r in rows(state, eng) if r["action"] == "gate.approve"]
    assert (gate["target"], gate["agent"]) == ("before_validate", "reviewer:ana@lab")
    assert verify_file(state / f"{eng}.sqlite3") is None


def test_aprobado_por_la_cli_se_valida_solo_ese(lab, capsys):
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    q = queue(capsys, state, eng)
    csp, hdr = by_cwe(q, "CWE-693"), by_cwe(q, "CWE-1021")
    assert (csp["poc_id"], csp["status"]) == ("POC-CSP-001", "pending")
    assert approve(state, eng, csp) == 0

    assert run(inbox, state, eng) == 0
    text = capsys.readouterr().out
    assert "OK: cadena íntegra" in text
    assert status(text, csp["finding_id"]) == "validated"
    assert status(text, hdr["finding_id"]) == "pending_hitl"
    (req,) = validation.SimDocker.runs                 # un envío: positivo al primer intento
    assert (req["ip"], req["host"], req["path"]) == ("10.99.0.10", "dvwa.lab.test", "/")
    (ok,) = sent(state, eng)
    assert (ok["subject"], ok["target"]) == (csp["finding_id"], "dvwa.lab.test")
    attempts = [r for r in rows(state, eng) if r["action"] == "validation.attempt"]
    assert [a["subject"] for a in attempts] == [csp["finding_id"]]
    assert verify_evidence(state, attempts[0]["evidence"])
    assert verify_file(state / f"{eng}.sqlite3") is None


# --- gate before_validate -------------------------------------------------------------------
def test_sin_gate_before_validate_no_corre(lab, capsys):
    inbox, state, eng = lab
    assert run(inbox, state, eng) == 0
    assert "Falta el gate before_validate" in capsys.readouterr().out
    assert [r["action"] for r in rows(state, eng)] == ["handoff.imported"]
    assert not (state / f"{eng}.approvals.sqlite3").exists()


def test_gate_sin_reviewer(lab, capsys):
    inbox, state, eng = lab
    assert run(inbox, state, eng, "--approve-phase") == 2
    assert run(inbox, state, eng, "--approve-phase", "--reviewer", "a b") == 2
    assert not state.exists()


# --- la bandeja la escribe el runner: no se le cree -----------------------------------------
def test_aprobacion_escrita_en_la_bandeja_no_cuenta(lab, capsys):
    """Revisión B2: desde el runner se puede correr la CLI sobre demo/out. No habilita nada."""
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    csp = by_cwe(queue(capsys, state, eng), "CWE-693")
    shutil.copy(state / f"{eng}.approvals.sqlite3", inbox / f"{eng}.approvals.sqlite3")
    assert approve(inbox, eng, csp) == 0                # aprobada... en la bandeja
    assert run(inbox, state, eng) == 0
    assert status(capsys.readouterr().out, csp["finding_id"]) == "pending_hitl"
    assert validation.SimDocker.runs == [] and sent(state, eng) == []


def test_entrega_modificada_no_se_importa(lab, capsys):
    inbox, state, eng = lab
    path = inbox / f"{eng}.handoff.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["vulns"] = []
    path.write_text(json.dumps(data), encoding="utf-8")
    n = len(rows(inbox, eng))
    assert first_run(inbox, state, eng) == 2
    assert "no coincide con la bitácora" in capsys.readouterr().err
    assert len(rows(inbox, eng)) == n
    assert [r["action"] for r in rows(state, eng)] == ["handoff.rejected"]


def test_exclusion_quitada_con_hash_recalculado(lab, capsys):
    """Revisión B1: se saca juiceshop de las exclusiones y se rehace todo lo que tiene hash."""
    inbox, state, eng = lab
    forge_handoff(inbox, eng, lambda d: d["roe"].update(exclusions={"hosts": []}))
    assert first_run(inbox, state, eng) == 2
    assert "una sola entrega" in capsys.readouterr().err
    assert validation.SimDocker.runs == []


def test_rol_contra_la_plantilla(lab):
    """Aunque la bitácora tuviera un solo registro coherente, el RoE se compara con la plantilla
    del repo, que el runner no puede escribir."""
    inbox, _, eng = lab
    roe = json.loads((inbox / f"{eng}.handoff.json").read_text(encoding="utf-8"))["roe"]
    validation.check_roe(roe, eng, now())
    for change, match in [
        (lambda r: r.update(exclusions={"hosts": []}), "roe-pipeline.yaml"),
        (lambda r: r["scope"]["cidrs"].append("10.99.1.0/24"), "roe-pipeline.yaml"),
        (lambda r: r["approval"].update(approver="otro@lab"), "roe-pipeline.yaml"),
        (lambda r: r["window"].update(end="2099-01-01T00:00:00+00:00"), "ventana"),
        (lambda r: r["window"].update(start="ayer"), "ventana"),
        (lambda r: r.update(engagement_id="otro"), "otro engagement"),
    ]:
        bad = json.loads(json.dumps(roe))
        change(bad)
        with pytest.raises(validation.HandoffError, match=match):
            validation.check_roe(bad, eng, now())


def test_entrega_de_simulacion_con_lab(lab, capsys, monkeypatch):
    """Revisión M2: lo ensayado con salidas grabadas no se valida contra el laboratorio."""
    inbox, state, eng = lab
    monkeypatch.setattr(validation, "default_docker_runner", validation.SimDocker())
    monkeypatch.setattr(validation, "lab_network_ok", lambda r: True)
    monkeypatch.setattr(validation, "sandbox_image", lambda r: validation.SIM_IMAGE)
    assert run(inbox, state, eng, "--lab", "--approve-phase", "--reviewer", "ana@lab") == 2
    assert "no se mezcla" in capsys.readouterr().err
    assert validation.SimDocker.runs == []


def test_entrega_importada_modificada_en_el_host(lab, capsys):
    inbox, state, eng = lab
    assert first_run(inbox, state, eng) == 0
    path = state / f"{eng}.handoff.json"
    path.write_bytes(path.read_bytes().replace(b"dvwa.lab.test", b"dvwa.lab.tesx"))
    assert run(inbox, state, eng) == 2
    assert "no coincide con la bitácora del host" in capsys.readouterr().err


def test_engagement_sin_entrega(tmp_path, capsys):
    assert run(tmp_path / "out", tmp_path / "state", "demo-pipeline-x",
               "--approve-phase", "--reviewer", "ana") == 2
    assert "python -m demo.pipeline" in capsys.readouterr().err


@pytest.mark.parametrize("eng", ["../x", "Demo", "a" * 64, ""])
def test_engagement_invalido(tmp_path, eng):
    assert run(tmp_path / "out", tmp_path / "state", eng) == 2
    assert not (tmp_path / "state").exists()


def test_bitacora_de_la_bandeja_rota(lab, capsys):
    inbox, state, eng = lab
    with sqlite3.connect(inbox / f"{eng}.sqlite3") as con:
        con.execute("DROP TRIGGER IF EXISTS audit_no_update")
        con.execute("UPDATE audit SET target = 'otro' WHERE rowid = 1")
    assert first_run(inbox, state, eng) == 2
    assert "bitácora" in capsys.readouterr().err
    assert validation.SimDocker.runs == []


# --- laboratorio: docker y red --------------------------------------------------------------
class Docker:
    def __init__(self, nets=None, internal="true", ipam='[{"Subnet":"10.99.0.0/24"}]',
                 image="sha256:" + "a" * 64):
        self.nets, self.internal, self.ipam, self.image = nets or {}, internal, ipam, image

    def __call__(self, argv, stdin, timeout_s):
        if argv[:3] == ["docker", "network", "inspect"]:
            if ".IPAM" in argv[4]:
                return 0, f"{self.internal} {self.ipam}\n"
            return 0, " ".join(self.nets) + " "
        if argv[:2] == ["docker", "inspect"]:
            info = self.nets.get(argv[-1])
            return (0, info) if info is not None else (1, "")
        if argv[:3] == ["docker", "image", "inspect"]:
            return (0, self.image + "\n") if self.image else (1, "")
        raise AssertionError(argv)


def _net(ip, *aliases):
    return json.dumps({"IPAddress": ip, "Aliases": list(aliases)})


def test_lab_resolver_alias_del_laboratorio():
    nets = {"a" * 64: _net("10.99.0.4", "dvwa", "dvwa.lab.test"),
            "b" * 64: _net("10.99.0.3", "juiceshop.lab.test"),
            "c" * 64: _net("10.97.0.10", "runner.lab.test"),        # fuera de 10.99.0.0/24
            "d" * 64: "no es json",
            "e" * 64: "null",
            "--format": _net("10.99.0.9", "inyectado.lab.test")}     # id que no es id
    resolve = validation.lab_resolver(Docker(nets))
    assert resolve("dvwa.lab.test") == ["10.99.0.4"]
    assert resolve("juiceshop.lab.test") == ["10.99.0.3"]
    assert resolve("dvwa") == []                       # solo nombres .lab.test
    assert resolve("runner.lab.test") == [] and resolve("inyectado.lab.test") == []


@pytest.mark.parametrize("internal,ipam,expected", [
    ("true", '[{"Subnet":"10.99.0.0/24"}]', True),
    ("false", '[{"Subnet":"10.99.0.0/24"}]', False),
    ("true", '[{"Subnet":"10.0.0.0/8"}]', False),
    ("true", '[{"Subnet":"10.99.0.0/24"},{"Subnet":"fd00::/64"}]', False),
    ("true", "[]", False),
    ("true", "roto", False),
])
def test_red_del_laboratorio(internal, ipam, expected):
    assert validation.lab_network_ok(Docker(internal=internal, ipam=ipam)) is expected


def test_lab_sin_docker(lab, capsys, monkeypatch):
    inbox, state, eng = lab
    monkeypatch.setattr(validation, "default_docker_runner", lambda argv, stdin, t: (127, ""))
    assert run(inbox, state, eng, "--lab") == 2
    assert "lab_lab" in capsys.readouterr().err


def test_lab_sin_imagen(lab, capsys, monkeypatch):
    inbox, state, eng = lab
    monkeypatch.setattr(validation, "default_docker_runner", Docker(image=""))
    assert run(inbox, state, eng, "--lab") == 2
    assert "--profile build build sandbox" in capsys.readouterr().err


def test_texto_del_objetivo_no_controla_la_pantalla():
    assert validation._printable("/a\x1b[2J\x07") == "/a\\x1b[2J\\x07"


def test_sim_docker_exige_las_opciones_del_contenedor():
    with pytest.raises(AssertionError):
        validation.SimDocker()(["docker", "run", "--network", "bridge", validation.SIM_IMAGE],
                               "{}", 5)
