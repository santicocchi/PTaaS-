"""Change 010 · tasks 2.6 y 2.7: demos con la RoE del integrador y procedencia del target."""
import hashlib
import json
import sqlite3
from datetime import datetime

import pytest

from demo import pipeline, validation
from demo.checkpoint1 import prepare_roe
from harness.audit import SqliteAuditLog
from harness.contracts import Result
from harness.roe import roe_digest


def now():
    return datetime.now().astimezone()


def integrador_roe(eng="demo-integrador-1"):
    return json.loads(json.dumps(prepare_roe(eng, now(), pipeline.ROE_TEMPLATES["integrador"])))


# --- 2.6: la entrega acepta solo plantillas del repo ----------------------------------------

def test_entrega_con_la_roe_del_integrador_se_acepta():
    validation.check_roe(integrador_roe(), "demo-integrador-1", now())


@pytest.mark.parametrize("change", [
    lambda r: r["exclusions"].update(hosts=["juiceshop.lab.test", "10.99.0.11"]),
    lambda r: r["scope"].update(cidrs=["10.99.0.0/24"]),
    lambda r: r["scope"]["domains"].append("dvwa.lab.test"),
    lambda r: r.update(phases=["recon", "correlate", "analyze", "validate", "report"]),
])
def test_roe_del_integrador_modificada_se_rechaza(change):
    roe = integrador_roe()
    change(roe)
    roe["approval"]["roe_sha256"] = roe_digest(roe)
    with pytest.raises(validation.HandoffError, match="ninguna plantilla del repo"):
        validation.check_roe(roe, "demo-integrador-1", now())


@pytest.mark.parametrize("eng", ["demo-pipeline-1", "demo-otra-1", "integrador-1"])
def test_engagement_de_otra_plantilla_no_cambia_de_target(eng):
    """Revisión 2.6: la plantilla sale del nombre del engagement, no de lo que diga la entrega."""
    with pytest.raises(validation.HandoffError, match="plantilla del repo"):
        validation.check_roe(integrador_roe(eng), eng, now())


def test_ventana_larga_con_la_roe_del_integrador_se_rechaza():
    roe = integrador_roe()
    roe["window"]["end"] = "2099-01-01T00:00:00+00:00"
    with pytest.raises(validation.HandoffError, match="ventana"):
        validation.check_roe(roe, "demo-integrador-1", now())


def test_mezcla_de_plantillas_se_rechaza():
    """El alcance de una plantilla con las exclusiones de la otra no es ninguna de las dos."""
    roe = integrador_roe()
    pipe = prepare_roe("x", now(), pipeline.ROE_TEMPLATE)
    roe["exclusions"] = pipe["exclusions"]
    with pytest.raises(validation.HandoffError, match="ninguna plantilla del repo"):
        validation.check_roe(roe, "demo-integrador-1", now())


@pytest.mark.parametrize("argv", [["--roe", "/tmp/mia.yaml"], ["--roe", "../roe-lab"]])
def test_roe_por_ruta_no_se_acepta(tmp_path, argv):
    with pytest.raises(SystemExit):
        pipeline.main([*argv, "--out", str(tmp_path)])
    assert not list(tmp_path.iterdir())


def test_integrador_sin_laboratorio_no_corre(tmp_path, capsys):
    assert pipeline.main(["--roe", "integrador", "--out", str(tmp_path)]) == 2
    assert "--lab" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_integrador_con_lab_pero_sin_laboratorio_no_hace_nada(tmp_path, monkeypatch):
    probed = []
    monkeypatch.setattr(pipeline, "_lab_reachable", lambda host: probed.append(host) or False)
    assert pipeline.main(["--roe", "integrador", "--lab", "--out", str(tmp_path)]) == 2
    assert probed == ["phantomcorp.lab.test"] and not list(tmp_path.iterdir())


def test_por_defecto_sigue_siendo_la_roe_del_pipeline(tmp_path):
    assert pipeline.main(["--out", str(tmp_path)]) == 0
    assert list(tmp_path.glob("demo-pipeline-*.handoff.json"))


# --- 2.7: procedencia del target --------------------------------------------------------------

IMG = "sha256:" + "ab" * 32


class FakeRunner:
    def __init__(self, image=(0, IMG + "\n"), commit=(0, "1234abc\n")):
        self.image, self.commit, self.calls = image, commit, []

    def __call__(self, argv, stdin, timeout_s):
        self.calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return self.image
        if argv[0] == "git":
            return self.commit
        raise AssertionError(argv)


GIT = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks", "-C"]


def test_procedencia_registrada(tmp_path):
    ctx = tmp_path / "phantomcorp"
    ctx.mkdir()
    env = tmp_path / ".env"
    env.write_text(f'PTAAS_ZAP_API_KEY=x\nPTAAS_INTEGRADOR_CONTEXT="{ctx}"\n')
    runner = FakeRunner()
    text = validation.target_provenance(runner, env)
    assert text == f"ptaas-phantomcorp@{IMG} repo@1234abc"
    assert [*GIT, str(ctx), "rev-parse", "HEAD"] in runner.calls


class Timeout(FakeRunner):
    def __call__(self, argv, stdin, timeout_s):
        if argv[0] == "git":
            raise validation.SandboxTimeout()
        return super().__call__(argv, stdin, timeout_s)


@pytest.mark.parametrize("env_text,runner,expected", [
    (None, FakeRunner(), f"ptaas-phantomcorp@{IMG} repo@desconocido"),
    ("PTAAS_ZAP_API_KEY=x\n", FakeRunner(), f"ptaas-phantomcorp@{IMG} repo@desconocido"),
    ("PTAAS_INTEGRADOR_CONTEXT=relativa/phantomcorp\n", FakeRunner(),
     f"ptaas-phantomcorp@{IMG} repo@desconocido"),
    ("PTAAS_INTEGRADOR_CONTEXT={ctx}\n", FakeRunner(image=(1, "")),
     "ptaas-phantomcorp@desconocido repo@1234abc"),
    ("PTAAS_INTEGRADOR_CONTEXT={ctx}\n", FakeRunner(commit=(128, "")),
     f"ptaas-phantomcorp@{IMG} repo@desconocido"),
    ("PTAAS_INTEGRADOR_CONTEXT={ctx}\n", FakeRunner(image=(0, IMG + "\x1b[2J")),
     "ptaas-phantomcorp@desconocido repo@1234abc"),
    ("PTAAS_INTEGRADOR_CONTEXT={ctx}\n", Timeout(), f"ptaas-phantomcorp@{IMG} repo@desconocido"),
])
def test_sin_env_o_sin_imagen_queda_desconocido(tmp_path, env_text, runner, expected):
    env = tmp_path / ".env"
    if env_text is not None:
        env.write_text(env_text.format(ctx=tmp_path))
    assert validation.target_provenance(runner, env) == expected


def test_solo_el_integrador_registra_procedencia():
    assert validation.is_integrador(integrador_roe())
    assert not validation.is_integrador(prepare_roe("x", now(), pipeline.ROE_TEMPLATE))


# --- 2.7 de punta a punta: `main` en modo lab registra la procedencia ---------------------------

def _lab_handoff(inbox, eng):
    """Entrega de laboratorio con la RoE del integrador, como la deja el pipeline en el runner."""
    inbox.mkdir()
    data = {"engagement_id": eng, "mode": "lab", "roe": integrador_roe(eng), "web_hosts": [],
            "candidates": [], "vulns": [], "observations": []}
    raw = json.dumps(data).encode()
    (inbox / f"{eng}.handoff.json").write_bytes(raw)
    audit = SqliteAuditLog.open(eng, inbox)
    audit.record_control(eng, "orchestrator", pipeline.HANDOFF_ACTION, f"{eng}.handoff.json",
                         Result.OK,
                         evidence=f"{eng}.handoff.json#sha256={hashlib.sha256(raw).hexdigest()}")
    audit.close()


@pytest.mark.parametrize("provenance", [
    f"ptaas-phantomcorp@{IMG} repo@1234abc", "ptaas-phantomcorp@desconocido repo@desconocido"])
def test_main_lab_registra_la_procedencia_antes_de_validar(tmp_path, monkeypatch, provenance):
    eng = "demo-integrador-20261120-161146"
    inbox, state = tmp_path / "out", tmp_path / "state"
    _lab_handoff(inbox, eng)
    monkeypatch.setattr(validation, "default_docker_runner", validation.SimDocker())
    monkeypatch.setattr(validation, "lab_network_ok", lambda r: True)
    monkeypatch.setattr(validation, "sandbox_image", lambda r: validation.SIM_IMAGE)
    monkeypatch.setattr(validation, "lab_resolver",
                        lambda r: (lambda h: ["10.99.0.12"] if h == "phantomcorp.lab.test" else []))
    monkeypatch.setattr(validation, "target_provenance", lambda r: provenance)
    assert validation.main(["--lab", "--engagement", eng, "--inbox", str(inbox), "--state",
                            str(state), "--approve-phase", "--reviewer", "santiago"]) == 0
    with sqlite3.connect(state / f"{eng}.sqlite3") as con:
        rows = list(con.execute("SELECT action, target, result FROM audit ORDER BY seq"))
    actions = [a for a, _, _ in rows]
    assert ("target.provenance", provenance, "OK") in rows
    # Justo después de registrar la imagen del sandbox y antes de cualquier envío.
    assert actions[actions.index("sandbox.image") + 1] == "target.provenance"
    assert "poc_catalog.run_parametrized" not in actions[:actions.index("target.provenance")]
