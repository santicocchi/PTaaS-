"""Change 004 · tool-adapters: subfinder pasivo y acotado, salida validada."""
from pathlib import Path

import pytest

from harness.adapters.common import ForbiddenArgument, InvalidTarget, load_profiles
from harness.adapters.subfinder_adapter import SubfinderEnum, build_argv, parse_output
from harness.contracts import Phase
from tests.conftest import act, make_token

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "recon"


def test_perfil_de_subfinder():
    argv = build_argv("dvwa.lab.test")
    assert argv[0] == "subfinder" and argv[argv.index("-d") + 1] == "dvwa.lab.test"
    assert {"-oJ", "-nc", "-silent", "-duc"} <= set(argv)
    assert not {"-all", "-recursive", "-active", "-nW", "-ip", "-oI"} & set(argv)


@pytest.mark.parametrize("target", ["10.99.0.3", "10.99.0.0/24", "-all", "; id"])
def test_subfinder_solo_acepta_dominios(target):
    with pytest.raises(InvalidTarget):
        build_argv(target)


@pytest.mark.parametrize("flag", ["-all", "-recursive", "-active", "-ip", "-pc"])
def test_perfil_con_argumento_prohibido_falla(flag):
    profile = dict(load_profiles()["subfinder"])
    profile["fixed_args"] = [*profile["fixed_args"], flag]
    with pytest.raises(ForbiddenArgument):
        build_argv("dvwa.lab.test", profile)


def test_salida_normalizada_y_deduplicada():
    out = parse_output((FIX / "subfinder_lab.jsonl").read_text())
    assert out["status"] == "ok" and out["invalid_lines"] == 0
    assert out["hosts"] == ["api.dvwa.lab.test", "juiceshop.lab.test", "otro.ejemplo.org",
                            "www.dvwa.lab.test"]


def test_salida_totalmente_invalida():
    out = parse_output((FIX / "subfinder_invalid.jsonl").read_text())
    assert out["status"] == "invalid_output" and out["hosts"] == [] and out["invalid_lines"] == 3


def test_nombres_maliciosos_o_ip_se_descartan():
    out = parse_output((FIX / "subfinder_malicious.jsonl").read_text())
    assert out["hosts"] == ["ok.dvwa.lab.test"]
    assert out["status"] == "partial" and out["invalid_lines"] == 3


def test_salida_vacia_es_ok_sin_hosts():
    assert parse_output("") == {"status": "ok", "hosts": [], "invalid_lines": 0}


def test_run_via_runner_y_error_tipado():
    seen = []
    adapter = SubfinderEnum(lambda argv, t: seen.append(argv) or
                            (FIX / "subfinder_lab.jsonl").read_text())
    out = adapter.run(act("subfinder.enum", Phase.RECON), "dvwa.lab.test", make_token(),
                      ("10.0.0.50",))
    assert out["tool"] == "subfinder" and "www.dvwa.lab.test" in out["hosts"]
    assert "10.0.0.50" not in seen[0]          # pasivo: no se conecta a la IP del objetivo

    def missing(argv, t):
        raise FileNotFoundError("subfinder")
    out = SubfinderEnum(missing).run(act("subfinder.enum", Phase.RECON), "dvwa.lab.test",
                                     make_token(), ("10.0.0.50",))
    assert out == {"tool": "subfinder", "target": "dvwa.lab.test", "status": "error",
                   "error": "binary_missing"}
