"""Change 004 · tool-adapters: httpx con IP fijada, sin redirecciones y con rate limit."""
from pathlib import Path

import pytest

from harness.adapters.common import ForbiddenArgument, InvalidTarget, load_profiles
from harness.adapters.httpx_adapter import HttpxProbe, build_argv, parse_output
from harness.contracts import Phase
from tests.conftest import act, make_token

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "recon"


def _flag_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


def test_perfil_de_httpx_con_ip_fijada_y_rate_limit():
    argv = build_argv("dvwa.lab.test", ("10.99.0.3",), rps=5)
    assert argv[0] == "httpx"
    assert _flag_values(argv, "-u") == ["http://10.99.0.3"]
    assert _flag_values(argv, "-H") == ["Host: dvwa.lab.test"]
    assert _flag_values(argv, "-rl") == ["5"]
    assert "dvwa.lab.test" not in _flag_values(argv, "-u")
    assert not {"-fr", "-follow-redirects", "-fhr", "-follow-host-redirects"} & set(argv)


def test_varias_ip_y_ipv6():
    argv = build_argv("app.lab.test", ("10.99.0.3", "fd00::3"), rps=5)
    assert _flag_values(argv, "-u") == ["http://10.99.0.3", "http://[fd00::3]"]


def test_objetivo_ip_no_lleva_host():
    argv = build_argv("10.99.0.3", ("10.99.0.3",), rps=5)
    assert _flag_values(argv, "-H") == [] and _flag_values(argv, "-u") == ["http://10.99.0.3"]


@pytest.mark.parametrize(("target", "addresses"), [
    ("dvwa.lab.test", ()),                       # sin IP validada no se sondea
    ("dvwa.lab.test", ("dvwa.lab.test",)),       # una dirección que no es IP
    ("dvwa.lab.test", ("10.99.0.3 -fr",)),
    ("dvwa.lab.test\r\nX: y", ("10.99.0.3",)),   # inyección de encabezados
])
def test_entradas_invalidas_se_rechazan(target, addresses):
    with pytest.raises(InvalidTarget):
        build_argv(target, addresses, rps=5)


@pytest.mark.parametrize("flag", ["-fr", "-follow-redirects", "-fhr", "-maxr", "-proxy", "-x",
                                  "--fr", "--follow-redirects=true", "-csp-probe", "-tls-probe",
                                  "-ss", "-screenshot", "-config", "-p", "--ports=8080", "-o"])
def test_perfil_con_argumento_prohibido_falla(flag):
    profile = dict(load_profiles()["httpx"])
    profile["fixed_args"] = [*profile["fixed_args"], flag]
    with pytest.raises(ForbiddenArgument):
        build_argv("dvwa.lab.test", ("10.99.0.3",), profile, rps=5)


def test_salida_real_de_httpx():
    out = parse_output("dvwa.lab.test", (FIX / "httpx_dvwa.jsonl").read_text())
    assert out["status"] == "ok"
    (svc,) = out["services"]
    assert svc["url"] == "http://dvwa.lab.test:80" and svc["address"] == "10.99.0.3"
    assert svc["status_code"] == 200 and "Apache HTTP Server:2.4.25" in svc["tech"]
    assert svc["location"] is None


def test_salida_parcialmente_invalida():
    out = parse_output("dvwa.lab.test", (FIX / "httpx_partial.jsonl").read_text())
    assert out["status"] == "partial" and out["invalid_lines"] == 1
    assert [s["port"] for s in out["services"]] == [80, 8080, 443]


def test_redireccion_queda_como_dato_y_no_se_sigue():
    out = parse_output("dvwa.lab.test", (FIX / "httpx_redirect.jsonl").read_text())
    (svc,) = out["services"]
    assert svc["status_code"] == 302 and svc["location"] == "http://203.0.113.7/"


def test_campos_de_tipo_raro_invalidan_la_linea():
    lines = [
        '{"url":"http://10.99.0.3","port":"80","status_code":"200"}',
        '{"url":"http://10.99.0.3","port":"99999","status_code":200}',
        '{"url":"http://10.99.0.3","port":"80","status_code":200,"tech":"Apache"}',
        '{"url":"http://203.0.113.7","port":"80","status_code":200}',   # IP que no se pidió
        '{"url":"http://10.99.0.3","port":"80","status_code":true}',    # bool no es int
    ]
    out = parse_output("dvwa.lab.test", "\n".join(lines), ("10.99.0.3",))
    assert out["status"] == "invalid_output" and out["invalid_lines"] == 5


def test_titulo_con_caracteres_de_control_se_limpia():
    raw = '{"url":"http://10.99.0.3","port":"80","status_code":200,"title":"a\\u001b[31mb' \
          + "x" * 500 + '"}'
    (svc,) = parse_output("dvwa.lab.test", raw)["services"]
    assert "\x1b" not in svc["title"] and len(svc["title"]) <= 200


def test_run_via_runner():
    seen = []
    adapter = HttpxProbe(lambda argv, t: seen.append(argv) or
                         (FIX / "httpx_dvwa.jsonl").read_text(), rps=5)
    out = adapter.run(act("httpx.probe", Phase.RECON), "dvwa.lab.test", make_token(),
                      ("10.99.0.3",))
    assert out["tool"] == "httpx" and out["services"][0]["port"] == 80
    assert _flag_values(seen[0], "-u") == ["http://10.99.0.3"]


def test_rate_limit_sale_de_la_politica():
    adapter = HttpxProbe(lambda argv, t: "")
    assert adapter.rps == 5


def test_lista_de_tecnologias_acotada():
    tech = ", ".join(f'"t{i}"' for i in range(500))
    raw = ('{"url":"http://10.99.0.3","port":"80","status_code":200,"tech":[' + tech + "]}")
    (svc,) = parse_output("dvwa.lab.test", raw)["services"]
    assert len(svc["tech"]) == 20
