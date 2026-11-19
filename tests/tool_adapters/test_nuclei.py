"""Change 005 · tool-adapters: nuclei con host, IP fijada, sin redirecciones y templates verificados."""
from pathlib import Path

import pytest

from harness.adapters.common import ForbiddenArgument, InvalidTarget, load_profiles
from harness.adapters.nuclei_adapter import NucleiSafeTemplates, build_argv, parse_output
from harness.contracts import Phase
from harness.templates import ALLOWLIST
from tests.conftest import act, make_token
from tests.tool_adapters.allowlist_helpers import approved_allowlist, rewrite_manifest_row

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "analysis"
CSP = [ALLOWLIST / "ptaas-missing-csp.yaml"]
IDS = {"ptaas-server-version", "ptaas-missing-csp", "ptaas-dvwa-login-panel"}


def test_perfil_de_nuclei():
    argv = build_argv("dvwa.lab.test", ("10.99.0.2",), CSP, (80,), rps=5)
    assert argv[argv.index("-u") + 1] == "http://10.99.0.2:80"
    assert argv[argv.index("-H") + 1] == "Host: dvwa.lab.test"
    assert {"-dr", "-ni", "-nh", "-duc"} <= set(argv)
    assert argv[argv.index("-rl") + 1] == "5" and argv[argv.index("-pt") + 1] == "http"
    assert not {"-fr", "-code", "-headless", "-dast", "-follow-redirects"} & set(argv)
    assert "dvwa.lab.test" not in [argv[i + 1] for i, a in enumerate(argv) if a == "-u"]


def test_varias_ip_puertos_y_ipv6():
    argv = build_argv("dvwa.lab.test", ("10.99.0.2", "fd00::2"), CSP, (8080, 80), rps=5)
    us = [argv[i + 1] for i, a in enumerate(argv) if a == "-u"]
    assert us == ["http://10.99.0.2:80", "http://10.99.0.2:8080", "http://[fd00::2]:80",
                  "http://[fd00::2]:8080"]


def test_objetivo_ip_no_lleva_host():
    assert "-H" not in build_argv("10.99.0.2", ("10.99.0.2",), CSP, rps=5)


@pytest.mark.parametrize(("target", "addresses", "ports"), [
    ("http://dvwa.lab.test/../", ("10.99.0.2",), (80,)),   # URL en vez de host (red team 4.1)
    ("dvwa.lab.test", (), (80,)),
    ("dvwa.lab.test", ("dvwa.lab.test",), (80,)),
    ("dvwa.lab.test", ("10.99.0.2",), (0,)),
    ("dvwa.lab.test", ("10.99.0.2",), ()),
    ("dvwa.lab.test", ("10.99.0.2",), ("80",)),
])
def test_entradas_invalidas(target, addresses, ports):
    with pytest.raises(InvalidTarget):
        build_argv(target, addresses, CSP, ports, rps=5)


def test_sin_templates_no_se_arma_comando():
    with pytest.raises(InvalidTarget):
        build_argv("dvwa.lab.test", ("10.99.0.2",), [], rps=5)


@pytest.mark.parametrize("flag", ["-fr", "--follow-redirects", "-code", "-headless", "-dast",
                                  "-as", "-ut", "-p", "-config", "-it", "-o", "-r", "-esc",
                                  "-lfa", "-w"])
def test_perfil_con_argumento_prohibido_falla(flag):
    profile = dict(load_profiles()["nuclei"])
    profile["fixed_args"] = [*profile["fixed_args"], flag]
    with pytest.raises(ForbiddenArgument):
        build_argv("dvwa.lab.test", ("10.99.0.2",), CSP, profile=profile, rps=5)


def test_salida_real_de_nuclei():
    out = parse_output("dvwa.lab.test", (FIX / "nuclei_dvwa.jsonl").read_text(), ("10.99.0.2",),
                       IDS)
    assert out["status"] == "ok" and out["invalid_lines"] == 0
    by_id = {f["template_id"]: f for f in out["findings"]}
    assert by_id["ptaas-server-version"]["cwe"] == "CWE-497"
    assert by_id["ptaas-server-version"]["evidence"] == ["Apache/2.4.25 (Debian)"]
    assert by_id["ptaas-server-version"]["url"] == "http://dvwa.lab.test:80/"
    assert by_id["ptaas-dvwa-login-panel"]["cwe"] == "unknown"
    assert by_id["ptaas-dvwa-login-panel"]["url"] == "http://dvwa.lab.test:80/login.php"


@pytest.mark.parametrize("line", [
    '{"template-id":"ptaas-missing-csp","ip":"203.0.113.7","matched-at":"http://203.0.113.7/"}',
    '{"template-id":"ptaas-missing-csp","ip":"10.99.0.2","matched-at":"http://203.0.113.7/"}',
    '{"template-id":"otro-template","ip":"10.99.0.2","matched-at":"http://10.99.0.2/"}',
    '{"template-id":"ptaas-missing-csp","ip":"no-ip","matched-at":"http://10.99.0.2/"}',
    '["no", "es", "un", "objeto"]',
    "no es json",
])
def test_lineas_que_no_corresponden_se_descartan(line):
    out = parse_output("dvwa.lab.test", line, ("10.99.0.2",), IDS)
    assert out["findings"] == [] and out["invalid_lines"] == 1
    assert out["status"] == "invalid_output"


def test_run_solo_con_templates_aprobados(tmp_path):
    seen = []

    def runner(argv, timeout):
        seen.append(argv)
        return (FIX / "nuclei_dvwa.jsonl").read_text()

    base = approved_allowlist(tmp_path)
    rewrite_manifest_row(base, "ptaas-missing-csp", revisor="pendiente")
    out = NucleiSafeTemplates(runner, templates_dir=base, ports_of=lambda h: (80,)).run(
        act("nuclei.safe_templates", Phase.ANALYZE), "dvwa.lab.test",
        make_token(Phase.ANALYZE), ("10.99.0.2",))
    templates = [Path(seen[0][i + 1]).stem for i, a in enumerate(seen[0]) if a == "-t"]
    assert "ptaas-missing-csp" not in templates and len(templates) == 5
    assert any("ptaas-missing-csp" in s for s in out["skipped"])
    # el hallazgo de un template que no corrió no se acepta
    assert "ptaas-missing-csp" not in {f["template_id"] for f in out["findings"]}


def test_template_modificado_no_corre(tmp_path):
    base = approved_allowlist(tmp_path)
    with open(base / "ptaas-server-version.yaml", "a") as fh:
        fh.write("# cambio\n")
    seen = []
    NucleiSafeTemplates(lambda a, t: seen.append(a) or "", templates_dir=base).run(
        act("nuclei.safe_templates", Phase.ANALYZE), "dvwa.lab.test",
        make_token(Phase.ANALYZE), ("10.99.0.2",))
    assert not any("ptaas-server-version" in a for a in seen[0])


def test_sin_templates_aprobados_no_se_ejecuta_nada():
    calls = []
    out = NucleiSafeTemplates(lambda a, t: calls.append(a) or "").run(
        act("nuclei.safe_templates", Phase.ANALYZE), "dvwa.lab.test",
        make_token(Phase.ANALYZE), ("10.99.0.2",))
    assert calls == [] and out["templates_run"] == [] and out["skipped"]


def test_error_de_herramienta_tipado(tmp_path):
    def boom(argv, timeout):
        raise FileNotFoundError("nuclei")
    out = NucleiSafeTemplates(boom, templates_dir=approved_allowlist(tmp_path)).run(
        act("nuclei.safe_templates", Phase.ANALYZE), "dvwa.lab.test",
        make_token(Phase.ANALYZE), ("10.99.0.2",))
    assert out["status"] == "error" and out["error"] == "binary_missing"


def test_rate_limit_sale_de_la_politica():
    from harness.policy_loader import load_policy
    assert NucleiSafeTemplates().rps == load_policy()["limits"]["rate_limit_rps_per_target"]
