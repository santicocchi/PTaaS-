import pytest

from harness.adapters.common import (ForbiddenArgument, InvalidTarget, load_profiles,
                                     reject_forbidden, validate_target, validate_url)
from harness.adapters.nmap_adapter import NmapServiceScan, build_argv as nmap_argv
from harness.adapters.nuclei_adapter import NucleiSafeTemplates, build_argv as nuclei_argv
from tests.conftest import act, make_token
from harness.contracts import Phase

MALOS = ["; rm -rf /", "10.0.0.5 -A", "-iL /etc/hosts", "host name", "http://x", "$(id)", ""]


@pytest.mark.parametrize("t", MALOS)
def test_targets_malformados_se_rechazan(t):
    with pytest.raises(InvalidTarget):
        validate_target(t)


def test_targets_validos():
    assert validate_target("10.0.0.5") == "10.0.0.5"
    assert validate_target("dvwa.lab.test") == "dvwa.lab.test"
    assert validate_target("10.0.0.0/24", allow_cidr=True)


def test_nmap_argv_acotado_y_sin_scripts():
    argv = nmap_argv("10.0.0.5")
    assert argv[0] == "nmap" and "-sV" in argv and "--max-rate" in argv
    assert not any(a.startswith("--script") or a in ("-A", "-sC", "-O") for a in argv)
    assert argv[-1] == "10.0.0.5"


def test_perfil_nmap_con_argumento_prohibido_falla():
    p = dict(load_profiles()["nmap"])
    p["fixed_args"] = [*p["fixed_args"], "--script=vuln"]
    with pytest.raises(ForbiddenArgument):
        nmap_argv("10.0.0.5", p)


def test_nuclei_usa_templates_curados_y_excluye_intrusivos():
    from harness.templates import ALLOWLIST
    argv = nuclei_argv("dvwa.lab.test", ("10.99.0.2",), [ALLOWLIST / "ptaas-missing-csp.yaml"],
                       rps=5)
    assert str(ALLOWLIST / "ptaas-missing-csp.yaml") in argv
    etags = argv[argv.index("-etags") + 1].split(",")
    assert {"intrusive", "dos", "fuzz", "bruteforce"} <= set(etags)
    assert "-ni" in argv                         # sin OAST hacia terceros


def test_nuclei_rechaza_url_con_credenciales_o_esquema_raro():
    for u in ["ftp://dvwa.lab.test", "http://u:p@dvwa.lab.test/", "javascript:alert(1)"]:
        with pytest.raises(InvalidTarget):
            validate_url(u)


def test_adaptadores_ejecutan_sin_shell_via_runner_inyectado(tmp_path):
    from tests.tool_adapters.allowlist_helpers import approved_allowlist
    vistos = []
    def runner(argv, timeout):
        vistos.append((argv, timeout)); return '{"template-id":"x"}\n'
    out = NucleiSafeTemplates(runner, templates_dir=approved_allowlist(tmp_path)).run(
        act("nuclei.safe_templates", Phase.ANALYZE), "dvwa.lab.test",
        make_token(Phase.ANALYZE), ("10.0.0.50",))
    assert out["invalid_lines"] == 1 and isinstance(vistos[0][0], list)
    NmapServiceScan(runner).run(act("nmap.service_scan", Phase.RECON), "10.0.0.5", make_token(),
                                ("10.0.0.5",))
    assert len(vistos) == 2


def test_reject_forbidden_detecta_forma_con_igual():
    with pytest.raises(ForbiddenArgument):
        reject_forbidden(["--script=vuln"], ["--script"])
