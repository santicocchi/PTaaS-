"""Change 004 · tool-adapters: errores de herramienta sin excepción y entorno sin proxy."""
import subprocess
import sys
from pathlib import Path

import pytest

from harness.adapters import common
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.contracts import Phase
from tests.conftest import act, make_token


def _raises(exc):
    def runner(argv, timeout):
        raise exc
    return runner


@pytest.mark.parametrize(("exc", "kind"), [
    (FileNotFoundError("nmap"), "binary_missing"),
    (subprocess.TimeoutExpired(["nmap"], 300), "timeout"),
    (common.ToolFailure("exit_code"), "exit_code"),
])
def test_error_de_herramienta_es_resultado_tipado(exc, kind):
    out = NmapServiceScan(_raises(exc)).run(act("nmap.service_scan", Phase.RECON), "10.0.0.5",
                                            make_token(), ("10.0.0.5",))
    assert out["status"] == "error" and out["error"] == kind


def test_runner_real_traduce_binario_ausente_y_codigo_de_salida():
    with pytest.raises(common.ToolFailure) as missing:
        common.default_runner(["ptaas-binario-que-no-existe"], 5)
    assert missing.value.kind == "binary_missing"
    with pytest.raises(common.ToolFailure) as failed:
        common.default_runner(["false"], 5)
    assert failed.value.kind == "exit_code"
    with pytest.raises(common.ToolFailure) as slow:
        common.default_runner(["sleep", "5"], 1)
    assert slow.value.kind == "timeout"


def test_entorno_de_herramientas_sin_proxy(monkeypatch):
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
                "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:3128")
    monkeypatch.setenv("PATH_EXTRA_OK", "1")
    env = common.safe_env()
    assert not any(k.lower().endswith("_proxy") and k.lower() != "no_proxy" for k in env)
    assert env["PATH_EXTRA_OK"] == "1"


def test_la_herramienta_no_hereda_la_entrada_estandar():
    """httpx lee objetivos de stdin si es un pipe: con stdin heredado se cuelga o, peor,
    sondea lo que le llegue por ahí. El runner le da una entrada vacía."""
    # pytest ya tapa el fd 0 de este proceso, así que se prueba en un proceso aparte con un
    # pipe en stdin, como lo tendría el harness corriendo detrás de otro programa.
    code = "from harness.adapters.common import default_runner; print(repr(default_runner(['cat'], 5)))"
    proc = subprocess.run([sys.executable, "-c", code], input="203.0.113.7\n", text=True,
                          capture_output=True, timeout=30, check=True,
                          cwd=Path(__file__).resolve().parents[2])
    assert proc.stdout.strip() == "''"
