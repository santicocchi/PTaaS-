"""Change 004 · tool-adapters: salida de nmap validada y convertida en tecnologías."""
from pathlib import Path

from harness.adapters.nmap_adapter import NmapServiceScan, parse_output
from harness.contracts import Phase
from tests.conftest import act, make_token

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "recon"


def test_puertos_abiertos_y_tecnologias_con_version():
    out = parse_output((FIX / "nmap_dvwa.xml").read_text())
    assert out["status"] == "ok"
    assert [(s["address"], s["port"], s["service"]) for s in out["services"]] == [
        ("10.99.0.3", 80, "http"), ("10.99.0.3", 3306, "mysql")]
    assert out["services"][0]["tech"] == "Apache httpd:2.4.25"
    assert out["services"][1]["tech"] is None          # sin producto no hay tecnología


def test_xml_roto_es_salida_invalida():
    assert parse_output("<nmaprun><host>")["status"] == "invalid_output"


def test_salida_vacia_es_ok_sin_servicios():
    assert parse_output("") == {"status": "ok", "services": [], "invalid_lines": 0}


def test_puerto_con_datos_raros_se_descarta():
    raw = ('<nmaprun><host><address addr="10.99.0.3" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="99999"><state state="open"/></port>'
           '<port protocol="tcp" portid="80"><state state="open"/>'
           '<service name="http" product="Apache&#x85;httpd"/></port>'
           '</ports></host></nmaprun>')
    out = parse_output(raw)
    assert out["status"] == "partial" and out["invalid_lines"] == 1
    assert out["services"][0]["tech"] == "Apachehttpd"   # sin caracteres de control


def test_run_devuelve_servicios():
    adapter = NmapServiceScan(lambda argv, t: (FIX / "nmap_dvwa.xml").read_text())
    out = adapter.run(act("nmap.service_scan", Phase.RECON), "dvwa.lab.test", make_token(),
                      ("10.99.0.3",))
    assert out["tool"] == "nmap" and out["services"][0]["port"] == 80 and "raw" in out


def test_host_que_no_se_escaneo_se_descarta():
    raw = (FIX / "nmap_dvwa.xml").read_text()
    escaneado = parse_output(raw)["services"][0]["address"]
    out = parse_output(raw, ("10.99.0.200",))
    assert out["services"] == [] and out["status"] == "invalid_output"
    assert parse_output(raw, (escaneado,))["services"]
