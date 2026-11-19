"""Change 005 · tool-adapters: solo templates registrados, intactos, revisados y de lectura."""
import pytest

from harness.templates import ALLOWLIST, load_manifest, problems, runnable, sha256_of
from tests.tool_adapters.allowlist_helpers import add_template, approved_allowlist

GOOD = """id: {name}
info:
  name: test
  author: t
  severity: info
  tags: headers
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers:
      - type: status
        status: [200]
"""


def test_cada_archivo_esta_en_el_manifiesto_con_su_hash_y_viceversa():
    entries = {e.file: e for e in load_manifest()}
    files = {p.name for p in ALLOWLIST.glob("*.yaml")}
    assert files == set(entries), "archivo sin registrar o registro sin archivo"
    for name, e in entries.items():
        assert sha256_of(ALLOWLIST / name) == e.sha256, f"{name}: hash desactualizado"
        assert e.id == name.removesuffix(".yaml")


def test_hay_al_menos_cinco_templates():
    assert len(load_manifest()) >= 5


@pytest.mark.parametrize("path", sorted(ALLOWLIST.glob("*.yaml")), ids=lambda p: p.stem)
def test_cada_template_pasa_el_control_estatico(path):
    assert problems(path) == []


def test_revisor_distinto_del_autor():
    for e in load_manifest():
        assert e.reviewer and e.reviewer.lower() != e.author.lower()


@pytest.mark.parametrize(("change", "fragment"), [
    (lambda s: s.replace("method: GET", "method: POST"), "método"),
    (lambda s: s.replace("    path:", "    redirects: true\n    path:"), "redirecciones"),
    (lambda s: s.replace("    path:", "    body: x=1\n    path:"), "cuerpo"),
    (lambda s: s.replace("    path:", "    payloads:\n      p: [a]\n    path:"), "prohibidos"),
    (lambda s: s.replace("    path:", "    fuzzing:\n      - part: query\n    path:"),
     "prohibidos"),
    (lambda s: s.replace("tags: headers", "tags: headers,intrusive"), "excluidas"),
    (lambda s: s.replace('"{{BaseURL}}/"', '"http://203.0.113.7/"'), "fuera del objetivo"),
    (lambda s: s + "dns:\n  - name: x\n", "no permitidas"),
    (lambda s: s + "code:\n  - engine: [sh]\n", "no permitidas"),
    (lambda s: s.replace("status: [200]", "words: ['{{interactsh-url}}']"), "OAST"),
    (lambda s: s.replace("id: t-", "id: otro-"), "id"),
    # revisión 005, M4: tags en forma de lista y Host propio
    (lambda s: s.replace("tags: headers", "tags: [headers, intrusive]"), "excluidas"),
    (lambda s: s.replace("tags: headers", "tags:\n    - oast"), "OAST"),
    (lambda s: s.replace("    path:", "    headers:\n      Host: 203.0.113.7\n    path:"),
     "Host"),
    (lambda s: s.replace("    path:", "    headers:\n      HOST: x\n    path:"), "Host"),
])
def test_control_estatico_rechaza(tmp_path, change, fragment):
    path = tmp_path / "t-x.yaml"
    path.write_text(change(GOOD.format(name="t-x")))
    found = problems(path)
    assert any(fragment in p for p in found), found


def test_template_sin_registrar_no_corre(tmp_path):
    base = approved_allowlist(tmp_path)
    add_template(base, "t-nuevo", GOOD.format(name="t-nuevo"), register=False)
    ok, _ = runnable(base)
    assert "t-nuevo" not in {p.stem for p in ok}


def test_template_registrado_y_revisado_corre(tmp_path):
    base = approved_allowlist(tmp_path)
    add_template(base, "t-nuevo", GOOD.format(name="t-nuevo"), register=True)
    assert "t-nuevo" in {p.stem for p in runnable(base)[0]}


def test_autor_que_se_revisa_a_si_mismo_no_corre(tmp_path):
    base = approved_allowlist(tmp_path)
    add_template(base, "t-nuevo", GOOD.format(name="t-nuevo"), register=True, reviewer="autor")
    ok, skipped = runnable(base)
    assert "t-nuevo" not in {p.stem for p in ok} and any("revisor" in s for s in skipped)


def test_template_registrado_que_no_pasa_el_control_no_corre(tmp_path):
    base = approved_allowlist(tmp_path)
    add_template(base, "t-post", GOOD.format(name="t-post").replace("GET", "POST"),
                 register=True)
    assert "t-post" not in {p.stem for p in runnable(base)[0]}


def test_fila_mal_formada_se_ignora(tmp_path):
    base = approved_allowlist(tmp_path)
    with open(base / "MANIFEST.md", "a") as fh:
        fh.write("| ../../etc/passwd | ../x.yaml | zz | a | b | GET | c | d | e |\n")
    assert all(e.file != "../x.yaml" for e in load_manifest(base))
