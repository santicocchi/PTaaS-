"""Spec archivada de reporting (antes del 007). El 007 la reemplaza al archivarse (task 3.6);
los Scenarios nuevos están en tests/reporting/."""
import pytest

from harness.reporting import DeliveryNotApproved, MissingField, deliver
from tests.reporting.helpers import Lab


def test_hallazgo_sin_cwe_falla_indicando_el_campo(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("F-1", cwe="unknown")
    with pytest.raises(MissingField) as e:
        lab.generate()
    assert ("F-1", "cwe") in e.value.missing


def test_entrega_sin_aprobacion_se_rechaza(tmp_path):
    lab = Lab(tmp_path)
    lab.finding("F-1")
    rep = lab.generate()
    with pytest.raises(DeliveryNotApproved):
        deliver({"report_id": rep.report_id}, reviewer_approved=False)
