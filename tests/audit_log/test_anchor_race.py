"""Bitácora (002): una escritura concurrente entre leer y comparar el ancla no es truncado.

Lo encontró el test A10 de forma intermitente al cambiar los tiempos en el 004: un hilo leía
los registros, otro agregaba uno y movía el ancla, y el primero comparaba su lectura vieja
con el ancla nueva → "faltan registros" falso → el Harness activaba el kill switch.
"""
from harness.audit import SqliteAuditLog
from harness.contracts import Result


def test_escritura_entre_lectura_y_ancla_no_es_truncado(tmp_path, monkeypatch):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    log.record_control("eng-1", "a", "x.y", "t", Result.OK)
    log.verify_integrity()

    real_entries = SqliteAuditLog.entries.fget
    calls = []

    def stale_then_append(self):
        snapshot = real_entries(self)
        if not calls:                       # otro "hilo" escribe justo después de la lectura
            calls.append(1)
            self.record_control("eng-1", "b", "x.y", "t", Result.OK)
        return snapshot

    monkeypatch.setattr(SqliteAuditLog, "entries", property(stale_then_append))
    log.verify_integrity()                  # no debe lanzar
    monkeypatch.undo()
    log.verify_integrity()
    assert len(log.entries) == 2


def test_el_ancla_no_retrocede(tmp_path):
    log = SqliteAuditLog.open("eng-1", tmp_path)
    for _ in range(3):
        log.record_control("eng-1", "a", "x.y", "t", Result.OK)
    log._anchor = (3, log.entries[-1]["hash"])
    log.verify_integrity()
    assert log._anchor[0] == 3
