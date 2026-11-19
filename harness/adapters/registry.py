"""Adaptadores reales del harness. El test de contrato los recorre todos y `mypy --strict`
verifica que cada clase cumpla `ToolAdapter` (por ejemplo, que `run` reciba `addresses`)."""
from __future__ import annotations

from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.contracts import ToolAdapter

ADAPTER_CLASSES: tuple[type[ToolAdapter], ...] = (SubfinderEnum, HttpxProbe, NmapServiceScan,
                                     NucleiSafeTemplates)
