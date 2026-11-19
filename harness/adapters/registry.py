"""Adaptadores reales del harness. El test de contrato los recorre todos."""
from __future__ import annotations

from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nmap_adapter import NmapServiceScan
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.subfinder_adapter import SubfinderEnum

ADAPTER_CLASSES: tuple[type, ...] = (SubfinderEnum, HttpxProbe, NmapServiceScan,
                                     NucleiSafeTemplates)
