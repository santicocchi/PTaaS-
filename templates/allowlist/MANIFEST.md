# Manifiesto de templates de Nuclei (allow-list)

Solo corren los templates de esta tabla cuyo SHA-256 coincide con el archivo y que tienen un
**revisor distinto del autor**. `pendiente` en la columna revisor significa que todavía no se
aprobó: el adaptador no lo ejecuta. Cambiar un template = recalcular su hash y volver a revisarlo.

Control estático: `tests/tool_adapters/test_template_allowlist.py`. Control en ejecución: el
adaptador recalcula el hash antes de cada corrida (change 005, D9).

| id | archivo | sha256 | origen | detecta | método | autor | revisor | fecha |
|---|---|---|---|---|---|---|---|---|
| ptaas-server-version | ptaas-server-version.yaml | eae24342c0e942ea3248e8f421d4f19ea07507eca337d36823188019df53790f | propio | Encabezado Server con versión (CWE-497) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
| ptaas-x-powered-by-version | ptaas-x-powered-by-version.yaml | 0b56a693842db487c3c3310204c26c90c5885f459b4350374c7c8bdafba00513 | propio | X-Powered-By con versión (CWE-497) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
| ptaas-missing-csp | ptaas-missing-csp.yaml | b10d61b4ca171dc6f030d0ba402884a8db6e8e8a580f42fefb4ff1d1ea6993c4 | propio | Falta Content-Security-Policy (CWE-693) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
| ptaas-missing-anticlickjacking | ptaas-missing-anticlickjacking.yaml | aac9975a24a45db664d06e8695eaca5bf2307b0ba7e97fa6114873f5814a9614 | propio | Falta X-Frame-Options / frame-ancestors (CWE-1021) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
| ptaas-cookie-without-httponly | ptaas-cookie-without-httponly.yaml | a808546c5b2a16b3b439604b0a338ef5eb70307bba33448ba7267af0f746cbf8 | propio | Cookies sin HttpOnly (CWE-1004) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
| ptaas-dvwa-login-panel | ptaas-dvwa-login-panel.yaml | f6fdd60af9408d79bc5d49cb25f4c7e3ad9fb7281f9d53360dd1e1dd3e7364dd | propio | Panel de login de DVWA (panel) | GET | Claude (asistente IA) | pendiente | 2026-11-19 |
