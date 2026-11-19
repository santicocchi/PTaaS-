# Imagen del runner: el único contenedor desde el que se alcanzan los objetivos del laboratorio.
# Se construye CON internet (instala nmap, httpx, subfinder y las dependencias) y después corre
# SOLO en la red `lab`, que es `internal: true`: en ejecución no tiene salida a internet.
#
# Base Alpine (musl) porque los binarios oficiales de httpx vienen enlazados contra musl.
# Las versiones están fijadas por tag Y por digest: son las que se verificaron contra los
# perfiles (change 004). Si alguien vuelve a publicar el tag, se sigue usando la imagen probada.
FROM projectdiscovery/httpx:v1.12.0@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc AS httpx
FROM projectdiscovery/subfinder:v2.17.0@sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf AS subfinder

FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
RUN apk add --no-cache nmap
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /work
