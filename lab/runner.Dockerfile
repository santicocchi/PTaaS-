# Imagen del runner: el único contenedor desde el que se alcanzan los objetivos del laboratorio.
# Se construye CON internet (instala nmap, httpx, subfinder y las dependencias) y después corre
# SOLO en la red `lab`, que es `internal: true`: en ejecución no tiene salida a internet.
#
# Base Alpine (musl) porque los binarios oficiales de httpx vienen enlazados contra musl.
# Las versiones están fijadas: son las que se verificaron contra los perfiles (change 004).
FROM projectdiscovery/httpx:v1.12.0 AS httpx
FROM projectdiscovery/subfinder:v2.17.0 AS subfinder

FROM python:3.12-alpine
RUN apk add --no-cache nmap
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /work
