# Imagen del runner: el único contenedor desde el que se alcanzan los objetivos del laboratorio.
# Se construye CON internet (instala nmap y las dependencias) y después corre SOLO en la red
# `lab`, que es `internal: true`: en ejecución no tiene salida a internet.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /work
