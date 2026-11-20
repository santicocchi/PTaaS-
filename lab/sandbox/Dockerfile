# Imagen del sandbox del loop C (change 006, D3). Mínima y sin dependencias externas.
# Se construye una vez y se usa con `docker run --rm` desde harness/sandbox.py, nunca como
# servicio. La base va fijada por digest, la misma que el runner.
#
#   docker compose -f lab/docker-compose.yml --profile build build sandbox
#   docker image inspect ptaas-sandbox --format '{{.Id}}'   # digest que recibe DockerSandbox
FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
COPY send.py /app/send.py
USER 65534:65534
ENTRYPOINT ["python", "-I", "/app/send.py"]
