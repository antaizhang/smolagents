# Build from the repository root so the whole package is in the build context:
#   docker build -f examples/sensitiveguard/demo_server/Dockerfile -t sensitiveguard-demo .
#   docker run --rm -p 8080:8080 -e SG_DEMO_TOKEN=change-me sensitiveguard-demo
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e . \
    && python examples/sensitiveguard/demo_server/run_cases.py

# The demo never spawns a process and never opens an outbound socket, so it can
# run unprivileged with a read-only root filesystem.
RUN useradd --create-home --uid 10001 demo
USER demo

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["python", "examples/sensitiveguard/demo_server/server.py", "--host", "0.0.0.0", "--port", "8080"]
