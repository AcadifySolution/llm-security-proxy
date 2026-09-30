# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim AS runner

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 appgroup     && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin appuser     && mkdir -p /var/log/llm-security-proxy     && chown -R appuser:appgroup /var/log/llm-security-proxy

COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup proxy /app/proxy

ENV PATH="/home/appuser/.local/bin:$PATH"
ENV HOST=0.0.0.0 PORT=8080
ENV AUDIT_LOG_PATH=/var/log/llm-security-proxy/audit.log

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3   CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"

CMD ["uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", "8080"]
