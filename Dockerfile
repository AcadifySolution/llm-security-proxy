# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Stage 2: Runtime image
FROM python:3.11-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:$PATH"

# Create a non-privileged user and group for running the proxy service
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /sbin/nologin appuser

# Copy installed python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Create audit logging directory and set ownership
RUN mkdir -p /var/log/llm-security-proxy && \
    chown -R appuser:appgroup /var/log/llm-security-proxy && \
    chmod -R 755 /var/log/llm-security-proxy

COPY --chown=appuser:appgroup proxy/ /app/proxy/

USER appuser

EXPOSE 8080

ENV PORT=8080
ENV HOST=0.0.0.0
ENV AUDIT_LOG_PATH=/var/log/llm-security-proxy/audit.log

CMD ["uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", "8080"]
