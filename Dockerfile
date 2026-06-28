# ============================================================================
# ShieldLLM — Multi-stage Docker Build
# ============================================================================

# ---- Stage 1: Builder ----------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---- Stage 2: Runtime ----------------------------------------------------
FROM python:3.11-slim

RUN groupadd -r shieldllm && useradd -r -g shieldllm shieldllm

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY security/ security/
COPY app.py dashboard.html config.yml .

ENV PATH=/opt/venv/bin:$PATH
ENV PYTHONUNBUFFERED=1

RUN chown -R shieldllm:shieldllm /app /opt/venv

EXPOSE 8080

USER shieldllm

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
