# AegisHarness Production & Sandbox Docker Container
FROM python:3.11-slim

LABEL maintainer="Harkirat Singh <harkiratsinghsaggar@gmail.com>"
LABEL project="AegisHarness"
LABEL description="Secure Multi-Tenant Infrastructure for Adversarial AI Safety Testing"

# Security & runtime tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and frontend
COPY aegis /app/aegis
COPY web /app/web
COPY README.md /app/README.md

# Setup simulated read-only model weights directory
RUN mkdir -p /models/weights && \
    echo "CRYPTO_SIGNATURE: sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" > /models/weights/model.safetensors.meta && \
    chmod -R 555 /models/weights

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8000

CMD ["python", "-m", "aegis.api.server"]
