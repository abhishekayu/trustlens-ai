# ──────────────────────────────────────────────────────────────────────────────
# TrustLens AI – Multi-stage Dockerfile
# ──────────────────────────────────────────────────────────────────────────────
# Build:   docker build -t trustlens-ai .
# Run:     docker run -p 8000:8000 --env-file .env trustlens-ai
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# System deps for Playwright, cryptography, lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependencies ─────────────────────────────────────────────────────────────
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only for smaller image)
RUN playwright install --with-deps chromium

# ── Application ──────────────────────────────────────────────────────────────
COPY . .
RUN pip install --no-cache-dir -e .

# ── Runtime ──────────────────────────────────────────────────────────────────
ENV TRUSTLENS_HOST=0.0.0.0
ENV TRUSTLENS_PORT=8000

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with uvicorn
CMD ["uvicorn", "trustlens.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
