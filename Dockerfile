# ── Build Stage ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install .

COPY app/ ./app/

# ── Runtime Stage ────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd -r authserver && useradd -r -g authserver -d /app -s /sbin/nologin authserver

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local
COPY --from=builder /build/app ./app/

# Copy server-side game offsets (NEVER shipped to client binary)
COPY data/game_offsets.json ./data/game_offsets.json

# Copy license seed file (ensures keys survive DB resets)
COPY data/licenses_seed.json ./data/licenses_seed.json

# Copy entrypoint script
COPY scripts/entrypoint.sh ./entrypoint.sh

# Create data directories + fix permissions
RUN mkdir -p /app/data /app/audit_log /app/certs \
    && chmod +x /app/entrypoint.sh \
    && chown -R authserver:authserver /app

# Environment  — PORT is injected by Render.com at runtime
# DATABASE_URL is set via Render Dashboard (Neon PostgreSQL)
ENV ENVIRONMENT=production \
    HOST=0.0.0.0 \
    PORT=8443 \
    ED25519_AUTO_GENERATE=false

EXPOSE 8443

USER authserver

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",8443)}/health')" || exit 1

# Entrypoint: seed DB → start uvicorn (uses $PORT from Render)
ENTRYPOINT ["/app/entrypoint.sh"]
