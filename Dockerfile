# Bases are pinned by digest; Dependabot proposes digest updates (.github/dependabot.yml).
# The React panel is compiled in a throwaway Node stage; only static files ship.
FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS panel
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run build

# This base includes fixed APT; pin the remaining Debian zlib security update explicitly.
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

# Runtime dependencies come only from the hashed lock, installed into a venv copied below.
FROM builder AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.txt \
    && /opt/venv/bin/pip uninstall -y pip

FROM builder

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/opt/venv/bin:$PATH
WORKDIR /srv
COPY --from=dependencies /opt/venv /opt/venv
COPY app ./app
# Checksummed upgrades for existing databases: python -m app.migrations
COPY migrations ./migrations
COPY --from=panel /app/panel_dist ./app/panel_dist
# Shared policy, categories and uninstall-code modules must ship together.
COPY agent ./agent
COPY tools/update_categories.py ./tools/update_categories.py
COPY tools/update_app_catalog.py ./tools/update_app_catalog.py
# No package installer remains in the runtime layer. A new named volume copies this owner,
# so the daily category job can publish as the unprivileged user.
RUN /usr/local/bin/python -m pip uninstall -y pip \
    && useradd --system --uid 10001 --no-create-home openems \
    && mkdir -p /var/lib/openems/categories /var/lib/openems/app-catalog && chown 10001:10001 /var/lib/openems/categories /var/lib/openems/app-catalog
USER 10001:10001
EXPOSE 8013
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8013/panel/', timeout=4).status == 200 else 1)"]
CMD ["uvicorn", "--factory", "app.api:build", "--host", "0.0.0.0", "--port", "8013", "--no-access-log"]
