# The React panel is compiled in a throwaway Node stage; only static files ship.
FROM node:24-slim AS panel
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run build

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=panel /app/panel_dist ./app/panel_dist
# Shared stdlib policy validation must be identical on server and endpoint.
COPY agent/policy.py ./agent/policy.py
RUN useradd --system --uid 10001 --no-create-home openems
USER 10001:10001
EXPOSE 8013
CMD ["uvicorn", "--factory", "app.api:build", "--host", "0.0.0.0", "--port", "8013", "--no-access-log"]
