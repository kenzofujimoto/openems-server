FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Shared stdlib policy validation must be identical on server and endpoint.
COPY agent/policy.py ./agent/policy.py
RUN useradd --system --uid 10001 --no-create-home openems
USER 10001:10001
EXPOSE 8013
CMD ["uvicorn", "--factory", "app.api:build", "--host", "0.0.0.0", "--port", "8013", "--no-access-log"]
