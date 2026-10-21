FROM python:3.13-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8013
# backends are wired from env (OPENEMS_DATABASE_URL / OPENEMS_REDIS_URL); see app/api.py:build
CMD ["uvicorn", "--factory", "app.api:build", "--host", "0.0.0.0", "--port", "8013"]
