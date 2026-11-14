# Image unique du portail QR-Shield : elle sert à l'API, à l'interface et au bot (voir docker-compose.yml)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# le code ; les modèles, la base de menaces et les journaux sont montés depuis le PC (volumes)
COPY src/ src/
COPY api/ api/
COPY app/ app/
COPY bot/ bot/
COPY scripts/ scripts/
COPY registre/ registre/

# l'application ne tourne pas en administrateur (bonne pratique de sécurité)
RUN useradd --create-home qrshield && mkdir -p models logs donnees && chown -R qrshield /app
USER qrshield

EXPOSE 8000 8501
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
