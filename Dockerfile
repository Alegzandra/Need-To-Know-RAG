# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    NTK_DATA_DIR=/data NTK_USERS_FILE=/config/users.yaml NTK_COMPARTMENTS_FILE=/config/compartments.yaml

# OCR for scanned documents (Romanian + English)
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-ron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY ntk ./ntk
RUN pip install . && useradd --uid 10001 --create-home ntk && mkdir -p /data /config && chown ntk /data
COPY config /config

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').status==200 else 1)"
CMD ["uvicorn", "ntk.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
