
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY *.py /app/

RUN groupadd --system app && \
    useradd --system --gid app app && \
    mkdir -p /app/data && \
    chown app:app /app/data

ENV ATIVOS_JSON=/app/data/ativos.json
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["python", "-u", "API_Beta.py"]
