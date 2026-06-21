FROM python:3.12-slim

ARG APP_VERSION=unknown
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_VERSION=${APP_VERSION}

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY mail_admin ./mail_admin
COPY wsgi.py gunicorn.conf.py mailctl.py ./

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.getenv(\"GUNICORN_BIND_PORT\",\"8080\")}/ping').read()" || exit 1

CMD ["gunicorn", "wsgi:app", "-c", "gunicorn.conf.py"]
