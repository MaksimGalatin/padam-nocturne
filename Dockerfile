# PADAM · NOCTURNE — локальный сервер памяти (REST API + PADAM Studio)
# Запуск с обязательным токеном владельца и постоянным томом для базы SQLite:
#   docker compose up -d
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PADAM_HOME=/data \
    PADAM_PORT=8077

WORKDIR /app

# Создаём непривилегированного пользователя и каталог данных с правами 0700
RUN groupadd --gid 10001 padam \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin padam \
    && mkdir -p /data \
    && chown -R padam:padam /data /app \
    && chmod 0700 /data

COPY pyproject.toml README.md README.ru.md LICENSE ./
COPY padam ./padam

RUN pip install --no-cache-dir -e .

USER padam
VOLUME ["/data"]
EXPOSE 8077

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8077/health', timeout=3)" || exit 1

CMD ["python", "-c", "import os, sys; from padam import api; tok = (os.environ.get('PADAM_API_TOKEN') or '').strip(); sys.exit(api.main(['--host', '0.0.0.0', '--port', os.environ.get('PADAM_PORT', '8077'), '--ui', '--token', tok])) if len(tok) >= 16 and not tok.upper().startswith('REPLACE') else (sys.stderr.write('Refused: PADAM_API_TOKEN (>= 16 chars) is required in Docker.\\nОтказ: для запуска в Docker необходим PADAM_API_TOKEN (не короче 16 символов).\\n'), sys.exit(2))"]
