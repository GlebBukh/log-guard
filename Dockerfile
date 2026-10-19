# Минимальный образ: slim-база, без лишних пакетов
FROM python:3.13-slim

# Не запускаем приложение от root
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app

COPY log_guard/ ./log_guard/

USER appuser

ENTRYPOINT ["python", "-m", "log_guard"]
CMD ["--help"]
