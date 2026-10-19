# log-guard

![CI / Security](https://github.com/GlebBukh/log-guard/actions/workflows/security.yml/badge.svg)

Утилита на Python для поиска попыток подбора пароля (brute-force) в SSH-логах (`/var/log/auth.log`), а также учебный DevSecOps-пайплайн: каждый коммит проходит тесты и проверки безопасности в GitHub Actions.

## Что умеет

- считает неудачные попытки входа по каждому IP;
- помечает адреса, превысившие порог (`--threshold`, по умолчанию 5);
- отдельно сообщает, если после подбора с этого IP был **успешный вход**, то есть вероятную компрометацию учётной записи;
- возвращает код выхода для автоматизации: `0` — чисто, `1` — есть подозрительные IP, `2` — успешный вход после подбора.

## Запуск

```bash
python -m log_guard samples/auth.log
```

```
Неудачных попыток входа: 12

Подозрительные IP (>= 5 неудачных попыток):
  192.0.2.77       5 попыток
  203.0.113.5      6 попыток

[!] После подбора был успешный вход:
  203.0.113.5 -> пользователь deploy
```

Через Docker:

```bash
docker build -t log-guard .
docker run --rm -v "$PWD/samples:/data:ro" log-guard /data/auth.log
```

## DevSecOps-пайплайн

Файл `.github/workflows/security.yml` запускается на каждый push и pull request:

| Этап | Инструмент | Что проверяет |
| --- | --- | --- |
| Тесты | pytest | корректность логики |
| SAST | Bandit | небезопасные конструкции в Python-коде |
| SCA | pip-audit | известные уязвимости (CVE) в зависимостях |
| Секреты | Gitleaks | пароли, токены и ключи в истории git |
| Контейнер | Trivy | уязвимости в Docker-образе (CRITICAL/HIGH) |

Меры безопасности в самом проекте:
- контейнер работает от непривилегированного пользователя, а не от root;
- slim-образ и `.dockerignore`, чтобы в образ не попало лишнее;
- версии зависимостей зафиксированы в `requirements-dev.txt`;
- у токена пайплайна только право чтения (`permissions: contents: read`).

## Разработка

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
bandit -r log_guard
```

IP-адреса в `samples/auth.log` взяты из диапазонов для документации (RFC 5737) и не принадлежат реальным узлам.
