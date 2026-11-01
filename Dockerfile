FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:0.5.31 /uv /bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN DJANGO_SECRET_KEY=collectstatic-only python manage.py collectstatic --noinput \
 && useradd --system --no-create-home app \
 && chown -R app /app/staticfiles

USER app
EXPOSE 8000
ENTRYPOINT ["/app/deploy/entrypoint.sh"]
# 4 processes x 8 threads comfortably serves 150+ students submitting at once.
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "4", \
     "--threads", "8", "--timeout", "60", "--access-logfile", "-"]
