ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN uv pip install --python /app/.venv/bin/python --no-cache \
    psycopg2-binary==2.9.13 trino==0.340.0
USER superset
