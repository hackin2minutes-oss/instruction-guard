# Tiny, dependency-free image for the GitHub Action.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="instruction-guard" \
      org.opencontainers.image.description="Govern the instruction artifacts AI agents obey." \
      org.opencontainers.image.source="https://github.com/hackin2minutes-oss/instruction-guard"

WORKDIR /app
COPY instruction_guard/ /app/instruction_guard/
COPY pyproject.toml README.md /app/
RUN pip install --no-cache-dir ".[sign]"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
