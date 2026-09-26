# syntax=docker/dockerfile:1
# Hardened SecNotes image (main branch).
#  - slim base pinned by digest (Dependabot bumps it), multi-stage build
#  - dependencies installed with --require-hashes (tampered wheels fail the build)
#  - pip removed from the runtime stage
#  - application code owned by root and read-only for the runtime user
#  - non-root numeric UID, no shell entrypoint, no secrets in any layer
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --no-compile --require-hashes --prefix=/install -r requirements.txt

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
LABEL org.opencontainers.image.source="https://github.com/Weasley18/SecPipe" \
      org.opencontainers.image.title="secnotes" \
      org.opencontainers.image.description="SecNotes API, the SecPipe target application" \
      org.opencontainers.image.licenses="MIT"
# pip is only needed to build; removing it from the runtime image drops its CVEs
# and means a compromised process cannot install tooling.
RUN python -m pip uninstall --yes --no-cache-dir pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /install /usr/local
COPY app/src/ ./src/
ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=2)"]
ENTRYPOINT ["uvicorn", "secnotes.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--proxy-headers"]
