# SecPipe tooling image: the aggregator CLI, the metrics exporter and the log
# correlator. Same hardening as the app image: pinned base, hash-verified
# dependencies, no pip in the runtime image, non-root, read-only friendly.
# docker build -f tools/secpipe.Dockerfile -t secpipe-tools:local .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
WORKDIR /src
RUN python -m venv /opt/secpipe
COPY requirements/secpipe.txt requirements/secpipe.txt
RUN /opt/secpipe/bin/pip install --no-cache-dir --require-hashes -r requirements/secpipe.txt
COPY pyproject.toml ./
COPY secpipe/ secpipe/
RUN /opt/secpipe/bin/pip install --no-cache-dir --no-deps --no-build-isolation . \
    && /opt/secpipe/bin/python -m pip uninstall --yes pip setuptools

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN python -m pip uninstall --yes --no-cache-dir pip \
    && useradd --uid 10002 --user-group --no-create-home --shell /usr/sbin/nologin secpipe
COPY --from=build /opt/secpipe /opt/secpipe
ENV PATH=/opt/secpipe/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1
USER 10002:10002
ENTRYPOINT ["secpipe"]
CMD ["--help"]
