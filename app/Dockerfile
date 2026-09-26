# PLANTED FLAW #12: end-of-life full base image (Debian 11 "bullseye", hundreds of
# OS CVEs) on an unpinned tag, runs as root, secret baked into an image layer,
# ADD of the whole repository (including .git), dev-mode --reload.
FROM python:3.11-bullseye
ENV DB_PASSWORD=supersecret123
ADD . /app
WORKDIR /app
RUN pip install -r app/requirements.txt
ENV PYTHONPATH=/app/app/src
CMD uvicorn secnotes.main:app --host 0.0.0.0 --reload
