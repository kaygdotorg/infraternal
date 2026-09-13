# syntax=docker/dockerfile:1.7

# Pin the base image by digest so a rebuild does not silently change the
# Python runtime.  The tag documents the intended Debian/Python release.
FROM docker.io/library/python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STATUS_CONFIG=/etc/status-page/config.json \
    LISTEN_HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# The application has no package dependencies.  A numeric UID keeps the image
# non-root even when the image is run without a passwd entry or with a custom
# rootless user namespace.
RUN mkdir -p /etc/status-page
COPY --chown=65532:65532 status_api.py /app/status_api.py
COPY --chown=65532:65532 web /app/web
COPY --chown=65532:65532 LICENSE THIRD_PARTY_NOTICES.md /app/
COPY --chown=65532:65532 licenses /app/licenses

USER 65532:65532
EXPOSE 8080

# This probes the application itself, rather than a process or socket.  It is
# also useful when the image is run behind the compose reverse proxy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; response = urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2); raise SystemExit(0 if response.status == 200 else 1)"]

ENTRYPOINT ["python3", "/app/status_api.py"]
