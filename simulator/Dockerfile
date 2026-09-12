# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# TAK Simulator engine container (PLAN v10.1.61 §4.2).
# - base pinned BY DIGEST to the multi-arch python:3.12-slim index (amd64 + arm64 resolve
#   from the same digest; re-pin deliberately, never float)
# - standard library only: no pip, no lockfile, no supply chain beyond the base image
# - runs as an unprivileged user; no host networking, no Docker socket, no capabilities
# - no EXPOSE'd public port: compose publishes the control API on 127.0.0.1 only
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG SIM_VERSION=dev
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SIM_VERSION=${SIM_VERSION}

RUN groupadd --gid 10001 sim \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sim

WORKDIR /app
COPY engine /app/engine

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python3", "-m", "engine", "--healthcheck"]

ENTRYPOINT ["python3", "-m", "engine"]
