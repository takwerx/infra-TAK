# SPDX-License-Identifier: AGPL-3.0-or-later
# etl-shim image (ETL Runner, v10.4.0 W1). Built on the box from this directory; never pulled.
# Base pinned by INDEX digest (multi-arch: amd64 + arm64 resolve from the same pin).
# node:22-alpine as of 2026-11-05. Bump deliberately, with a /module-scan note.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
WORKDIR /app
COPY lib.mjs shim.mjs /app/
# Runs as the host's takwerx-etl uid (compose `user:`); `node` is only the fallback.
USER node
EXPOSE 4000 4001
CMD ["node", "shim.mjs"]
