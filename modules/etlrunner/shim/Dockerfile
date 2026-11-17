# SPDX-License-Identifier: AGPL-3.0-or-later
# etl-shim image (ETL Runner, v10.4.0 W1). Built on the box from this directory; never pulled.
# Base pinned by INDEX digest (multi-arch: amd64 + arm64 resolve from the same pin).
# node:22-alpine = Node 22.23.5 (2026-11-11 security release, ops #824). Bump deliberately, with a /module-scan note.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
WORKDIR /app
COPY lib.mjs shim.mjs /app/
# Runs as the host's takwerx-etl uid (compose `user:`); `node` is only the fallback.
USER node
EXPOSE 4000 4001
CMD ["node", "shim.mjs"]
