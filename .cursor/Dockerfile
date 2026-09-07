FROM debian:bookworm-slim
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates gcc make pkg-config libpq-dev libc6-dev \
 && rm -rf /var/lib/apt/lists/*
