# Shared Gitea Actions job image. Built once per run by the prepare job
# on the runner's Docker daemon; check jobs docker-run the local tag.
FROM debian:bookworm-slim
WORKDIR /src

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        gcc \
        make \
        pkg-config \
        libpq-dev \
        libc6-dev \
        cppcheck \
        clang-format \
        curl \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/osv-scanner \
        https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks
