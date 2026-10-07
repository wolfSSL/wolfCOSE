# Shared dependencies for wolfCOSE Linux CI. Rebuild through publish-ci-image.yml.
FROM ubuntu:24.04

LABEL org.opencontainers.image.source="https://github.com/wolfSSL/wolfCOSE" \
      org.opencontainers.image.description="wolfCOSE Linux CI toolchains and test dependencies" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/python-cwt/bin:/opt/ci-tools/bin:/usr/local/go/bin:/opt/cargo/bin:$PATH

# Package installation belongs here, rather than in individual CI jobs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential gcc-11 gcc-12 gcc-13 \
        clang clang-14 clang-15 clang-17 clang-tools clang-tidy \
        libclang-rt-18-dev cppcheck=2.13.0-2ubuntu3 \
        autoconf automake libtool libtool-bin pkg-config m4 \
        libssl-dev libffi-dev \
        lcov bc valgrind \
        git curl ca-certificates jq \
        python3 python3-dev python3-pip python3-venv \
        zip unzip xz-utils zstd file procps \
    && rm -rf /var/lib/apt/lists/*

# Preserve the existing Go 1.24.x and stable Rust policies, resolved at image
# build time rather than downloaded in every interop job.
RUN curl --fail --silent --show-error --location \
        'https://go.dev/dl/?mode=json&include=all' -o /tmp/go-releases.json \
    && read -r go_archive go_sha < <(jq -r \
        '[.[] | select(.stable and (.version | test("^go1\\.24\\.[0-9]+$")))] \
         | first | .files[] \
         | select(.os == "linux" and .arch == "amd64" and .kind == "archive") \
         | [.filename, .sha256] | @tsv' /tmp/go-releases.json) \
    && test -n "$go_archive" && test -n "$go_sha" \
    && curl --fail --silent --show-error --location \
        "https://go.dev/dl/$go_archive" -o /tmp/go.tar.gz \
    && echo "$go_sha  /tmp/go.tar.gz" | sha256sum --check - \
    && tar -xzf /tmp/go.tar.gz -C /usr/local \
    && rm /tmp/go.tar.gz /tmp/go-releases.json

RUN curl --fail --silent --show-error --location \
        https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --profile minimal \
        --default-toolchain stable --no-modify-path \
    && rm /tmp/rustup-init.sh

# Keep the pinned interop environment independent of analysis-tool dependencies.
COPY tests/interop/python_cwt/requirements.txt /tmp/python-cwt-requirements.txt
RUN python3 -m venv /opt/python-cwt \
    && /opt/python-cwt/bin/python -m pip install --no-cache-dir \
        --requirement /tmp/python-cwt-requirements.txt \
    && python3 -m venv /opt/ci-tools \
    && /opt/ci-tools/bin/python -m pip install --no-cache-dir semgrep codespell \
    && rm /tmp/python-cwt-requirements.txt

COPY .github/docker/wolfcose-ci/smoke-test.sh /usr/local/bin/wolfcose-ci-smoke
RUN chmod +x /usr/local/bin/wolfcose-ci-smoke && wolfcose-ci-smoke
