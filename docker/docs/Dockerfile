FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/wolfSSL/wolfCOSE"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash git make patch perl librsvg2-bin \
        pandoc texlive-xetex texlive-latex-extra texlive-fonts-recommended \
        fonts-noto-core fonts-noto-mono lmodern \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements-docs.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-docs.txt

WORKDIR /work
