FROM rust:1-slim-trixie AS rust-build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY python/bridge.py ./python/bridge.py
RUN cargo build --locked --release --bin miasm-disasm

FROM python:3.12-slim-trixie AS python-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY python/requirements.txt python/mcp-requirements.txt /build/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /build/mcp-requirements.txt

FROM python:3.12-slim-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 miasm \
    && useradd --uid 10001 --gid miasm --no-create-home miasm \
    && mkdir /samples
COPY --from=rust-build /build/target/release/miasm-disasm /usr/local/bin/miasm-disasm
COPY --from=python-build /opt/venv /opt/venv
COPY python/mcp_server.py LICENSE NOTICE /opt/miasm/
ENV MIASM_PYTHON=/opt/venv/bin/python \
    MIASM_INPUT_ROOT=/samples \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /samples
ENTRYPOINT ["/opt/venv/bin/python", "/opt/miasm/mcp_server.py"]