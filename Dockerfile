# ── Stage 1: Build from source ────────────────────────────────────────────────
# Railway runs this stage on a Linux builder — no pre-built binary needed.
FROM rust:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    librocksdb-dev \
    clang \
    llvm \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files (Railway excludes target/ via .dockerignore)
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Pre-build dependencies (cached layer)
RUN cargo build --release --locked 2>&1 | tail -5 || \
    cargo build --release 2>&1 | tail -5

# Build the binary
RUN cp target/release/arobi-network arobi-network-$(git rev-parse --short HEAD 2>/dev/null || echo "build") && \
    chmod +x arobi-network-*

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 1000 -s /bin/sh arobi

# Copy binary from builder
COPY --from=builder /app/arobi-network-* /usr/local/bin/arobi-network
RUN chmod +x /usr/local/bin/arobi-network

USER arobi
WORKDIR /home/arobi

# Note: persistent storage is configured via railway.toml [volumes] persist = true
ENV RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/api/v1/info || exit 1

ENTRYPOINT ["arobi-network"]
CMD ["start", "--data-dir", "/home/arobi/.arobi", "--no-mine"]
