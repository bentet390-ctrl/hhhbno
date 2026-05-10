# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /app

# Install dependencies untuk build (openssl dll)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifest dulu biar layer cache optimal
COPY Cargo.toml Cargo.lock* ./

# Dummy build untuk cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm src/main.rs

# Copy source asli dan build
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/rpow2-miner .

CMD ["./rpow2-miner"]
