# ==============================================================================
# Stage 1: Build the Vite frontend
# ==============================================================================
# Base images are pinned by multi-arch manifest digest for reproducible
# builds. Bump by pulling the new tag and updating the digest (keep the
# human-readable version in the comment):
#   node 22.23.4, rust 1.99.1, alpine 3.22.7
FROM docker.io/library/node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS frontend-builder
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/root/.npm,id=npm-${TARGETPLATFORM} \
    npm ci || npm install

# Copy source code and build
COPY . .
RUN npm run build

# ==============================================================================
# Stage 2: Build the Rust backend
# ==============================================================================
FROM docker.io/library/rust:alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS backend-builder
WORKDIR /app

# Install dependencies for sqlx and compilation
RUN apk add --no-cache musl-dev sqlite-dev pkgconfig

ARG TARGETPLATFORM

# Pre-build the dependency graph into this layer. CI builders are
# ephemeral, so cache mounts do not survive between runs — dependency
# caching there relies on layer caching, which only hits while this
# layer stays unchanged (i.e. Cargo.toml/Cargo.lock did not change).
COPY Cargo.toml Cargo.lock* ./
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    mkdir -p src-rust && \
    echo 'fn main() {}' > src-rust/main.rs && \
    cargo build --release --locked && \
    rm -rf src-rust

# Copy the real sources and rebuild — only the crate itself recompiles.
# (No /app/target cache mount here: it would shadow the pre-built
# dependencies baked into the layer above.)
COPY src-rust ./src-rust
COPY schema.sql ./
# BuildKit COPY preserves context mtimes, which predate the dummy build
# above — cargo's mtime fingerprints then treat the real sources as
# unchanged and this step becomes a silent no-op that ships the dummy
# binary (seen in CI 2026-10-23). Refresh mtimes and drop the crate's
# fingerprints so this build always recompiles the crate.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    find src-rust schema.sql -exec touch {} + && \
    rm -rf target/release/.fingerprint/ghostbin[-_]server* && \
    cargo build --release --locked && \
    cp /app/target/release/ghostbin-server /app/ghostbin-server_built

# ==============================================================================
# Stage 3: Final runtime image
# ==============================================================================
FROM docker.io/library/alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
WORKDIR /app

RUN apk add --no-cache sqlite-libs libgcc

# Create directory for sqlite database
RUN mkdir -p /app/data && chown -R 1000:1000 /app/data

# Copy the built backend binary
COPY --from=backend-builder /app/ghostbin-server_built /app/ghostbin-server

# Copy the built frontend static files
COPY --from=frontend-builder /app/dist /app/dist

# Ensure the executable has permissions
RUN chmod +x /app/ghostbin-server

# Set environment variables
ENV BIND_ADDR=0.0.0.0
ENV PORT=8788
ENV DATABASE_PATH=./data/ghostbin.sqlite
ENV UPLOADS_DIR=./data/uploads
ENV RUST_LOG=info
ENV MAX_TEXT_SIZE=524288
ENV MAX_FILE_SIZE=52428800

EXPOSE 8788

# Switch to a non-root user for security
USER 1000:1000

CMD ["/app/ghostbin-server"]
