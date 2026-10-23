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

# Copy Cargo files and source
COPY Cargo.toml Cargo.lock* ./
COPY src-rust ./src-rust
COPY schema.sql ./

# Build release binary
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    --mount=type=cache,target=/app/target,id=cargo-target-${TARGETPLATFORM} \
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
