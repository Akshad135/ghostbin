# ==============================================================================
# Stage 1: Build the Vite frontend
# ==============================================================================
FROM node:22-alpine AS frontend-builder
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
FROM rust:alpine AS backend-builder
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
    cargo build --release && \
    cp /app/target/release/ghostbin-server /app/ghostbin-server_built

# ==============================================================================
# Stage 3: Final runtime image
# ==============================================================================
FROM alpine:3.19
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
