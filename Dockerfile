# Build Stage
FROM rust:1.75-bookworm AS builder

WORKDIR /usr/src/jsnabber

# Install dependencies for rquickjs
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire workspace
COPY . .

# Build the server in release mode
RUN cargo build --release --package jsnabber-server

# Runtime Stage
FROM debian:bookworm-slim

WORKDIR /usr/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/jsnabber/target/release/jsnabber-server /usr/local/bin/jsnabber-server

# Copy static assets
COPY public ./public

# Expose the server port
EXPOSE 3000

# Set the environment variable for logging (optional)
ENV RUST_LOG=info

# Run the server
CMD ["jsnabber-server"]
