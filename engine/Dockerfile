FROM rust:1.75-slim as builder

WORKDIR /usr/src/garuda-engine

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release

# Remove dummy main.rs and copy source
RUN rm src/main.rs
COPY src/ ./src/

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy binary from builder stage
COPY --from=builder /usr/src/garuda-engine/target/release/garuda-engine .

# Create non-root user
RUN useradd -r -s /bin/false garuda
USER garuda

EXPOSE 3000

CMD ["./garuda-engine"]