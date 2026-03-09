# Lightweight builder image
FROM rust:1.87 as builder
WORKDIR /app
COPY Cargo.toml .
COPY src ./src
COPY policies ./policies
COPY templates ./templates
RUN cargo build --release

FROM debian:stable-slim
WORKDIR /app
RUN useradd -m appuser
COPY --from=builder /app/target/release/handshaker /usr/local/bin/handshaker
USER appuser
ENTRYPOINT ["handshaker"]
