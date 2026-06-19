FROM rust:1.85-alpine AS builder

WORKDIR /app

RUN apk add --no-cache musl-dev openssl-dev perl make gcc

COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch || true

COPY . .
RUN cargo build --release

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata openssl

WORKDIR /app

COPY --from=builder /app/target/release/cert-monitor /usr/local/bin/cert-monitor

VOLUME ["/root/.cert-monitor"]

ENTRYPOINT ["/usr/local/bin/cert-monitor"]
CMD ["--help"]
