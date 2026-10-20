FROM rust:1.93-bookworm AS builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p the-standard-service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 the-standard
COPY --from=builder /workspace/target/release/the-standard-service /usr/local/bin/the-standard-service
COPY the-standard.toml /etc/the-standard/the-standard.toml
ENV THE_STANDARD_CONFIG_FILE=/etc/the-standard/the-standard.toml
USER the-standard
EXPOSE 8081
ENTRYPOINT ["the-standard-service"]
