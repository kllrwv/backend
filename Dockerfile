# syntax=docker/dockerfile:1
FROM rust:1.100.0-slim-bookworm AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock translations.json ./
COPY src ./src
COPY migrations ./migrations

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked \
    && install -m 0755 target/release/killerwave-api /usr/local/bin/killerwave-api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /usr/local/bin/killerwave-api /usr/local/bin/killerwave-api

USER 10001:10001
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/killerwave-api"]
