# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev build-essential && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
COPY config ./config
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/manticore-sentinel /usr/local/bin/manticore-sentinel
ENV MANTICORE_OBS_HTTP_ENABLED=true
ENV MANTICORE_OBS_HTTP_BIND=0.0.0.0
ENV MANTICORE_STORE_PATH=/var/lib/manticore/sentinel.sqlite
ENV MANTICORE_EVENT_STREAM_ENABLED=true
WORKDIR /var/lib/manticore
EXPOSE 9462 9463
CMD ["manticore-sentinel", "--headless"]
