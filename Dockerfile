ARG RUST_VERSION=1.90.0
ARG ALPINE_VERSION=3.22
ARG APP_NAME=anzar

# Build stage
FROM rust:${RUST_VERSION}-alpine AS build
ARG APP_NAME
WORKDIR /app

RUN mkdir migrations

RUN apk add --no-cache musl-dev
RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    strip ./target/release/$APP_NAME && \
    cp ./target/release/$APP_NAME /bin/$APP_NAME

RUN echo "appuser:x:10001:10001::/app:/sbin/nologin" > /etc/passwd.minimal && \
    echo "appuser:x:10001:" > /etc/group.minimal

# Execution stage
FROM scratch AS final
ARG APP_NAME=anzar
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd.minimal /etc/passwd
COPY --from=build /etc/group.minimal /etc/group

COPY --from=build /bin/$APP_NAME /bin/$APP_NAME
COPY --chown=10001:10001 configuration /app/configuration

USER 10001:10001

ENV ENV=prod
ENV RUNTIME=docker

EXPOSE 3000
CMD ["/bin/anzar"]
