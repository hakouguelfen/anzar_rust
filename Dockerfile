ARG RUST_VERSION=1.81.0
ARG APP_NAME=anzar

FROM rust:${RUST_VERSION}-alpine AS build
ARG APP_NAME
WORKDIR /app

RUN apk add --no-cache musl-dev
# COPY configuration.yaml /app/configuration.yaml
# COPY .env /app/.env
RUN --mount=type=bind,source=src,target=src \
    # --mount=type=bind,source=configuration.yaml,target=configuration.yaml \
    # --mount=type=bind,source=.env,target=.env \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    cp ./target/release/$APP_NAME /bin/server

# Final stage
FROM alpine:latest AS final
RUN apk --no-cache add ca-certificates

ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

USER appuser
COPY --from=build /bin/server /bin/
# COPY --from=build /app/configuration.yaml /app/configuration.yaml
# COPY --from=build /app/.env /app/.env
# WORKDIR /app

EXPOSE 3000
CMD ["/bin/server"]
