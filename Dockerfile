# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS daemon-build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY plugins ./plugins

RUN CGO_ENABLED=1 GOOS=linux go build -trimpath \
    -tags "sqlite_omit_load_extension" \
    -ldflags '-s -w -extldflags "-static"' \
    -o /out/weaveftpd ./cmd/weaveftpd

FROM golang:1.25-alpine AS sitebot-build
WORKDIR /src/sitebot

COPY sitebot/go.mod sitebot/go.sum ./
RUN go mod download

COPY sitebot ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags '-s -w' \
    -o /out/sitebot ./cmd

FROM alpine:3.21 AS daemon
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S weaveftpd \
    && adduser -S -G weaveftpd weaveftpd
LABEL org.opencontainers.image.source="https://github.com/WeaveFTPd/WeaveFTPd" \
      org.opencontainers.image.description="WeaveFTPd master or slave daemon (selected by configuration)"
WORKDIR /app
COPY --from=daemon-build /out/weaveftpd /usr/local/bin/weaveftpd

# Config, users, site data and logs are bind-mounted at runtime.
USER weaveftpd
ENTRYPOINT ["weaveftpd"]
CMD ["--config", "/app/etc/config.yml"]

FROM alpine:3.21 AS sitebot
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S weaveftpd \
    && adduser -S -G weaveftpd weaveftpd
LABEL org.opencontainers.image.source="https://github.com/WeaveFTPd/WeaveFTPd" \
      org.opencontainers.image.description="WeaveFTPd IRC sitebot"
WORKDIR /app/sitebot
COPY --from=sitebot-build /out/sitebot /usr/local/bin/sitebot

# The whole sitebot directory is bind-mounted so plugin configs and templates
# stay editable without rebuilding the image.
USER weaveftpd
ENTRYPOINT ["sitebot"]
CMD ["--config", "/app/sitebot/etc/config.yml"]
