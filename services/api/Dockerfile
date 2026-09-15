FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache build-base argon2-dev
COPY services/api/go.mod ./go.mod
COPY services/api/cmd ./cmd
COPY services/api/internal ./internal
RUN go build -o /out/neverlauncher-api ./cmd/neverlauncher-api

FROM alpine:3.20
RUN apk add --no-cache postgresql-client libargon2 wget ca-certificates \
    && addgroup -g 10001 neverlauncher \
    && adduser -D -H -u 10001 -G neverlauncher neverlauncher \
    && mkdir -p /var/lib/neverlauncher/storage/current /var/lib/neverlauncher/backups \
    && chown -R 10001:10001 /var/lib/neverlauncher
WORKDIR /app
COPY --from=build /out/neverlauncher-api /usr/local/bin/neverlauncher-api
USER neverlauncher
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD wget -q -O - http://127.0.0.1:8080/ready || exit 1
ENTRYPOINT ["neverlauncher-api"]
