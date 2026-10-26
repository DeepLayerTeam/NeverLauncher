FROM golang:1.27.3-alpine AS factory-cli
WORKDIR /factory-src
COPY cli/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/neverlauncher ./cmd/neverlauncher

FROM golang:1.27.3-alpine AS build
WORKDIR /src
ARG NEVERLAUNCHER_VERSION=dev
ARG NEVERLAUNCHER_SOURCE_COMMIT=unknown
RUN apk add --no-cache build-base argon2-dev
COPY services/api/go.mod services/api/go.sum ./
RUN go mod download
COPY services/api/cmd ./cmd
COPY services/api/internal ./internal
COPY services/api/pkg ./pkg
RUN go build -trimpath -ldflags="-s -w -X main.version=${NEVERLAUNCHER_VERSION} -X main.commit=${NEVERLAUNCHER_SOURCE_COMMIT}" -o /out/neverlauncher-api ./cmd/neverlauncher-api \
    && go build -trimpath -o /out/neverlauncher-sqlite ./cmd/neverlauncher-sqlite

FROM alpine:3.20
RUN apk add --no-cache postgresql-client argon2-libs wget ca-certificates openjdk21-jre-headless \
    && addgroup -g 10001 neverlauncher \
    && adduser -D -H -u 10001 -G neverlauncher neverlauncher \
    && mkdir -p /var/lib/neverlauncher/storage/current /var/lib/neverlauncher/backups /var/lib/neverlauncher/factory \
    && chown -R 10001:10001 /var/lib/neverlauncher
WORKDIR /app
COPY --from=build /out/neverlauncher-api /usr/local/bin/neverlauncher-api
COPY --from=build /out/neverlauncher-sqlite /usr/local/bin/neverlauncher-sqlite
COPY --from=factory-cli /out/neverlauncher /usr/local/bin/neverlauncher
ENV NEVERLAUNCHER_FACTORY_CLI=/usr/local/bin/neverlauncher
ENV NEVERLAUNCHER_FACTORY_ROOT=/var/lib/neverlauncher/factory
USER neverlauncher
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD wget -q -O - http://127.0.0.1:8080/ready || exit 1
ENTRYPOINT ["neverlauncher-api"]
