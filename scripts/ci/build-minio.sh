#!/usr/bin/env bash
# Build the exact community MinIO source revision used by the S3 integration tests.
# The historical container repositories no longer serve these images reliably.
set -euo pipefail
case "${1:-}" in
  RELEASE.2025-02-07T23-21-09Z) revision=703f51164d3d0c44af41b0d86075a1f61e4779e7 ;;
  RELEASE.2024-10-13T13-34-11Z) revision=d10bb7e1b667c2df72c394ef1fa52ab4a6802d0f ;;
  *) echo "Unsupported MinIO release" >&2; exit 2 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Build outside the product module; do not modify its go.mod or go.sum.
# Go verifies public module content against its checksum database.
(cd "$work" && GOWORK=off GOTOOLCHAIN=go1.23.6 GOSUMDB=sum.golang.org CGO_ENABLED=0 GOBIN="$work" go install "github.com/minio/minio@$revision")
go version -m "$work/minio"
cat > "$work/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
COPY minio /usr/local/bin/minio
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/minio"]
EOF
docker build --tag "launcher-ci-minio:$1" "$work"
