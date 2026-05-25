#!/usr/bin/env bash
set -euo pipefail

# NeoFS AIO integration harness
#
# Lifecycle under test (requires NEOFS_AIO=1):
#   1. dial gRPC endpoint
#   2. networkInfo -> current epoch
#   3. container create (Put)
#   4. session create -> object put -> object get (verify payload)
#   5. object delete
#   6. container delete
#
# Environment:
#   NEOFS_AIO_IMAGE  docker image (default: nspccdev/neofs-aio:latest)
#   NEOFS_AIO_PORT   host port mapped to container 8080 (default: 8080)
#   NEOFS_ENDPOINT   gRPC URI (default: grpc://localhost:${NEOFS_AIO_PORT})
#   NEOFS_WIF        signer WIF (default: neofs-aio test account)
#   NEOFS_AIO=1      required by test/integration/lifecycle.zig

echo "Starting NeoFS AIO integration check"
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for integration tests" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER_NAME="neofs-sdk-zig-aio-${RANDOM}${RANDOM}"
IMAGE="${NEOFS_AIO_IMAGE:-nspccdev/neofs-aio:latest}"
HOST_PORT="${NEOFS_AIO_PORT:-8080}"
DEFAULT_WIF="KxyjQ8eUa4FHt3Gvioyt1Wz29cTUrE4eTqX3yFSk1YFCsPL8uNsY"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Pulling ${IMAGE}"
docker pull "${IMAGE}" >/dev/null

echo "Starting ${CONTAINER_NAME} on localhost:${HOST_PORT}"
docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${HOST_PORT}:8080" \
  "${IMAGE}" >/dev/null

echo "Waiting for gRPC endpoint to come up..."
for _ in $(seq 1 90); do
  if docker logs "${CONTAINER_NAME}" 2>&1 | rg -q "aio container started"; then
    break
  fi
  sleep 2
done

if ! docker logs "${CONTAINER_NAME}" 2>&1 | rg -q "aio container started"; then
  echo "AIO startup marker was not observed" >&2
  docker logs "${CONTAINER_NAME}" >&2 || true
  exit 1
fi

cd "${ROOT_DIR}"

echo "Running SDK dial smoke test"
zig build -Dexample=client_dial run

export NEOFS_AIO=1
export NEOFS_ENDPOINT="${NEOFS_ENDPOINT:-grpc://localhost:${HOST_PORT}}"
export NEOFS_WIF="${NEOFS_WIF:-${DEFAULT_WIF}}"

echo "Running container/object lifecycle against ${NEOFS_ENDPOINT}"
zig build -Dexample=aio_lifecycle run

echo "Integration check passed"
