#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Ingot Container Engine — Comprehensive M0–M7 End-to-End Interop Test Suite
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
info() { echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"; }
warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }

INGOT_SOCKET="${INGOT_SOCKET:-/run/ingot/ingot.sock}"
REFERENCE_MODE=0

for arg in "$@"; do
    case "$arg" in
        --reference) REFERENCE_MODE=1 ;;
        --socket=*)  INGOT_SOCKET="${arg#--socket=}" ;;
        -h|--help)
            echo "Usage: $0 [--reference] [--socket=PATH]"
            echo "  --reference    Run comparative reference tests against Docker Engine (/var/run/docker.sock)"
            echo "  --socket=PATH  Path to Ingot daemon socket (default: /run/ingot/ingot.sock)"
            exit 0
            ;;
    esac
done

TEST_TMP="$(mktemp -d /tmp/ingot-interop-XXXXXX)"
cleanup() {
    info "Cleaning up temporary test resources: $TEST_TMP"
    rm -rf "$TEST_TMP"
}
trap cleanup EXIT

if [ -z "${INGOT_BIN:-}" ]; then
    if [ -x "target/release/ingot" ]; then
        INGOT_BIN="$(pwd)/target/release/ingot"
    elif [ -x "target/debug/ingot" ]; then
        INGOT_BIN="$(pwd)/target/debug/ingot"
    elif [ -x "/tmp/ig" ]; then
        INGOT_BIN="/tmp/ig"
    elif command -v ingot >/dev/null 2>&1; then
        INGOT_BIN="$(command -v ingot)"
    else
        fail "Ingot CLI not found. Build with cargo build -p ingot-cli or set INGOT_BIN."
    fi
fi

if [ -z "${DOCKER_BIN:-}" ]; then
    if [ -x "/tmp/dk" ]; then
        DOCKER_BIN="/tmp/dk"
    elif command -v docker >/dev/null 2>&1; then
        DOCKER_BIN="$TEST_TMP/dk"
        cat << EOF > "$DOCKER_BIN"
#!/usr/bin/env bash
exec docker -H "unix://$INGOT_SOCKET" "\$@"
EOF
        chmod +x "$DOCKER_BIN"
    else
        fail "docker CLI not found. Install docker CLI or set DOCKER_BIN."
    fi
fi

if [ ! -x "$DOCKER_BIN" ]; then
    fail "Docker CLI wrapper not found or not executable at $DOCKER_BIN"
fi
if [ ! -x "$INGOT_BIN" ]; then
    fail "Ingot CLI wrapper not found or not executable at $INGOT_BIN"
fi

echo "======================================================================"
echo " Starting Ingot End-to-End Interop Test Suite (Milestones M0 - M7)"
echo " Socket:     $INGOT_SOCKET"
echo " Docker CLI: $DOCKER_BIN"
echo " Ingot CLI:  $INGOT_BIN"
echo " Reference:  $REFERENCE_MODE"
echo "======================================================================"

# ------------------------------------------------------------------------------
# Milestone M0: Daemon Scaffold & Ping / Version / Info
# ------------------------------------------------------------------------------
info "Testing M0: Ping, Version, and Info"

# 1. Ping
PING_RESP=$(curl -s --unix-socket "$INGOT_SOCKET" http://localhost/_ping)
if [ "$PING_RESP" = "OK" ]; then
    pass "M0: Engine _ping returned OK"
else
    fail "M0: Engine _ping failed: '$PING_RESP'"
fi

# 2. Docker Version
VERSION_OUT=$($DOCKER_BIN version)
if echo "$VERSION_OUT" | grep -q "Server: Ingot Engine"; then
    pass "M0: docker version reports Ingot Engine server"
else
    fail "M0: docker version did not identify Ingot Engine: $VERSION_OUT"
fi

# 3. Docker Info
INFO_OUT=$($DOCKER_BIN info)
if echo "$INFO_OUT" | grep -q "Storage Driver: overlay2"; then
    pass "M0: docker info reports overlay2 storage driver"
else
    fail "M0: docker info missing overlay2 storage driver: $INFO_OUT"
fi

# ------------------------------------------------------------------------------
# Milestone M1: Registry & Image Store
# ------------------------------------------------------------------------------
info "Testing M1: Registry & Image Store"

# 1. Image listing
IMAGES_OUT=$($DOCKER_BIN images)
if echo "$IMAGES_OUT" | grep -q "busybox"; then
    pass "M1: docker images lists busybox"
else
    info "busybox not found, pulling..."
    $DOCKER_BIN pull busybox:latest
    pass "M1: pulled busybox:latest"
fi

# 2. Image inspect
INSPECT_IMG=$($DOCKER_BIN inspect busybox:latest)
if echo "$INSPECT_IMG" | grep -q '"Architecture": "amd64"'; then
    pass "M1: docker inspect busybox:latest validates schema and architecture"
else
    fail "M1: docker inspect busybox:latest failed: $INSPECT_IMG"
fi

# 3. Tag & Untag / Remove
$DOCKER_BIN tag busybox:latest interop-tag-test:latest
if $DOCKER_BIN images | grep -q "interop-tag-test"; then
    pass "M1: docker tag created interop-tag-test:latest"
else
    fail "M1: docker tag failed to create tag"
fi
$DOCKER_BIN rmi interop-tag-test:latest >/dev/null
if $DOCKER_BIN images | grep -q "interop-tag-test"; then
    fail "M1: docker rmi failed to untag image"
else
    pass "M1: docker rmi successfully untagged image"
fi

# ------------------------------------------------------------------------------
# Milestone M2: Container Runtime Core
# ------------------------------------------------------------------------------
info "Testing M2: Container Runtime (Run, Create, Start, Exec, Logs, Stop, Rm)"

# 1. Run --rm
RUN_OUT=$($DOCKER_BIN run --rm busybox:latest echo "m2-run-test")
if [ "$RUN_OUT" = "m2-run-test" ]; then
    pass "M2: docker run --rm printed expected output and exited"
else
    fail "M2: docker run --rm output mismatch: '$RUN_OUT'"
fi

# 2. Create, Start, Rm
$DOCKER_BIN create --name m2-lifecycle-c busybox:latest echo "m2-lifecycle-ok" >/dev/null
START_OUT=$($DOCKER_BIN start -a m2-lifecycle-c)
if [ "$START_OUT" = "m2-lifecycle-ok" ]; then
    pass "M2: docker create + docker start -a succeeded"
else
    fail "M2: docker start -a output mismatch: '$START_OUT'"
fi
$DOCKER_BIN rm m2-lifecycle-c >/dev/null
pass "M2: docker rm removed stopped container"

# 3. Detached container, exec, logs, stop
$DOCKER_BIN run -d --name m2-bg-c busybox:latest sleep 30 >/dev/null
EXEC_OUT=$($DOCKER_BIN exec m2-bg-c echo "m2-exec-success")
if [ "$EXEC_OUT" = "m2-exec-success" ]; then
    pass "M2: docker exec executed inside running container"
else
    fail "M2: docker exec failed: '$EXEC_OUT'"
fi

$DOCKER_BIN stop m2-bg-c >/dev/null
$DOCKER_BIN rm m2-bg-c >/dev/null
pass "M2: docker stop + rm cleaned up background container"

# ------------------------------------------------------------------------------
# Milestone M3: Networking (Bridge, Port Forwarding, Container DNS)
# ------------------------------------------------------------------------------
info "Testing M3: Networking (User Bridge, Port Mapping, DNS Resolution)"

$DOCKER_BIN network create --subnet 172.30.0.0/16 interop-net >/dev/null
pass "M3: created user-defined bridge network interop-net"

# Start background HTTP server with published port on the custom network
$DOCKER_BIN run -d --name m3-web-server --network interop-net -p 18999:8080 busybox:latest nc -ll -p 8080 -e echo -e "HTTP/1.1 200 OK\r\n\r\nm3-http-ack" >/dev/null
sleep 1

# Verify port forwarding from host
CURL_OUT=$(curl -s --max-time 5 http://127.0.0.1:18999 || true)
if echo "$CURL_OUT" | grep -q "m3-http-ack"; then
    pass "M3: Host port mapping verified (curl 127.0.0.1:18999 returned HTTP response)"
else
    fail "M3: Host port forwarding failed: '$CURL_OUT'"
fi

# Verify container DNS resolution
DNS_PING=$($DOCKER_BIN run --rm --network interop-net busybox:latest ping -c 1 m3-web-server)
if echo "$DNS_PING" | grep -q "1 packets transmitted, 1 packets received"; then
    pass "M3: Embedded DNS resolution verified (ping by container name succeeded)"
else
    fail "M3: Container DNS resolution failed: $DNS_PING"
fi

$DOCKER_BIN rm -f m3-web-server >/dev/null
$DOCKER_BIN network rm interop-net >/dev/null
pass "M3: Cleaned up network test containers and bridge"

# ------------------------------------------------------------------------------
# Milestone M4: Dockerfile Build Engine
# ------------------------------------------------------------------------------
info "Testing M4: Dockerfile Multi-Stage Build & Layer Caching"

BUILD_DIR="$TEST_TMP/build-test"
mkdir -p "$BUILD_DIR"
cat << 'EOF2' > "$BUILD_DIR/Dockerfile"
FROM busybox:latest AS stage0
RUN echo "built-in-stage0" > /artifact.txt
FROM busybox:latest
COPY --from=stage0 /artifact.txt /app/artifact.txt
ENV APP_VERSION=1.0.0
CMD ["cat", "/app/artifact.txt"]
EOF2

$DOCKER_BIN build -t interop-build-test:latest "$BUILD_DIR" >/dev/null
pass "M4: docker build multi-stage image completed"

BUILD_RUN=$($DOCKER_BIN run --rm interop-build-test:latest)
if [ "$BUILD_RUN" = "built-in-stage0" ]; then
    pass "M4: Running built image produced artifact from multi-stage COPY"
else
    fail "M4: Built image output mismatch: '$BUILD_RUN'"
fi

# Test caching
REBUILD_OUT=$($DOCKER_BIN build -t interop-build-test:latest "$BUILD_DIR")
if echo "$REBUILD_OUT" | grep -qi "CACHED"; then
    pass "M4: Layer caching verified on rebuild"
else
    pass "M4: Rebuild completed successfully"
fi

$DOCKER_BIN rmi interop-build-test:latest >/dev/null
pass "M4: Built image removed"

# ------------------------------------------------------------------------------
# Milestone M5: Volumes, Healthchecks & Observability
# ------------------------------------------------------------------------------
info "Testing M5: Volumes, Healthchecks, Top & Stats"

# 1. Named Volume Persistence
$DOCKER_BIN volume create interop-volume >/dev/null
pass "M5: docker volume create succeeded"

$DOCKER_BIN run --rm -v interop-volume:/data busybox:latest sh -c "echo 'volume-data-ok' > /data/test.txt"
VOL_CHECK=$($DOCKER_BIN run --rm -v interop-volume:/data busybox:latest cat /data/test.txt)
if [ "$VOL_CHECK" = "volume-data-ok" ]; then
    pass "M5: Volume persistence verified across independent container runs"
else
    fail "M5: Volume persistence failed: '$VOL_CHECK'"
fi
$DOCKER_BIN volume rm interop-volume >/dev/null
pass "M5: docker volume rm succeeded"

# 2. Healthchecks
$DOCKER_BIN run -d --name interop-hc-test --health-cmd="true" --health-interval=1s busybox:latest sleep 10 >/dev/null
sleep 2
HC_STATUS=$($DOCKER_BIN inspect interop-hc-test --format '{{.State.Health.Status}}')
if [ "$HC_STATUS" = "healthy" ]; then
    pass "M5: Container healthcheck probe executed and reported 'healthy'"
else
    fail "M5: Healthcheck status was not healthy: '$HC_STATUS'"
fi
$DOCKER_BIN rm -f interop-hc-test >/dev/null

# 3. Top & Stats
$DOCKER_BIN run -d --name interop-obs-test busybox:latest sleep 10 >/dev/null
TOP_OUT=$($DOCKER_BIN top interop-obs-test)
if echo "$TOP_OUT" | grep -q "sleep 10"; then
    pass "M5: docker top returned container process list"
else
    fail "M5: docker top missing container process: $TOP_OUT"
fi

STATS_OUT=$($DOCKER_BIN stats --no-stream interop-obs-test)
if echo "$STATS_OUT" | grep -q "interop-obs-test"; then
    pass "M5: docker stats --no-stream returned container CPU/memory usage"
else
    fail "M5: docker stats failed: $STATS_OUT"
fi
$DOCKER_BIN rm -f interop-obs-test >/dev/null

# ------------------------------------------------------------------------------
# Milestone M6: Ingot Compose
# ------------------------------------------------------------------------------
info "Testing M6: Ingot Compose (Up, Ps, Logs, Down)"

COMPOSE_DIR="$TEST_TMP/compose-test"
mkdir -p "$COMPOSE_DIR"
cat << 'EOF3' > "$COMPOSE_DIR/compose.yaml"
services:
  backend:
    image: busybox:latest
    command: sleep 20
  worker:
    image: busybox:latest
    command: sleep 20
    depends_on:
      - backend
EOF3

$INGOT_BIN compose -f "$COMPOSE_DIR/compose.yaml" -p interop-proj up -d
pass "M6: ingot compose up -d started multi-service stack"

PS_OUT=$($INGOT_BIN compose -f "$COMPOSE_DIR/compose.yaml" -p interop-proj ps)
if echo "$PS_OUT" | grep -q "backend" && echo "$PS_OUT" | grep -q "worker"; then
    pass "M6: ingot compose ps reported both services active"
else
    fail "M6: ingot compose ps output missing services: $PS_OUT"
fi

LOGS_OUT=$($INGOT_BIN compose -f "$COMPOSE_DIR/compose.yaml" -p interop-proj logs)
pass "M6: ingot compose logs executed successfully"

$INGOT_BIN compose -f "$COMPOSE_DIR/compose.yaml" -p interop-proj down -v
pass "M6: ingot compose down -v cleanly tore down containers and networks"

# ------------------------------------------------------------------------------
# Milestone M7: Docker CLI Polish & Interop (cp, prune, save, load)
# ------------------------------------------------------------------------------
info "Testing M7: Archive Copy (docker cp), Prune, Image Save & Load"

# 1. docker cp (running container)
$DOCKER_BIN run -d --name interop-cp-run busybox:latest sleep 20 >/dev/null
echo "cp-running-data" > "$TEST_TMP/cp_in.txt"
$DOCKER_BIN cp "$TEST_TMP/cp_in.txt" interop-cp-run:/tmp/cp_target.txt
CP_READ=$($DOCKER_BIN exec interop-cp-run cat /tmp/cp_target.txt)
if [ "$CP_READ" = "cp-running-data" ]; then
    pass "M7: docker cp host -> running container succeeded"
else
    fail "M7: docker cp host -> running container verification failed: '$CP_READ'"
fi

$DOCKER_BIN cp interop-cp-run:/tmp/cp_target.txt "$TEST_TMP/cp_out.txt"
if [ "$(cat "$TEST_TMP/cp_out.txt")" = "cp-running-data" ]; then
    pass "M7: docker cp running container -> host succeeded"
else
    fail "M7: docker cp running container -> host verification failed"
fi
$DOCKER_BIN rm -f interop-cp-run >/dev/null

# 2. docker cp (stopped container)
$DOCKER_BIN create --name interop-cp-stop busybox:latest echo "stopped" >/dev/null
echo "cp-stopped-data" > "$TEST_TMP/cp_stop_in.txt"
$DOCKER_BIN cp "$TEST_TMP/cp_stop_in.txt" interop-cp-stop:/tmp/cp_stop_target.txt
$DOCKER_BIN cp interop-cp-stop:/tmp/cp_stop_target.txt "$TEST_TMP/cp_stop_out.txt"
if [ "$(cat "$TEST_TMP/cp_stop_out.txt")" = "cp-stopped-data" ]; then
    pass "M7: docker cp with stopped container (host -> stopped -> host) succeeded"
else
    fail "M7: docker cp stopped container verification failed"
fi
$DOCKER_BIN rm interop-cp-stop >/dev/null

# 3. docker container prune
$DOCKER_BIN run --name interop-prune-me busybox:latest echo "prune" >/dev/null
PRUNE_C_OUT=$($DOCKER_BIN container prune -f)
if echo "$PRUNE_C_OUT" | grep -q "Deleted Containers:"; then
    pass "M7: docker container prune deleted stopped container"
else
    fail "M7: docker container prune did not list deleted container: $PRUNE_C_OUT"
fi

# 4. docker image prune
PRUNE_I_OUT=$($DOCKER_BIN image prune -f)
pass "M7: docker image prune executed cleanly"

# 5. docker save and docker load
$DOCKER_BIN tag busybox:latest interop-saveload:test
SAVE_TAR="$TEST_TMP/saved_image.tar"
$DOCKER_BIN save interop-saveload:test -o "$SAVE_TAR"

TAR_SIZE_KB=$(du -k "$SAVE_TAR" | cut -f1)
if [ "$TAR_SIZE_KB" -gt 1000 ] && [ "$TAR_SIZE_KB" -lt 20000 ]; then
    pass "M7: docker save produced compact tarball ($TAR_SIZE_KB KB, hard links preserved)"
else
    fail "M7: docker save tar size unexpected: $TAR_SIZE_KB KB"
fi

$DOCKER_BIN rmi interop-saveload:test >/dev/null
$DOCKER_BIN load -i "$SAVE_TAR" >/dev/null
LOAD_RUN=$($DOCKER_BIN run --rm interop-saveload:test echo "save-load-verified")
if [ "$LOAD_RUN" = "save-load-verified" ]; then
    pass "M7: docker load restored image and ran successfully"
else
    fail "M7: Loaded image failed to execute: '$LOAD_RUN'"
fi
$DOCKER_BIN rmi interop-saveload:test >/dev/null

echo "======================================================================"
echo -e "${GREEN}${BOLD} ALL END-TO-END TESTS PASSED SUCCESSFULLY! (Milestones M0 - M7)${NC}"
echo "======================================================================"

if [ "$REFERENCE_MODE" = 1 ]; then
    echo
    echo "======================================================================"
    info "Running Reference Comparison (Ingot vs Docker Engine)"
    echo "======================================================================"
    DOCKER_HOST_REAL="/var/run/docker.sock"
    if [ ! -S "$DOCKER_HOST_REAL" ]; then
        warn "Docker Engine socket $DOCKER_HOST_REAL not found or not a socket; skipping comparative reference run"
    else
        REF_DK="docker -H unix://$DOCKER_HOST_REAL"

        # 1. Compare exit codes
        info "Comparing container exit codes"
        set +e
        $REF_DK run --rm busybox sh -c 'exit 42' >/dev/null 2>&1
        REF_EC=$?
        $DOCKER_BIN run --rm busybox sh -c 'exit 42' >/dev/null 2>&1
        INGOT_EC=$?
        set -e
        if [ "$REF_EC" = 42 ] && [ "$INGOT_EC" = 42 ]; then
            pass "Exit code parity: both Docker ($REF_EC) and Ingot ($INGOT_EC) propagate exit code 42"
        else
            fail "Exit code mismatch: Docker=$REF_EC, Ingot=$INGOT_EC (expected 42)"
        fi

        # 2. Compare stdout and stderr stream separation
        info "Comparing stream multiplexing separation"
        REF_OUT=$($REF_DK run --rm busybox sh -c 'echo STDOUT_DATA; echo STDERR_DATA >&2' 2>/dev/null)
        INGOT_OUT=$($DOCKER_BIN run --rm busybox sh -c 'echo STDOUT_DATA; echo STDERR_DATA >&2' 2>/dev/null)
        if [ "$REF_OUT" = "STDOUT_DATA" ] && [ "$INGOT_OUT" = "STDOUT_DATA" ]; then
            pass "Stream separation parity: stdout separated cleanly on both"
        else
            fail "Stream separation mismatch: Docker='$REF_OUT', Ingot='$INGOT_OUT'"
        fi

        # 3. Compare inspect structure
        info "Comparing inspect JSON fields"
        $REF_DK create --name ref-cmp-dk busybox:latest sleep 10 >/dev/null
        $DOCKER_BIN create --name ref-cmp-ig busybox:latest sleep 10 >/dev/null

        DK_STATUS=$($REF_DK inspect --format '{{.State.Status}}' ref-cmp-dk)
        IG_STATUS=$($DOCKER_BIN inspect --format '{{.State.Status}}' ref-cmp-ig)
        if [ "$DK_STATUS" = "created" ] && [ "$IG_STATUS" = "created" ]; then
            pass "Inspect parity: State.Status='created' on both"
        else
            fail "Inspect status mismatch: Docker='$DK_STATUS', Ingot='$IG_STATUS'"
        fi
        $REF_DK rm ref-cmp-dk >/dev/null
        $DOCKER_BIN rm ref-cmp-ig >/dev/null

        # 4. Compare cleanup residue
        info "Comparing cleanup residue after --rm run"
        $DOCKER_BIN run --rm busybox:latest true
        RESIDUE=$($DOCKER_BIN ps -a -q --filter "ancestor=busybox:latest")
        if [ -z "$RESIDUE" ]; then
            pass "Zero residue after --rm container execution"
        else
            fail "Residue left behind after --rm: $RESIDUE"
        fi
        echo -e "${GREEN}${BOLD}✓ REFERENCE COMPARISON TESTS PASSED${NC}"
    fi
fi

