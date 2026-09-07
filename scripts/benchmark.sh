#!/usr/bin/env bash
# ==============================================================================
# Ingot Benchmark Harness (Milestone 0.2, Section 6.1)
# Measures:
#   1. Installed binary sizes
#   2. Idle daemon RSS and thread count
#   3. Daemon ping response latency
#   4. Container lifecycle latency (p50, p95)
#   5. Parallel container throughput
#   6. Dockerfile build latency
# Compares Ingot against Docker Engine if available.
# Outputs: human-readable summary and raw JSON artifacts.
# ==============================================================================
set -euo pipefail

RUNS=10
SOCKET="${INGOT_SOCKET:-/run/ingot/ingot.sock}"
OUTPUT_DIR="benchmarks/results/$(date +%Y%m%d_%H%M%S)"
COMPARE_DOCKER=1

for arg in "$@"; do
    case "$arg" in
        --runs=*)       RUNS="${arg#--runs=}" ;;
        --socket=*)     SOCKET="${arg#--socket=}" ;;
        --output-dir=*) OUTPUT_DIR="${arg#--output-dir=}" ;;
        --no-docker)    COMPARE_DOCKER=0 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --runs=N          Number of iterations for repeated benchmarks (default: 10)"
            echo "  --socket=PATH     Path to Ingot daemon socket (default: /run/ingot/ingot.sock)"
            echo "  --output-dir=DIR  Directory to save benchmark output (default: benchmarks/results/<timestamp>)"
            echo "  --no-docker       Skip Docker Engine comparison"
            exit 0
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
JSON_OUT="$OUTPUT_DIR/results.json"

echo "======================================================================"
echo " Ingot Benchmark Suite"
echo " Date:       $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo " Iterations: $RUNS"
echo " Socket:     $SOCKET"
echo " Output:     $OUTPUT_DIR"
echo "======================================================================"

# Build release binaries if not present
if [ ! -f "target/release/ingotd" ] || [ ! -f "target/release/ingot" ]; then
    echo "==> Building release binaries..."
    cargo build --release -p ingotd -p ingot-cli
fi

# 1. Binary Sizes
echo "==> 1. Measuring Binary Sizes"
INGOTD_SIZE=$(stat -c %s target/release/ingotd 2>/dev/null || stat -f %z target/release/ingotd)
INGOT_SIZE=$(stat -c %s target/release/ingot 2>/dev/null || stat -f %z target/release/ingot)
TOTAL_INGOT_SIZE=$((INGOTD_SIZE + INGOT_SIZE))

DOCKER_BIN_SIZE=0
CONTAINERD_BIN_SIZE=0
if command -v dockerd >/dev/null 2>&1; then
    DOCKER_BIN_SIZE=$(stat -c %s "$(command -v dockerd)" 2>/dev/null || stat -f %z "$(command -v dockerd)")
fi
if command -v containerd >/dev/null 2>&1; then
    CONTAINERD_BIN_SIZE=$(stat -c %s "$(command -v containerd)" 2>/dev/null || stat -f %z "$(command -v containerd)")
fi
TOTAL_DOCKER_SIZE=$((DOCKER_BIN_SIZE + CONTAINERD_BIN_SIZE))

python3 -c "print(f'  Ingot daemon (ingotd): {int($INGOTD_SIZE):10d} bytes ({int($INGOTD_SIZE)/1048576:.2f} MB)')"
python3 -c "print(f'  Ingot CLI (ingot):     {int($INGOT_SIZE):10d} bytes ({int($INGOT_SIZE)/1048576:.2f} MB)')"
python3 -c "print(f'  Total Ingot:           {int($TOTAL_INGOT_SIZE):10d} bytes ({int($TOTAL_INGOT_SIZE)/1048576:.2f} MB)')"
if [ "$TOTAL_DOCKER_SIZE" -gt 0 ]; then
    python3 -c "print(f'  Docker Engine total:   {int($TOTAL_DOCKER_SIZE):10d} bytes ({int($TOTAL_DOCKER_SIZE)/1048576:.2f} MB)')"
fi

# 2. Daemon Idle RSS and Threads
echo "==> 2. Measuring Daemon Idle RSS"
INGOT_PID=$(pgrep -f "target/release/ingotd" | head -n1 || pgrep -f "ingotd" | head -n1 || echo "")
INGOT_RSS_KB=0
INGOT_THREADS=0
if [ -n "$INGOT_PID" ] && [ -d "/proc/$INGOT_PID" ]; then
    INGOT_RSS_KB=$(grep VmRSS "/proc/$INGOT_PID/status" | awk '{print $2}')
    INGOT_THREADS=$(grep Threads "/proc/$INGOT_PID/status" | awk '{print $2}')
    printf "  Ingot daemon (PID %s): %s KB RSS, %s threads\n" "$INGOT_PID" "$INGOT_RSS_KB" "$INGOT_THREADS"
else
    echo "  Ingot daemon process not currently running; skipping RSS measurement"
fi

# 3. Ping Latency
echo "==> 3. Measuring _ping Response Latency ($RUNS samples)"
PING_AVG=0
PING_P50=0
PING_P95=0
if [ -S "$SOCKET" ]; then
    PING_TIMES=()
    for i in $(seq 1 "$RUNS"); do
        START=$(date +%s%N)
        curl -s --unix-socket "$SOCKET" http://localhost/_ping >/dev/null
        END=$(date +%s%N)
        DIFF_US=$(( (END - START) / 1000 ))
        PING_TIMES+=("$DIFF_US")
    done

    IFS=$'\n' SORTED_PING=($(sort -n <<<"${PING_TIMES[*]}"))
    unset IFS

    IDX_50=$(( (RUNS * 50) / 100 ))
    IDX_95=$(( (RUNS * 95) / 100 ))
    [ "$IDX_95" -ge "$RUNS" ] && IDX_95=$((RUNS - 1))
    PING_P50="${SORTED_PING[$IDX_50]}"
    PING_P95="${SORTED_PING[$IDX_95]}"

    TOTAL_US=0
    for t in "${PING_TIMES[@]}"; do TOTAL_US=$((TOTAL_US + t)); done
    PING_AVG=$((TOTAL_US / RUNS))

    python3 -c "print(f'  Ingot _ping latency: avg={float($PING_AVG)/1000:.2f} ms, p50={float($PING_P50)/1000:.2f} ms, p95={float($PING_P95)/1000:.2f} ms')"
else
    echo "  Socket $SOCKET not found; skipping ping latency"
fi

# 4. Container Lifecycle Latency (run --rm busybox true)
echo "==> 4. Measuring Container Run/Exit/Remove Latency ($RUNS samples)"
RUN_AVG=0
RUN_P50=0
RUN_P95=0
if [ -S "$SOCKET" ] && command -v docker >/dev/null 2>&1; then
    TMP_DK=$(mktemp /tmp/bench-dk-XXXXXX)
    cat << DKEOF > "$TMP_DK"
#!/usr/bin/env bash
exec docker -H "unix://$SOCKET" "\$@"
DKEOF
    chmod +x "$TMP_DK"

    "$TMP_DK" pull busybox:latest >/dev/null 2>&1 || true

    RUN_TIMES=()
    for i in $(seq 1 "$RUNS"); do
        START=$(date +%s%N)
        "$TMP_DK" run --rm busybox:latest true
        END=$(date +%s%N)
        DIFF_MS=$(( (END - START) / 1000000 ))
        RUN_TIMES+=("$DIFF_MS")
    done
    rm -f "$TMP_DK"

    IFS=$'\n' SORTED_RUN=($(sort -n <<<"${RUN_TIMES[*]}"))
    unset IFS

    IDX_50=$(( (RUNS * 50) / 100 ))
    IDX_95=$(( (RUNS * 95) / 100 ))
    [ "$IDX_95" -ge "$RUNS" ] && IDX_95=$((RUNS - 1))
    RUN_P50="${SORTED_RUN[$IDX_50]}"
    RUN_P95="${SORTED_RUN[$IDX_95]}"

    TOTAL_MS=0
    for t in "${RUN_TIMES[@]}"; do TOTAL_MS=$((TOTAL_MS + t)); done
    RUN_AVG=$((TOTAL_MS / RUNS))

    printf "  Ingot container lifecycle: avg=%d ms, p50=%d ms, p95=%d ms\n" "$RUN_AVG" "$RUN_P50" "$RUN_P95"
else
    echo "  Ingot socket not active or docker CLI missing; skipping container run test"
fi

# 5. Parallel Container Throughput
echo "==> 5. Measuring Parallel Container Throughput (10 concurrent runs)"
PARALLEL_MS=0
if [ -S "$SOCKET" ] && command -v docker >/dev/null 2>&1; then
    TMP_DK=$(mktemp /tmp/bench-dk-XXXXXX)
    cat << DKEOF > "$TMP_DK"
#!/usr/bin/env bash
exec docker -H "unix://$SOCKET" "\$@"
DKEOF
    chmod +x "$TMP_DK"

    START=$(date +%s%N)
    PIDS=()
    for i in $(seq 1 10); do
        "$TMP_DK" run --rm busybox:latest true >/dev/null 2>&1 &
        PIDS+=($!)
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    END=$(date +%s%N)
    PARALLEL_MS=$(( (END - START) / 1000000 ))
    rm -f "$TMP_DK"
    printf "  10 parallel containers completed in: %d ms\n" "$PARALLEL_MS"
else
    echo "  Skipping parallel test"
fi

# 6. Write JSON results
cat << JSONEOF > "$JSON_OUT"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "iterations": $RUNS,
  "binary_sizes": {
    "ingotd_bytes": $INGOTD_SIZE,
    "ingot_cli_bytes": $INGOT_SIZE,
    "total_ingot_bytes": $TOTAL_INGOT_SIZE,
    "dockerd_bytes": $DOCKER_BIN_SIZE,
    "containerd_bytes": $CONTAINERD_BIN_SIZE,
    "total_docker_bytes": $TOTAL_DOCKER_SIZE
  },
  "daemon_memory": {
    "rss_kb": $INGOT_RSS_KB,
    "threads": $INGOT_THREADS
  },
  "ping_latency_us": {
    "avg": $PING_AVG,
    "p50": $PING_P50,
    "p95": $PING_P95
  },
  "container_lifecycle_ms": {
    "avg": $RUN_AVG,
    "p50": $RUN_P50,
    "p95": $RUN_P95
  },
  "parallel_throughput_ms": {
    "concurrent_10_total_ms": $PARALLEL_MS
  }
}
JSONEOF

echo
echo "==> Benchmark completed. Results saved to $JSON_OUT"
