#!/bin/bash
# Run perf from the HOST targeting meshguard in mg-bench-b container.
# This avoids LXC perf_event restrictions.
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
DURATION="${1:-10}"

# Get host-visible PID of meshguard in CT_B
HOST_PID=$(ps aux | grep '[m]eshguard up --seed' | awk '{print $2}' | head -1)
if [ -z "$HOST_PID" ]; then
    echo "ERROR: meshguard not running in $CT_B"
    exit 1
fi
echo "Host PID: $HOST_PID"

# Get mesh IP
MESH_IP=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 2>/dev/null | grep inet | awk '{print \$2}' | cut -d/ -f1")
echo "Mesh IP: $MESH_IP"

# Start iperf3
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
sleep 0.5
lxc exec $CT_A -T -- sh -c "iperf3 -s -p 5201 -D"
sleep 0.5
lxc exec $CT_B -T -- sh -c "iperf3 -c $MESH_IP -p 5201 -t $((DURATION+5)) >/dev/null 2>&1 &"
sleep 2

echo "Recording perf (${DURATION}s, F=999)..."
mkdir -p bench-results
sudo perf record -F 999 -p "$HOST_PID" -g --call-graph dwarf,8192 -o bench-results/perf-host.data -- sleep "$DURATION" 2>&1

echo "=== perf report ==="
sudo perf report -i bench-results/perf-host.data --stdio --no-children --percent-limit 1 2>/dev/null | tee bench-results/perf-report.txt | head -40

echo "=== perf script ==="
sudo perf script -i bench-results/perf-host.data 2>/dev/null > bench-results/perf.script
echo "Script: $(wc -l < bench-results/perf.script) lines"

echo "=== flamegraph ==="
if [ -s bench-results/perf.script ]; then
    bench-results/FlameGraph/stackcollapse-perf.pl bench-results/perf.script > bench-results/perf.folded 2>/dev/null
    bench-results/FlameGraph/flamegraph.pl --minwidth 0.5 bench-results/perf.folded > bench-results/flamegraph.svg 2>/dev/null
    echo "Generated: bench-results/flamegraph.svg ($(wc -c < bench-results/flamegraph.svg) bytes)"
fi

echo "=== Top hotspots ==="
grep -E "^\s+[0-9]" bench-results/perf-report.txt | head -20

echo "=== Cleanup ==="
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
echo "Done (meshguard left running)"
