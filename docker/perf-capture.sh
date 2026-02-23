#!/bin/bash
# Capture perf data from inside LXC container during iperf3 benchmark.
# Runs perf INSIDE the container where meshguard is root.
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
DURATION="${1:-10}"
EW="${2:-8}"

echo "=== Cleanup ==="
lxc exec $CT_A -- pkill -9 meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill -9 meshguard 2>/dev/null || true
lxc exec $CT_A -- pkill -9 iperf3 2>/dev/null || true
sleep 1
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
sleep 1

echo "=== Start MeshGuard ==="
MG_IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
echo "  IP A: $MG_IP_A"

lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard nohup meshguard up --encrypt-workers $EW </dev/null >/dev/null 2>/tmp/mg.err &"
sleep 2
lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard nohup meshguard up --seed $MG_IP_A:51821 --encrypt-workers $EW </dev/null >/dev/null 2>/tmp/mg.err &"
sleep 8

MESH_IP=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 2>/dev/null | grep inet | awk '{print \$2}' | cut -d/ -f1")
if [ -z "$MESH_IP" ]; then
    echo "ERROR: mg0 not up"
    echo "stderr A:"; lxc exec $CT_A -- cat /tmp/mg.err 2>/dev/null | head -3
    echo "stderr B:"; lxc exec $CT_B -- cat /tmp/mg.err 2>/dev/null | head -3
    exit 1
fi
echo "  Mesh IP: $MESH_IP"

echo "=== Verify processes ==="
lxc exec $CT_B -- pgrep -la meshguard || true

echo "=== Start iperf3 ==="
lxc exec $CT_A -T -- sh -c "iperf3 -s -p 5201 -D"
sleep 0.5
lxc exec $CT_B -T -- sh -c "iperf3 -c $MESH_IP -p 5201 -t $DURATION >/tmp/iperf.log 2>&1 &"
sleep 2

echo "=== Capture perf (sender, ${DURATION}s) ==="
lxc exec $CT_B -- sh -c "MG_PID=\$(pgrep meshguard | head -1); echo PID=\$MG_PID; perf record -F 999 -p \$MG_PID -g --call-graph dwarf,8192 -o /tmp/perf.data -- sleep $DURATION 2>&1" || \
    lxc exec $CT_B -- sh -c "MG_PID=\$(pgrep meshguard | head -1); perf record -F 99 -p \$MG_PID -g -o /tmp/perf.data -- sleep $DURATION 2>&1" || \
    echo "WARNING: perf failed"

echo "=== Results ==="
lxc exec $CT_B -- ls -lh /tmp/perf.data 2>/dev/null || echo "no perf data"
echo "--- iperf3 ---"
lxc exec $CT_B -- cat /tmp/iperf.log 2>/dev/null | grep -E "sender|receiver" | tail -2

echo "=== Generate report ==="
mkdir -p bench-results
# Generate inside container first (avoids SIGPIPE from piping large perf data)
lxc exec $CT_B -- sh -c "perf report -i /tmp/perf.data --stdio --no-children --percent-limit 0.5 > /tmp/perf-report.txt 2>/dev/null"
lxc exec $CT_B -- sh -c "perf script -i /tmp/perf.data > /tmp/perf.script 2>/dev/null"
# Pull files out
lxc file pull $CT_B/tmp/perf-report.txt bench-results/perf-report.txt
lxc file pull $CT_B/tmp/perf.script bench-results/perf.script

if [ -s bench-results/perf.script ]; then
    bench-results/FlameGraph/stackcollapse-perf.pl bench-results/perf.script > bench-results/perf.folded 2>/dev/null
    bench-results/FlameGraph/flamegraph.pl --minwidth 0.5 bench-results/perf.folded > bench-results/flamegraph.svg 2>/dev/null
    echo "Flamegraph: bench-results/flamegraph.svg"
fi

echo "=== Top hotspots ==="
cat bench-results/perf-report.txt | grep -E "^\s+[0-9]" | head -20

echo "=== GSO diagnostics ==="
lxc exec $CT_B -- cat /tmp/mg.err 2>/dev/null | head -3

echo "=== Cleanup ==="
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
echo "Done"
