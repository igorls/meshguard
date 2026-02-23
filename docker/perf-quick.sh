#!/bin/bash
# Quick perf capture that generates report inside container before cleanup.
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"

echo "[1] Cleanup"
lxc exec $CT_A -- pkill -9 meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill -9 meshguard 2>/dev/null || true
lxc exec $CT_A -- pkill -9 iperf3 2>/dev/null || true
sleep 1
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
sleep 1

echo "[2] Start meshguard"
MG_IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard nohup meshguard up --encrypt-workers 8 </dev/null >/dev/null 2>/tmp/mg.err &"
sleep 2
lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard nohup meshguard up --seed $MG_IP_A:51821 --encrypt-workers 8 </dev/null >/dev/null 2>/tmp/mg.err &"
sleep 8

MESH_IP=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 2>/dev/null | grep inet | awk '{print \$2}' | cut -d/ -f1")
echo "  Mesh: $MESH_IP"
if [ -z "$MESH_IP" ]; then
    echo "ERROR: no mesh IP"
    lxc exec $CT_B -- cat /tmp/mg.err | head -5
    exit 1
fi

echo "[3] iperf3 + perf"
lxc exec $CT_A -T -- sh -c "iperf3 -s -p 5201 -D"
sleep 0.5
lxc exec $CT_B -T -- sh -c "iperf3 -c $MESH_IP -p 5201 -t 15 >/tmp/iperf.log 2>&1 &"
sleep 2

echo "  Recording 10s at 999Hz..."
lxc exec $CT_B -- sh -c 'MG_PID=$(pgrep meshguard | head -1); perf record -F 999 -p $MG_PID -g --call-graph dwarf,8192 -o /tmp/perf.data -- sleep 10' 2>&1
echo "  Done recording"

echo "[4] Generate report (process still alive)"
lxc exec $CT_B -- sh -c 'perf report -i /tmp/perf.data --stdio --no-children --percent-limit 0.5 2>/dev/null' > bench-results/perf-report.txt
echo "  Report: $(wc -l < bench-results/perf-report.txt) lines"

lxc exec $CT_B -- sh -c 'perf script -i /tmp/perf.data 2>/dev/null' > bench-results/perf.script
echo "  Script: $(wc -l < bench-results/perf.script) lines"

echo "[5] Flamegraph"
if [ -s bench-results/perf.script ]; then
    bench-results/FlameGraph/stackcollapse-perf.pl bench-results/perf.script > bench-results/perf.folded 2>/dev/null
    bench-results/FlameGraph/flamegraph.pl --minwidth 0.5 bench-results/perf.folded > bench-results/flamegraph.svg 2>/dev/null
    echo "  Generated: bench-results/flamegraph.svg"
else
    echo "  WARN: empty perf.script, no flamegraph"
fi

echo "[6] Results"
lxc exec $CT_B -- cat /tmp/iperf.log 2>/dev/null | grep -E "sender|receiver" | tail -2
echo "--- Top hotspots ---"
grep -E "^\s+[0-9]" bench-results/perf-report.txt | head -20
echo "--- GSO ---"
lxc exec $CT_B -- cat /tmp/mg.err 2>/dev/null | head -3

echo "[7] Cleanup"
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
echo "Done"
