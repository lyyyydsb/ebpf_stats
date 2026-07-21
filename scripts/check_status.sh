#!/system/bin/sh
MODDIR=/data/adb/modules/ebpf_stats
echo "=== pidof sgame ==="
pidof com.tencent.tmgp.sgame 2>/dev/null
echo "=== ps sgame ==="
ps -A 2>/dev/null | grep -i sgame | head -15
echo "=== daemon.log ==="
cat "$MODDIR/run/daemon.log" 2>/dev/null
echo "=== run dir ==="
ls -la "$MODDIR/run/"
echo "=== statistics ==="
ls -laR "$MODDIR/ebpf_statistics/"
echo "=== kprobe_events ==="
cat /sys/kernel/tracing/kprobe_events 2>/dev/null
echo "=== tracing_on ==="
cat /sys/kernel/tracing/tracing_on 2>/dev/null
echo "=== set_event_pid count ==="
wc -l < /sys/kernel/tracing/set_event_pid 2>/dev/null
echo "=== daemon alive? ==="
pid=$(cat "$MODDIR/run/daemon.pid" 2>/dev/null)
if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
  echo "YES $pid"
else
  echo "NO"
fi
