#!/system/bin/sh
MODDIR="${0%/*}"
[ -f "$MODDIR/scripts/cleanup.sh" ] && sh "$MODDIR/scripts/cleanup.sh" es_ >/dev/null 2>&1
for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
  [ -r "/proc/$p/cmdline" ] || continue
  cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
  case "$cmd" in *ebpf_stats/scripts/daemon.sh*) kill -9 "$p" 2>/dev/null ;; esac
done
# 不自动卸载 EnvProbe，避免丢掉复扫结果；需要可手动 pm uninstall com.envprobe
