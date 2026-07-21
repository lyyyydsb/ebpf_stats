#!/system/bin/sh
# late_start：确保 EnvProbe 已装 + 单实例 daemon
MODDIR="${0%/*}"
export MODDIR
export PATH="/data/adb/ksu/bin:/data/adb/magisk:/system/bin:/system/xbin:/vendor/bin:$PATH"

sleep 25

mkdir -p "$MODDIR/run" "$MODDIR/ebpf_statistics" "$MODDIR/apk" "$MODDIR/scripts"
exec >>"$MODDIR/run/service.log" 2>&1
echo "=== service start $(date) ==="

# 修复错误 zip 的反斜杠文件名
if [ ! -f "$MODDIR/apk/EnvProbe.apk" ]; then
  for bad in "$MODDIR"/apk\\EnvProbe.apk; do
    [ -f "$bad" ] || continue
    mkdir -p "$MODDIR/apk"
    mv -f "$bad" "$MODDIR/apk/EnvProbe.apk" 2>/dev/null || cp -f "$bad" "$MODDIR/apk/EnvProbe.apk"
  done
fi
for s in daemon probe cleanup ctl check_status; do
  if [ ! -f "$MODDIR/scripts/${s}.sh" ]; then
    for bad in "$MODDIR"/scripts\\${s}.sh; do
      [ -f "$bad" ] || continue
      mkdir -p "$MODDIR/scripts"
      mv -f "$bad" "$MODDIR/scripts/${s}.sh" 2>/dev/null || cp -f "$bad" "$MODDIR/scripts/${s}.sh"
    done
  fi
done
chmod 755 "$MODDIR/scripts"/*.sh "$MODDIR/service.sh" 2>/dev/null

# 若未安装 EnvProbe，开机补装
if ! pm path com.envprobe >/dev/null 2>&1; then
  APK="$MODDIR/apk/EnvProbe.apk"
  if [ -f "$APK" ]; then
    echo "install EnvProbe from $APK ..."
    cp -f "$APK" /data/local/tmp/EnvProbe.apk
    chmod 644 /data/local/tmp/EnvProbe.apk
    pm install -r -t -g /data/local/tmp/EnvProbe.apk 2>&1 || \
      pm install -r -t /data/local/tmp/EnvProbe.apk 2>&1 || \
      /system/bin/pm install -r -t /data/local/tmp/EnvProbe.apk 2>&1 || \
      cmd package install -r -t /data/local/tmp/EnvProbe.apk 2>&1 || true
    pm path com.envprobe 2>&1 || true
  else
    echo "APK missing: $APK"
    ls -la "$MODDIR" "$MODDIR/apk" 2>&1 || true
  fi
else
  echo "EnvProbe already installed: $(pm path com.envprobe)"
fi

# 杀旧 daemon
for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
  [ -r "/proc/$p/cmdline" ] || continue
  cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
  case "$cmd" in *ebpf_stats/scripts/daemon.sh*) kill -9 "$p" 2>/dev/null ;; esac
done
sleep 0.5
[ -f "$MODDIR/scripts/cleanup.sh" ] && sh "$MODDIR/scripts/cleanup.sh" es_ >/dev/null 2>&1
rm -rf "$MODDIR/run/daemon.lock"

if [ -f "$MODDIR/scripts/daemon.sh" ]; then
  nohup sh "$MODDIR/scripts/daemon.sh" </dev/null >/dev/null 2>&1 &
  echo "spawned $!"
else
  echo "daemon.sh missing"
  ls -la "$MODDIR/scripts" 2>&1 || true
fi