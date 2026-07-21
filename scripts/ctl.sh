#!/system/bin/sh
MODDIR=/data/adb/modules/ebpf_stats
export PATH="/data/adb/ksu/bin:/system/bin:/system/xbin:$PATH"
cmd="${1:-status}"

kill_all() {
  for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
    [ -r /proc/$p/cmdline ] || continue
    cmdl=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
    case "$cmdl" in *ebpf_stats/scripts/daemon.sh*) kill -9 "$p" 2>/dev/null ;; esac
  done
  sh "$MODDIR/scripts/cleanup.sh" es_ 2>/dev/null
  rm -rf "$MODDIR/run/daemon.lock" "$MODDIR/run/daemon.pid"
}

# 过滤风险路径（与 daemon 一致）
filter_risk() {
  grep -E '^/' | grep -ivE \
    '^/data/user/|^/data/data/|^/storage/|^/sdcard/|^/mnt/|^/apex/|^/dev/ashmem|^/dev/null|^/dev/urandom|^/dev/__properties__' \
  | grep -iE \
    'magisk|ksu|kernelsu|xposed|lsposed|lspd|frida|zygisk|riru|shamiko|tricky|busybox|data/adb|/su$|/su/|modules|selinux|/proc/mounts|/proc/self/maps|data/local/(tmp|su|bin|xbin)|/system/bin/su|/system/xbin/su|/sbin/su|libriruloader|XposedBridge' \
  | sort -u
}

push_one() {
  sess="$1"
  [ -d "$sess" ] || return 1
  # 优先推全部外部路径；旧 session 回退到风险路径
  external="$sess/paths_external.txt"
  paths="$sess/paths_risk.txt"
  risklog="$sess/events_risk.log"
  [ -f "$risklog" ] || risklog="$sess/events.log"

  pkg=$(grep '^package=' "$risklog" 2>/dev/null | head -1 | cut -d= -f2)
  [ -z "$pkg" ] && pkg=$(basename "$(dirname "$sess")" | sed 's/_u[0-9]*$//')
  user=$(basename "$(dirname "$sess")" | sed 's/.*_u//')
  case "$user" in *[!0-9]*) user=0 ;; esac
  [ -z "$user" ] && user=0
  key="${pkg}_u${user}"

  if [ ! -s "$external" ] && [ -f "$risklog" ]; then
    awk -v pkg="$pkg" -v user="$user" '
    function own(p) {
      if (p ~ /^\/proc\/(self|thread-self)(\/|$)/) return 1
      if (p ~ ("^/data/(data|user/" user "|user_de/" user ")/" pkg "(/|$)")) return 1
      if (p ~ ("^/(storage/emulated/" user "|sdcard)/Android/(data|media|obb)/" pkg "(/|$)")) return 1
      if (p ~ /^\/data\/app\// && index(p, "/" pkg "-") > 0) return 1
      if (p ~ /^\/data\/misc\/apexdata\/com\.android\.art\/dalvik-cache\// && index(p, "@" pkg "@") > 0) return 1
      return 0
    }
    /^pids=/ {
      line=$0; sub(/^pids=/, "", line); count=split(line, ids, " ")
      for (j=1;j<=count;j++) if (ids[j] ~ /^[0-9]+$/) ownpid[ids[j]]=1
      next
    }
    {
      for(i=1;i<=NF;i++) if($i~/^\//) {
        p=$i
        if (match(p, /^\/proc\/[0-9]+/)) {
          id=substr(p, 7, RLENGTH-6)
          if (id in ownpid) continue
        }
        if (!own(p)) print p
      }
    }' "$risklog" 2>/dev/null | sort -u > "$external"
  fi
  if [ ! -s "$paths" ] && [ -f "$risklog" ]; then
    awk '{for(i=1;i<=NF;i++) if($i~/^\//) print $i}' "$risklog" 2>/dev/null | sort -u > "$sess/paths_all.tmp"
    filter_risk < "$sess/paths_all.tmp" > "$paths"
    rm -f "$sess/paths_all.tmp"
  fi
  [ -f "$paths" ] || : > "$paths"
  [ -f "$external" ] || : > "$external"

  EP=com.envprobe
  ep_files="/data/user/${user}/${EP}/files"
  [ -d "/data/user/${user}/${EP}" ] || ep_files="/data/data/${EP}/files"
  [ -d "$(dirname "$ep_files")" ] || { echo "EnvProbe not installed user=$user"; return 1; }
  mkdir -p "$ep_files" 2>/dev/null

  pkgdir="$ep_files/from_module/by_pkg/$key"
  mkdir -p "$pkgdir"
  cp -f "$external" "$pkgdir/paths_external.txt"
  # paths_risk 已是过滤结果则直接拷；否则再滤
  if [ -s "$paths" ]; then
    filter_risk < "$paths" > "$pkgdir/paths_risk.txt"
  else
    : > "$pkgdir/paths_risk.txt"
  fi
  nr=$(awk 'END{print NR+0}' "$pkgdir/paths_risk.txt")
  nall=$(awk 'END{print NR+0}' "$pkgdir/paths_external.txt")
  {
    echo "source_package=$pkg"
    echo "user=$user"
    echo "key=$key"
    echo "session=$sess"
    echo "exported=$(date)"
    echo "paths_external=$nall"
    echo "paths_risk=$nr"
  } > "$pkgdir/meta.txt"

  base="$ep_files/from_module"
  mkdir -p "$base"
  touch "$base/index.txt"
  grep -qx "$key" "$base/index.txt" 2>/dev/null || echo "$key" >> "$base/index.txt"
  echo "$key" > "$base/latest_key.txt"
  cp -f "$pkgdir/paths_external.txt" "$base/latest_paths_external.txt"
  cp -f "$pkgdir/paths_risk.txt" "$base/latest_paths_risk.txt"
  cp -f "$pkgdir/meta.txt" "$base/latest_meta.txt"

  ep_uid=$(stat -c %u "/data/user/${user}/${EP}" 2>/dev/null || stat -c %u "/data/data/${EP}" 2>/dev/null)
  [ -n "$ep_uid" ] && chown -R "$ep_uid:$ep_uid" "$base"
  chmod -R 755 "$base"
  echo "OK $key risk=$nr -> $pkgdir"
}

case "$cmd" in
  status)
    echo "=== daemons ==="
    ps -A -o PID,PCPU,ARGS 2>/dev/null | grep 'ebpf_stats/scripts/daemon' | grep -v grep
    echo "=== scope ==="
    grep -v '^#' "$MODDIR/scope.list" 2>/dev/null | grep -v '^$'
    echo "=== stats ==="
    ls "$MODDIR/ebpf_statistics" 2>/dev/null
    echo "=== envprobe by_pkg ==="
    ls /data/data/com.envprobe/files/from_module/by_pkg 2>/dev/null
    cat /data/data/com.envprobe/files/from_module/index.txt 2>/dev/null
    ;;
  stop) kill_all; echo stopped ;;
  start)
    export MODDIR
    nohup sh "$MODDIR/scripts/daemon.sh" </dev/null >/dev/null 2>&1 &
    sleep 1; echo started
    ;;
  restart)
    kill_all; sleep 1
    export MODDIR
    nohup sh "$MODDIR/scripts/daemon.sh" </dev/null >/dev/null 2>&1 &
    sleep 2; echo restarted
    ;;
  scope)
    [ -n "$2" ] && { echo "$2" >> "$MODDIR/scope.list"; echo "added $2"; }
    cat "$MODDIR/scope.list"
    ;;
  list)
    ls -laR "$MODDIR/ebpf_statistics"
    ;;
  push)
    # push 全部 session 的最新每个包，或指定 session
    if [ -n "$2" ]; then
      push_one "$2"
    else
      # 每个 包_uN 目录取最新 session
      for d in "$MODDIR/ebpf_statistics"/*_u*; do
        [ -d "$d" ] || continue
        sess=$(ls -td "$d"/session_* 2>/dev/null | sed -n '1p')
        [ -n "$sess" ] && push_one "$sess"
      done
    fi
    echo "--- index ---"
    cat /data/data/com.envprobe/files/from_module/index.txt 2>/dev/null
    ls -la /data/data/com.envprobe/files/from_module/by_pkg/ 2>/dev/null
    ;;
  *)
    echo "usage: $0 {status|start|stop|restart|scope|list|push}"
    ;;
esac
