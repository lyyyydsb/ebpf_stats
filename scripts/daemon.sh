#!/system/bin/sh
# eBPF App Statistics daemon v1.4 — 能真正写出数据
export PATH="/data/adb/ksu/bin:/data/adb/magisk:/system/bin:/system/xbin:/vendor/bin:$PATH"

MODDIR="${MODDIR:-${0%/*}/..}"
case "$MODDIR" in */scripts) MODDIR="${MODDIR%/scripts}" ;; esac
MODDIR=$(cd "$MODDIR" 2>/dev/null && pwd || echo "$MODDIR")

SCRIPTS="$MODDIR/scripts"
STATS_ROOT="$MODDIR/ebpf_statistics"
RUN_DIR="$MODDIR/run"
SCOPE_FILE="$MODDIR/scope.list"
CONFIG_FILE="$MODDIR/config.prop"
LOG_DAEMON="$RUN_DIR/daemon.log"
PIDFILE="$RUN_DIR/daemon.pid"
LOCKFILE="$RUN_DIR/daemon.lock"

mkdir -p "$STATS_ROOT" "$RUN_DIR"

acquire_lock() {
  i=0
  while ! mkdir "$LOCKFILE" 2>/dev/null; do
    oldpid=$(cat "$LOCKFILE/pid" 2>/dev/null)
    if [ -n "$oldpid" ] && [ -d "/proc/$oldpid" ] && [ "$oldpid" != "$$" ]; then
      echo "another daemon $oldpid, exit" >> "$LOG_DAEMON"
      exit 0
    fi
    rm -rf "$LOCKFILE"
    i=$((i + 1))
    [ $i -gt 5 ] && exit 1
    sleep 0.1
  done
  echo $$ > "$LOCKFILE/pid"
  echo $$ > "$PIDFILE"
}

release_lock() {
  rm -rf "$LOCKFILE"
  rm -f "$PIDFILE"
}

kill_other_daemons() {
  me=$$
  for p in $(ls /proc 2>/dev/null | grep '^[0-9]*$'); do
    [ "$p" = "$me" ] && continue
    [ -r "/proc/$p/cmdline" ] || continue
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
    case "$cmd" in
      *ebpf_stats/scripts/daemon.sh*) kill -9 "$p" 2>/dev/null ;;
    esac
  done
  sleep 0.2
}

POLL_SEC=3
ENABLE_CONN=1
ENABLE_DEATH=0
LOG_NOISE=0
PROBE_PREFIX=es_
ALLOWED_USERS=0
MAX_EVENTS=500000
MAX_RESULT_BYTES=524288
MAX_SESSIONS_PER_APP=3
MAX_DAEMON_LOG_BYTES=524288

load_config() {
  [ -f "$CONFIG_FILE" ] || return 0
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    k=$(echo "$k" | tr -d ' \r')
    v=$(echo "$v" | tr -d ' \r')
    case "$k" in
      POLL_SEC) POLL_SEC="$v" ;;
      ENABLE_CONN) ENABLE_CONN="$v" ;;
      ENABLE_DEATH) ENABLE_DEATH="$v" ;;
      LOG_NOISE) LOG_NOISE="$v" ;;
      PROBE_PREFIX) PROBE_PREFIX="$v" ;;
      ALLOWED_USERS) ALLOWED_USERS="$v" ;;
      MAX_EVENTS) MAX_EVENTS="$v" ;;
      MAX_RESULT_BYTES) MAX_RESULT_BYTES="$v" ;;
      MAX_SESSIONS_PER_APP) MAX_SESSIONS_PER_APP="$v" ;;
      MAX_DAEMON_LOG_BYTES) MAX_DAEMON_LOG_BYTES="$v" ;;
    esac
  done < "$CONFIG_FILE"
}

user_allowed() {
  u="$1"
  [ -z "$ALLOWED_USERS" ] && return 0
  oldifs=$IFS; IFS=','
  for x in $ALLOWED_USERS; do
    x=$(echo "$x" | tr -d ' ')
    [ "$x" = "$u" ] && { IFS=$oldifs; return 0; }
  done
  IFS=$oldifs
  return 1
}

dlog() {
  size=$(wc -c < "$LOG_DAEMON" 2>/dev/null || echo 0)
  if [ "$size" -ge "$MAX_DAEMON_LOG_BYTES" ] 2>/dev/null; then
    mv -f "$LOG_DAEMON" "$LOG_DAEMON.1" 2>/dev/null
  fi
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_DAEMON"
}

TRACE_DIR="/sys/kernel/tracing"
[ -d "$TRACE_DIR" ] || TRACE_DIR="/sys/kernel/debug/tracing"
T="$TRACE_DIR"
export TRACE_DIR T PROBE_PREFIX ENABLE_CONN ENABLE_DEATH
# shellcheck disable=SC1090
. "$SCRIPTS/probe.sh"

BPF_DIR="$MODDIR/bin"
BPF_BIN="$BPF_DIR/file_monitor"
BPF_OBJ="$BPF_DIR/file_monitor.bpf.o"
BPF_LIB="$MODDIR/lib"
BPF_LOG="$RUN_DIR/bpf.log"
BPF_PIDFILE="$RUN_DIR/bpf.pid"
BPF_LAST_PIDS=""
BPF_LINES=0

bpf_stop() {
  p=$(cat "$BPF_PIDFILE" 2>/dev/null)
  if [ -n "$p" ]; then
    kill "$p" 2>/dev/null
    for child in $(ps -A -o PID,PPID 2>/dev/null | awk -v p="$p" '$2==p{print $1}'); do
      kill "$child" 2>/dev/null
    done
  fi
  rm -f "$BPF_PIDFILE"
  BPF_LAST_PIDS=""
  BPF_LINES=0
}

bpf_start() {
  targets="$1"
  bpf_stop
  [ -x "$BPF_BIN" ] || { dlog "BPF binary missing: $BPF_BIN"; return 1; }
  [ -f "$BPF_OBJ" ] || { dlog "BPF object missing: $BPF_OBJ"; return 1; }
  : > "$BPF_LOG"
  (
    cd "$BPF_DIR" || exit 1
    LD_LIBRARY_PATH="$BPF_LIB" ./file_monitor --vfs-only $targets |
      MODDIR="$MODDIR" sh "$SCRIPTS/bpf_collect.sh" >> "$BPF_LOG" 2>&1
  ) &
  echo $! > "$BPF_PIDFILE"
  BPF_LAST_PIDS="$targets"
  dlog "BPF VFS monitor started pids=[$targets] pid=$(cat "$BPF_PIDFILE")"
}

drain_bpf() {
  [ -f "$BPF_LOG" ] || return 0
  total=$(wc -l < "$BPF_LOG" 2>/dev/null || echo 0)
  case "$total" in *[!0-9]*) return 0 ;; esac
  [ "$total" -gt "$BPF_LINES" ] || return 0
  start=$((BPF_LINES + 1))
  BPF_LINES=$total
  awk -v start="$start" -v tidmap="$RUN_DIR/tidmap" -v rundir="$RUN_DIR" -v ts="$(date '+%Y-%m-%d %H:%M:%S')" '
  BEGIN {
    while ((getline L < tidmap) > 0) {
      split(L, a, " ")
      if (a[1] != "") { pkg[a[1]]=a[2]; user[a[1]]=a[3] }
    }
    close(tidmap)
  }
  NR < start || $1 != "VFS" { next }
  {
    tgid=""
    for (i=1;i<=NF;i++) if ($i ~ /^tgid=/) { tgid=$i; sub(/^tgid=/, "", tgid) }
    if (tgid == "" || !(tgid in pkg)) next
    key=pkg[tgid] "_u" user[tgid]
    sf=rundir "/sess_" key
    sess=""
    while ((getline sl < sf) > 0) if (index(sl, "sess=") == 1) sess=substr(sl, 6)
    close(sf)
    if (sess == "") next
    print "[" ts "] " $0 >> sess "/vfs_events.log"
    close(sess "/vfs_events.log")
  }' "$BPF_LOG" 2>/dev/null
}

load_scope_rules() {
  : > "$RUN_DIR/scope_rules"
  : > "$RUN_DIR/scope_pkgs"
  [ -f "$SCOPE_FILE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(echo "$line" | tr -d '\r')
    case "$line" in \#*|'') continue ;; esac
    line=$(echo "$line" | sed 's/#.*//;s/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$line" ] && continue
    case "$line" in
      *:*) pkg=${line%%:*}; uspec=${line#*:} ;;
      *) pkg=$line; uspec="@default" ;;
    esac
    pkg=$(echo "$pkg" | tr -d ' ')
    uspec=$(echo "$uspec" | tr -d ' ')
    [ -z "$pkg" ] && continue
    [ -z "$uspec" ] && uspec="@default"
    case "$uspec" in '*'|all|ALL) uspec="*" ;; esac
    echo "$pkg $uspec" >> "$RUN_DIR/scope_rules"
    grep -qx "$pkg" "$RUN_DIR/scope_pkgs" 2>/dev/null || echo "$pkg" >> "$RUN_DIR/scope_pkgs"
  done < "$SCOPE_FILE"
}

scope_hit() {
  pkg="$1"; user="$2"
  [ -f "$RUN_DIR/scope_rules" ] || return 1
  while read -r rpkg uspec; do
    [ "$rpkg" = "$pkg" ] || continue
    case "$uspec" in
      '*') return 0 ;;
      @default)
        [ -z "$ALLOWED_USERS" ] && return 0
        user_allowed "$user" && return 0
        ;;
      *)
        oldifs=$IFS; IFS=','
        for x in $uspec; do
          x=$(echo "$x" | tr -d ' uU')
          [ "$x" = "$user" ] && { IFS=$oldifs; return 0; }
        done
        IFS=$oldifs
        ;;
    esac
  done < "$RUN_DIR/scope_rules"
  return 1
}

discover_running() {
  load_scope_rules
  [ -s "$RUN_DIR/scope_pkgs" ] || return 0
  outf="$RUN_DIR/discover.out"
  : > "$outf"

  while read -r pkg; do
    [ -z "$pkg" ] && continue
    for pid in $(pidof "$pkg" 2>/dev/null); do
      [ -d "/proc/$pid" ] || continue
      uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null)
      [ -z "$uid" ] && continue
      auser=$((uid / 100000))
      scope_hit "$pkg" "$auser" || continue
      echo "$uid $pkg $pid" >> "$outf"
    done
  done < "$RUN_DIR/scope_pkgs"

  # 子进程 包:xxx
  ps -A -o PID,NAME 2>/dev/null > "$RUN_DIR/ps.out"
  if [ -s "$RUN_DIR/ps.out" ]; then
    awk 'NR==FNR{pkgs[$1]=1;next}{
      pid=$1; name=$2
      if(pid+0!=pid) next
      base=name; sub(/:.*/,"",base)
      if(base in pkgs) print pid, base
    }' "$RUN_DIR/scope_pkgs" "$RUN_DIR/ps.out" > "$RUN_DIR/ps.hit" 2>/dev/null
    while read -r pid base; do
      case "$pid" in *[!0-9]*|'') continue ;; esac
      [ -d "/proc/$pid" ] || continue
      grep -q " $pid$" "$outf" 2>/dev/null && continue
      uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null)
      [ -z "$uid" ] && continue
      auser=$((uid / 100000))
      scope_hit "$base" "$auser" || continue
      echo "$uid $base $pid" >> "$outf"
    done < "$RUN_DIR/ps.hit"
  fi
  [ -s "$outf" ] && sort -u "$outf"
}

collect_tids() {
  tids=""
  for g in $1; do
    if [ -d "/proc/$g/task" ]; then
      for t in /proc/$g/task/*; do
        t=${t##*/}
        case "$t" in *[!0-9]*) continue ;; esac
        tids="$tids $t"
      done
    else
      tids="$tids $g"
    fi
  done
  echo $tids
}

prune_sessions() {
  dir="$1"
  keep="$MAX_SESSIONS_PER_APP"
  case "$keep" in *[!0-9]*|'') keep=3 ;; esac
  n=0
  for old in $(ls -dt "$dir"/session_* 2>/dev/null); do
    n=$((n + 1))
    [ "$n" -le "$keep" ] && continue
    rm -rf "$old"
  done
}

start_session() {
  pkg="$1"; user="$2"; pids="$3"
  key="${pkg}_u${user}"
  sdir="$STATS_ROOT/${pkg}_u${user}"
  mkdir -p "$sdir"
  prune_sessions "$sdir"
  ts=$(date '+%Y%m%d_%H%M%S')
  sess="$sdir/session_${ts}"
  mkdir -p "$sess"
  {
    echo "=== session start $(date) ==="
    echo "package=$pkg"
    echo "user=$user"
    echo "pids=$pids"
    echo "format=compact_v3 external_full+own_count"
  } > "$sess/events_risk.log"
  # 兼容旧字段名：events.log 作为风险日志的软说明
  echo "see events_risk.log (compact)" > "$sess/events.log"
  : > "$sess/biz_counts.txt"
  : > "$sess/path_results.log"
  : > "$sess/vfs_events.log"
  echo "0" > "$RUN_DIR/evt_$key"
  echo "0" > "$RUN_DIR/evt_risk_$key"
  {
    echo "pkg=$pkg"
    echo "user=$user"
    echo "pids=$pids"
    echo "sess=$sess"
    echo "events=0"
    echo "started=$(date +%s)"
  } > "$RUN_DIR/sess_$key"
  dlog "START $key pids=[$pids] -> $sess"
  echo "$sess"
}

# 只保留「环境风险」路径，丢掉 App 私有目录/业务路径
filter_risk_paths() {
  # stdin -> stdout
  # 排除: /data/user/ /data/data/<pkg>/ /storage/ /sdcard/ 等业务路径
  # 保留: su/magisk/ksu/lspd/adb/modules/xposed/selinux/mounts/proc 探针等
  grep -E '^/' | grep -ivE \
    '^/data/user/|^/data/data/|^/storage/|^/sdcard/|^/mnt/|^/apex/|^/dev/ashmem|^/dev/null|^/dev/urandom|^/dev/__properties__' \
  | grep -iE \
    'magisk|kernelsu|(^|/)ksu(/|$)|xposed|lsposed|lspd|frida|zygisk|riru|shamiko|tricky|busybox|data/adb|/su$|/su/|selinux|/proc/mounts|/proc/self/maps|data/local/(tmp|su|bin|xbin)|/system/bin/su|/system/xbin/su|/sbin/su|libriruloader|XposedBridge' \
  | sort -u
}

# 推给 EnvProbe：按包名隔开，推目标实际探测的外部路径和风险子集
# from_module/by_pkg/<pkg>_u<user>/{paths_external.txt,paths_risk.txt,meta.txt}
# from_module/index.txt  一行一个 pkg_uN
push_to_envprobe() {
  src_pkg="$1"
  user="$2"
  sess="$3"
  external_file="$4"
  risk_file="$5"

  EP_PKG="com.envprobe"
  ep_files="/data/user/${user}/${EP_PKG}/files"
  [ -d "/data/user/${user}/${EP_PKG}" ] || [ -d "/data/data/${EP_PKG}" ] || {
    dlog "EnvProbe not installed (user=$user), skip push"
    return 0
  }
  if [ ! -d "$ep_files" ] && [ "$user" = "0" ]; then
    ep_files="/data/data/${EP_PKG}/files"
  fi

  key="${src_pkg}_u${user}"
  base="$ep_files/from_module"
  pkgdir="$base/by_pkg/$key"
  mkdir -p "$pkgdir" 2>/dev/null || return 0

  extf="$pkgdir/paths_external.txt"
  riskf="$pkgdir/paths_risk.txt"
  [ -f "$external_file" ] && cp -f "$external_file" "$extf" || : > "$extf"
  [ -f "$risk_file" ] && cp -f "$risk_file" "$riskf" || filter_risk_paths < "$extf" > "$riskf"
  nrisk=$(awk 'END{print NR+0}' "$riskf" 2>/dev/null)
  nall=$(awk 'END{print NR+0}' "$extf" 2>/dev/null)

  {
    echo "source_package=$src_pkg"
    echo "user=$user"
    echo "key=$key"
    echo "session=$sess"
    echo "exported=$(date)"
    echo "paths_external=$nall"
    echo "paths_risk=$nrisk"
  } > "$pkgdir/meta.txt"

  # 更新索引（去重追加）
  idx="$base/index.txt"
  touch "$idx"
  grep -qx "$key" "$idx" 2>/dev/null || echo "$key" >> "$idx"

  # 最近一次
  echo "$key" > "$base/latest_key.txt"
  cp -f "$extf" "$base/latest_paths_external.txt" 2>/dev/null
  cp -f "$riskf" "$base/latest_paths_risk.txt" 2>/dev/null
  cp -f "$pkgdir/meta.txt" "$base/latest_meta.txt" 2>/dev/null

  ep_uid=$(stat -c %u "/data/user/${user}/${EP_PKG}" 2>/dev/null)
  [ -z "$ep_uid" ] && ep_uid=$(stat -c %u "/data/data/${EP_PKG}" 2>/dev/null)
  [ -n "$ep_uid" ] && chown -R "${ep_uid}:${ep_uid}" "$base" 2>/dev/null
  chmod -R 755 "$base" 2>/dev/null
  dlog "pushed $key risk=$nrisk/$nall -> $pkgdir"
}

gen_session_stats() {
  sess="$1"; pkg="$2"; user="$3"; events="$4"
  # compact_v2: 风险明细 + 业务计数
  risklog="$sess/events_risk.log"
  [ -f "$risklog" ] || risklog="$sess/events.log"
  bizf="$sess/biz_counts.txt"
  resultf="$sess/path_results.log"
  vfsf="$sess/vfs_events.log"
  uniqf="$sess/unique_risk.txt"
  uniqextf="$sess/unique_external.txt"
  sockf="$sess/socks.txt"
  sumf="$sess/summary.txt"
  extpathsf="$sess/paths_external.txt"
  pathsf="$sess/paths_risk.txt"
  sdir=$(dirname "$sess")

  # 目标实际访问的外部路径：排除自身私有目录和自身 /proc 进程路径
  : > "$extpathsf"
  if [ -f "$risklog" ]; then
    awk -v pkg="$pkg" -v user="$user" '
    function own(p) {
      gsub(/\/\.\//, "/", p)
      while (index(p, "//")) gsub(/\/\//, "/", p)
      if (p ~ /^\/proc\/(self|thread-self)(\/|$)/) return 1
      if (p ~ ("^/data/(data|user/" user "|user_de/" user ")/" pkg "(/|$)")) return 1
      if (p ~ ("^/(storage/emulated/" user "|sdcard)/Android/(data|media|obb)/" pkg "(/|$)")) return 1
      if (p ~ ("^/mnt/user/" user "/[^/]+/Android/(data|media|obb)/" pkg "(/|$)")) return 1
      if (p ~ /^\/data\/app\// && index(p, "/" pkg "-") > 0) return 1
      if (p ~ /^\/data\/misc\/apexdata\/com\.android\.art\/dalvik-cache\// && index(p, "@" pkg "@") > 0) return 1
      return 0
    }
    /^pids=/ {
      line=$0
      sub(/^pids=/, "", line)
      count=split(line, ids, " ")
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
    }' "$risklog" | sort -u > "$extpathsf"
  fi

  # 风险路径仅作为外部路径的关键字子集保留
  : > "$pathsf"
  if [ -s "$extpathsf" ]; then
    tmp="$pathsf.tmp"
    filter_risk_paths < "$extpathsf" > "$tmp" 2>/dev/null
    mv "$tmp" "$pathsf"
  fi

  echo "=== 外部路径去重 $(date) ===" > "$uniqextf"
  sed 's/^/      1 /' "$extpathsf" >> "$uniqextf"

  echo "=== 风险路径去重 $(date) ===" > "$uniqf"
  sed 's/^/      1 /' "$pathsf" >> "$uniqf"

  echo "=== Socket ===" > "$sockf"
  # 普通 CONN 在 biz_counts；仅 root 相关 socket 进 risklog
  if [ -f "$risklog" ]; then
    awk '/\[CONN\]/{
      for(i=1;i<=NF;i++) if($i~/^@/ || $i~/^AF_/) print $i
    }' "$risklog" | sort | uniq -c | sort -rn >> "$sockf"
  fi
  if [ -f "$bizf" ]; then
    bc=$(awk -F'\t' '$1=="CONN"{print $2+0; exit}' "$bizf")
    [ -n "$bc" ] && [ "$bc" -gt 0 ] 2>/dev/null && echo "  (biz_CONN_count=$bc 已合并，非风险 socket 不写明细)" >> "$sockf"
  fi

  # 禁止 grep -c||echo0：0 匹配时会得到 "0\n0" 弄崩 $(( ))
  nstat=0; nacc=0; nopen=0; nconn=0; nmaps=0; nroot=0; nrisk=0; nexternal=0
  if [ -f "$risklog" ]; then
    nstat=$(awk 'BEGIN{c=0} /\[STAT\]/{c++} END{print c+0}' "$risklog")
    nacc=$(awk 'BEGIN{c=0} /\[ACCESS\]/{c++} END{print c+0}' "$risklog")
    nopen=$(awk 'BEGIN{c=0} /\[OPEN\]/{c++} END{print c+0}' "$risklog")
    nconn=$(awk 'BEGIN{c=0} /\[CONN\]/{c++} END{print c+0}' "$risklog")
    nmaps=$(awk 'BEGIN{c=0} /MAPS|\/maps/{c++} END{print c+0}' "$risklog")
    nroot=$(awk 'BEGIN{c=0} /ROOT/{c++} END{print c+0}' "$risklog")
  fi
  [ -f "$pathsf" ] && nrisk=$(awk 'END{print NR+0}' "$pathsf")
  [ -f "$extpathsf" ] && nexternal=$(awk 'END{print NR+0}' "$extpathsf")
  # 业务侧合计
  biz_open=0; biz_stat=0; biz_acc=0; biz_conn=0; biz_other=0
  if [ -f "$bizf" ]; then
    biz_open=$(awk -F'\t' '$1=="OPEN"{s+=$2} END{print s+0}' "$bizf")
    biz_stat=$(awk -F'\t' '$1=="STAT"{s+=$2} END{print s+0}' "$bizf")
    biz_acc=$(awk -F'\t' '$1=="ACCESS"{s+=$2} END{print s+0}' "$bizf")
    biz_conn=$(awk -F'\t' '$1=="CONN"{s+=$2} END{print s+0}' "$bizf")
    biz_other=$(awk -F'\t' '$1=="OTHER"{s+=$2} END{print s+0}' "$bizf")
  fi
  biz_total=$((biz_open + biz_stat + biz_acc + biz_conn + biz_other))
  vfs_total=0
  [ -f "$vfsf" ] && vfs_total=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^total=/){sub(/^total=/,"",$i); s+=$i}} END{print s+0}' "$vfsf")
  result_success=0; result_not_found=0; result_denied=0; result_error=0
  if [ -f "$resultf" ]; then
    result_success=$(awk '/state=SUCCESS/{n=1;for(i=1;i<=NF;i++)if($i~/^count=/){sub(/^count=/,"",$i);n=$i+0}c+=n}END{print c+0}' "$resultf")
    result_not_found=$(awk '/state=NOT_FOUND/{n=1;for(i=1;i<=NF;i++)if($i~/^count=/){sub(/^count=/,"",$i);n=$i+0}c+=n}END{print c+0}' "$resultf")
    result_denied=$(awk '/state=DENIED/{n=1;for(i=1;i<=NF;i++)if($i~/^count=/){sub(/^count=/,"",$i);n=$i+0}c+=n}END{print c+0}' "$resultf")
    result_error=$(awk '/state=ERROR/{n=1;for(i=1;i<=NF;i++)if($i~/^count=/){sub(/^count=/,"",$i);n=$i+0}c+=n}END{print c+0}' "$resultf")
  fi
  risk_lines=$((nstat + nacc + nopen + nconn))

  {
    echo "package=$pkg user=$user"
    echo "ended=$(date)"
    echo "format=compact_v3"
    echo "session_dir=$sess"
    echo "events_total=$events"
    echo "risk_lines=$risk_lines"
    echo "RISK_OPEN=$nopen RISK_STAT=$nstat RISK_ACCESS=$nacc RISK_CONN=$nconn"
    echo "external_paths=$nexternal risk_paths=$nrisk maps=$nmaps root_marks=$nroot"
    echo "BIZ_OPEN=$biz_open BIZ_STAT=$biz_stat BIZ_ACCESS=$biz_acc BIZ_CONN=$biz_conn BIZ_OTHER=$biz_other BIZ_TOTAL=$biz_total"
    echo "VFS_PERMISSION_TOTAL=$vfs_total"
    echo "PATH_SUCCESS=$result_success PATH_NOT_FOUND=$result_not_found PATH_DENIED=$result_denied PATH_ERROR=$result_error"
    echo "--- 风险路径 TOP ---"
    sed -n '1,50p' "$uniqf"
    echo "--- Socket TOP ---"
    sed -n '1,20p' "$sockf"
    echo "--- 文件说明 ---"
    echo "本目录: $sess"
    echo "  events_risk.log  外部路径事件（兼容旧文件名）"
    echo "  biz_counts.txt   自身私有路径按类型计数"
    echo "  vfs_events.log   内核 security_inode_permission 聚合事件"
    echo "  path_results.log 目标 App 实际系统调用返回结果"
    echo "  paths_external.txt 目标实际探测的全部外部路径"
    echo "  paths_risk.txt   过滤后的风险路径(给 EnvProbe)"
    echo "  unique_external.txt 外部路径去重"
    echo "  unique_risk.txt  风险日志路径频次"
    echo "  socks.txt        root 相关 socket + 业务 CONN 计数"
    echo "  summary.txt      本文件"
    echo "包级 latest_*: $sdir/latest_summary.txt 等"
    echo "EnvProbe: /data/user/${user}/com.envprobe/files/from_module/by_pkg/${pkg}_u${user}/"
  } > "$sumf"

  cp -f "$sumf" "$sdir/latest_summary.txt" 2>/dev/null
  cp -f "$uniqextf" "$sdir/latest_unique_external.txt" 2>/dev/null
  cp -f "$uniqf" "$sdir/latest_unique.txt" 2>/dev/null
  cp -f "$extpathsf" "$sdir/latest_paths_external.txt" 2>/dev/null
  cp -f "$pathsf" "$sdir/latest_paths_risk.txt" 2>/dev/null
  cp -f "$sockf" "$sdir/latest_socks.txt" 2>/dev/null
  rm -f "$sdir/latest_path_results.txt" "$sdir/latest_vfs_events.txt"
  ln -s "${sess##*/}/path_results.log" "$sdir/latest_path_results.txt" 2>/dev/null
  ln -s "${sess##*/}/vfs_events.log" "$sdir/latest_vfs_events.txt" 2>/dev/null
  prune_sessions "$sdir"

  push_to_envprobe "$pkg" "$user" "$sess" "$extpathsf" "$pathsf"
}

stop_session() {
  key="$1"
  st="$RUN_DIR/sess_$key"
  [ -f "$st" ] || return 0
  sess=$(grep '^sess=' "$st" | cut -d= -f2-)
  pkg=$(grep '^pkg=' "$st" | cut -d= -f2-)
  user=$(grep '^user=' "$st" | cut -d= -f2-)
  events=0
  [ -f "$RUN_DIR/evt_$key" ] && events=$(cat "$RUN_DIR/evt_$key")
  [ -z "$sess" ] && { rm -f "$st" "$RUN_DIR/evt_$key"; return 0; }
  gen_session_stats "$sess" "$pkg" "$user" "$events"
  dlog "STOP $key events=$events dir=$sess"
  rm -f "$st" "$RUN_DIR/evt_$key"
}

rebuild() {
  tmp="$RUN_DIR/discover.tmp"
  discover_running > "$tmp" 2>/dev/null

  : > "$RUN_DIR/pidmap"
  : > "$RUN_DIR/tidmap"
  : > "$RUN_DIR/active_keys"
  : > "$RUN_DIR/agg.tmp"

  if [ -s "$tmp" ]; then
    while read -r uid pkg pid; do
      case "$uid" in *[!0-9]*|'') continue ;; esac
      case "$pid" in *[!0-9]*|'') continue ;; esac
      user=$((uid / 100000))
      key="${pkg}_u${user}"
      if grep -q "^${key} " "$RUN_DIR/agg.tmp" 2>/dev/null; then
        old=$(grep "^${key} " "$RUN_DIR/agg.tmp" | sed -n '1p')
        old=${old#* }
        case " $old " in *" $pid "*) ;; *)
          grep -v "^${key} " "$RUN_DIR/agg.tmp" > "$RUN_DIR/agg.tmp.n"
          echo "$key $old $pid" >> "$RUN_DIR/agg.tmp.n"
          mv "$RUN_DIR/agg.tmp.n" "$RUN_DIR/agg.tmp"
        ;; esac
      else
        echo "$key $pid" >> "$RUN_DIR/agg.tmp"
      fi
    done < "$tmp"
  fi

  # 保活旧 pid
  for st in "$RUN_DIR"/sess_*; do
    [ -f "$st" ] || continue
    key=${st##*/sess_}
    oldpids=$(grep '^pids=' "$st" | cut -d= -f2-)
    keep=""
    for p in $oldpids; do [ -d "/proc/$p" ] && keep="$keep $p"; done
    keep=$(echo $keep)
    [ -z "$keep" ] && continue
    if grep -q "^${key} " "$RUN_DIR/agg.tmp" 2>/dev/null; then
      cur=$(grep "^${key} " "$RUN_DIR/agg.tmp" | sed -n '1p'); cur=${cur#* }
      for p in $keep; do
        case " $cur " in *" $p "*) ;; *) cur="$cur $p" ;; esac
      done
      grep -v "^${key} " "$RUN_DIR/agg.tmp" > "$RUN_DIR/agg.tmp.n"
      echo "$key $cur" >> "$RUN_DIR/agg.tmp.n"
      mv "$RUN_DIR/agg.tmp.n" "$RUN_DIR/agg.tmp"
    else
      echo "$key $keep" >> "$RUN_DIR/agg.tmp"
    fi
  done

  while read -r key pids; do
    [ -z "$key" ] && continue
    pkg=${key%_u*}; user=${key##*_u}
    live=""
    for p in $pids; do [ -d "/proc/$p" ] && live="$live $p"; done
    live=$(echo $live)
    [ -z "$live" ] && continue

    echo "$key" >> "$RUN_DIR/active_keys"
    for pid in $live; do
      echo "$pid $pkg $user" >> "$RUN_DIR/pidmap"
      if [ -d "/proc/$pid/task" ]; then
        for t in /proc/$pid/task/*; do
          t=${t##*/}
          case "$t" in *[!0-9]*) continue ;; esac
          echo "$t $pkg $user" >> "$RUN_DIR/tidmap"
        done
      else
        echo "$pid $pkg $user" >> "$RUN_DIR/tidmap"
      fi
    done

    st="$RUN_DIR/sess_$key"
    if [ ! -f "$st" ]; then
      start_session "$pkg" "$user" "$live" >/dev/null
    else
      grep -v '^pids=' "$st" > "$st.n"
      echo "pids=$live" >> "$st.n"
      mv "$st.n" "$st"
    fi
  done < "$RUN_DIR/agg.tmp"

  for st in "$RUN_DIR"/sess_*; do
    [ -f "$st" ] || continue
    key=${st##*/sess_}
    grep -qx "$key" "$RUN_DIR/active_keys" 2>/dev/null || stop_session "$key"
  done
}

refresh_filter() {
  all_pids=""
  for st in "$RUN_DIR"/sess_*; do
    [ -f "$st" ] || continue
    all_pids="$all_pids $(grep '^pids=' "$st" | cut -d= -f2-)"
  done
  all_pids=$(echo $all_pids | tr ' ' '\n' | sort -u | tr '\n' ' ')
  all_pids=$(echo $all_pids)

  if [ -z "$all_pids" ]; then
    [ -n "$BPF_LAST_PIDS" ] && bpf_stop
    if [ "$PROBES_LIVE" = "1" ]; then
      probe_off
      PROBES_LIVE=0
      LAST_PIDS=""
      dlog "no targets, probes off"
    fi
    return 0
  fi

  if [ "$PROBES_LIVE" = "1" ] && [ "$all_pids" = "$LAST_PIDS" ]; then
    [ "$BPF_LAST_PIDS" = "$all_pids" ] || bpf_start "$all_pids"
    return 0
  fi

  tids=$(collect_tids "$all_pids")
  ntid=$(echo $tids | wc -w)

  if [ "$PROBES_LIVE" != "1" ]; then
    ok=$(probe_setup)
    ok=$(echo "$ok" | tr -d ' \r' | sed -n '$p')
    if [ -z "$ok" ] || [ "$ok" = "0" ]; then
      dlog "probe_setup FAILED"
      PROBES_LIVE=0
      return 1
    fi
    np=$(probe_set_pids "$tids")
    probe_on
    PROBES_LIVE=1
    dlog "probe_setup ok=$ok tids=$ntid set_event_pid=$np"
  else
    np=$(probe_set_pids "$tids")
    probe_on
    dlog "update pids tids=$ntid set_event_pid=$np"
  fi
  LAST_PIDS="$all_pids"
  [ "$BPF_LAST_PIDS" = "$all_pids" ] || bpf_start "$all_pids"
}

compact_result_file() {
  file="$1"
  [ -f "$file" ] || return 0
  size=$(wc -c < "$file" 2>/dev/null || echo 0)
  [ "$size" -ge "$MAX_RESULT_BYTES" ] 2>/dev/null || return 0
  tmp="$file.compact"
  awk '
  {
    line=$0
    count=1
    if (match(line, / count=[0-9]+$/)) {
      count=substr(line, RSTART+7)+0
      line=substr(line, 1, RSTART-1)
    }
    if (line ~ /^\[[0-9]/) {
      op=line
      sub(/^\[[^]]+\]\[/, "", op)
      sub(/\].*/, "", op)
      rest=line
      sub(/^\[[^]]+\]\[[^]]+\] /, "", rest)
      split_at=index(rest, "  ")
      if (split_at > 0) line="[" op "] " substr(rest, split_at+2)
    }
    totals[line] += count
  }
  END { for (line in totals) print line " count=" totals[line] }
  ' "$file" > "$tmp" 2>/dev/null && mv -f "$tmp" "$file"
  size=$(wc -c < "$file" 2>/dev/null || echo 0)
  if [ "$size" -ge "$MAX_RESULT_BYTES" ] 2>/dev/null; then
    tail -n 2000 "$file" > "$tmp" 2>/dev/null && mv -f "$tmp" "$file"
  fi
}

cap_text_file() {
  file="$1"; limit="$2"; lines="$3"
  [ -f "$file" ] || return 0
  size=$(wc -c < "$file" 2>/dev/null || echo 0)
  [ "$size" -ge "$limit" ] 2>/dev/null || return 0
  tail -n "$lines" "$file" > "$file.cap" 2>/dev/null && mv -f "$file.cap" "$file"
}

maintain_storage() {
  cap_text_file "$LOG_DAEMON.1" "$MAX_DAEMON_LOG_BYTES" 3000
  for appdir in "$STATS_ROOT"/*_u*; do
    [ -d "$appdir" ] || continue
    prune_sessions "$appdir"
    for sess in "$appdir"/session_*; do
      [ -d "$sess" ] || continue
      compact_result_file "$sess/path_results.log"
      cap_text_file "$sess/events_risk.log" 524288 3000
      cap_text_file "$sess/vfs_events.log" 262144 2000
    done
    latest=$(ls -dt "$appdir"/session_* 2>/dev/null | sed -n '1p')
    if [ -d "$latest" ]; then
      rm -f "$appdir/latest_path_results.txt" "$appdir/latest_vfs_events.txt"
      ln -s "${latest##*/}/path_results.log" "$appdir/latest_path_results.txt" 2>/dev/null
      ln -s "${latest##*/}/vfs_events.log" "$appdir/latest_vfs_events.txt" 2>/dev/null
    fi
  done
}

# ---------- 热路径（已用真机 trace 验证 awk 可写 200+ 条）----------
DRAIN_N=0
drain_trace() {
  [ "$PROBES_LIVE" = "1" ] || return 0
  [ -s "$RUN_DIR/tidmap" ] || return 0
  # 有没有会话
  has=0
  for _s in "$RUN_DIR"/sess_*; do
    [ -f "$_s" ] && has=1 && break
  done
  [ "$has" = "1" ] || return 0

  # 暂停写入再读，避免半截行/二进制撕裂
  echo 0 > "$T/tracing_on" 2>/dev/null
  cat "$T/trace" > "$RUN_DIR/trace.chunk" 2>/dev/null
  echo > "$T/trace" 2>/dev/null
  echo 1 > "$T/tracing_on" 2>/dev/null

  sz=$(wc -c < "$RUN_DIR/trace.chunk" 2>/dev/null || echo 0)
  # 无 es_ 则返回（不用 grep -a，部分 toybox 不支持）
  if ! grep -q "$PROBE_PREFIX" "$RUN_DIR/trace.chunk" 2>/dev/null; then
    DRAIN_N=$((DRAIN_N + 1))
    if [ $((DRAIN_N % 10)) -eq 0 ]; then
      dlog "drain empty#$DRAIN_N chunk=${sz}B"
    fi
    return 0
  fi

  # 调试：前几次记录 chunk 信息
  DRAIN_N=$((DRAIN_N + 1))
  if [ "$DRAIN_N" -le 3 ]; then
    dlog "drain try#$DRAIN_N chunk=${sz}B es=$(grep -c "$PROBE_PREFIX" "$RUN_DIR/trace.chunk" 2>/dev/null)"
  fi

  # compact_v3:
  # - 外部路径事件 → events_risk.log（保留旧文件名兼容）
  # - 自身私有路径 → 只按 OPEN/STAT/ACCESS 累加到 biz_counts.txt
  wrote=$(awk -v P="$PROBE_PREFIX" -v tidmap="$RUN_DIR/tidmap" -v rundir="$RUN_DIR" -v noise="$LOG_NOISE" '
  BEGIN {
    while ((getline L < tidmap) > 0) {
      split(L, a, " ")
      if (a[1] != "") { pkg[a[1]]=a[2]; user[a[1]]=a[3] }
    }
    close(tidmap)
  }
  function is_risk_path(p) {
    if (p ~ /data\/adb|magisk|\/ksu(\/|$)|kernelsu|frida|xposed|lsposed|busybox|lspd|riru|shamiko|tricky/) return 1
    if (p ~ /\/maps$|cpu_capacity|cpuinfo_max_freq|\/system\/cpu|selinux/) return 1
    if (p ~ /\/proc\/.*\/(mounts|cmdline|status|fd\/)|\/proc\/self\/|\/proc\/mounts/) return 1
    if (p ~ /data\/local\/(tmp|su|bin|xbin)|\/system\/bin\/su|\/system\/xbin\/su|\/sbin\/su/) return 1
    if (p ~ /libriruloader|XposedBridge/) return 1
    return 0
  }
  function is_own_path(p, target_pkg, target_user) {
    gsub(/\/\.\//, "/", p)
    while (index(p, "//")) gsub(/\/\//, "/", p)
    if (p ~ /^\/proc\/(self|thread-self)(\/|$)/) return 1
    if (match(p, /^\/proc\/[0-9]+/)) {
      procid=substr(p, 7, RLENGTH-6)
      if ((procid in pkg) && pkg[procid] == target_pkg) return 1
    }
    if (p ~ ("^/data/(data|user/" target_user "|user_de/" target_user ")/" target_pkg "(/|$)")) return 1
    if (p ~ ("^/(storage/emulated/" target_user "|sdcard)/Android/(data|media|obb)/" target_pkg "(/|$)")) return 1
    if (p ~ ("^/mnt/user/" target_user "/[^/]+/Android/(data|media|obb)/" target_pkg "(/|$)")) return 1
    if (p ~ /^\/data\/app\// && index(p, "/" target_pkg "-") > 0) return 1
    if (p ~ /^\/data\/misc\/apexdata\/com\.android\.art\/dalvik-cache\// && index(p, "@" target_pkg "@") > 0) return 1
    return 0
  }
  index($0, P) == 0 { next }
  {
    pid=""
    if (match($0, /-[0-9]+[ \t\[]/)) {
      pid = substr($0, RSTART+1, RLENGTH-1)
      gsub(/[^0-9]/, "", pid)
    }
    if (pid == "" || !(pid in pkg)) next

    key = pkg[pid] "_u" user[pid]
    if (!(key in riskf)) {
      sf = rundir "/sess_" key
      sess=""
      while ((getline sl < sf) > 0) {
        if (index(sl, "sess=") == 1) sess = substr(sl, 6)
      }
      close(sf)
      if (sess == "") next
      riskf[key] = sess "/events_risk.log"
      bizf[key] = sess "/biz_counts.txt"
      resultf[key] = sess "/path_results.log"
      cntf[key] = rundir "/evt_" key
    }

    ts=""
    if (match($0, /[0-9]+\.[0-9]+:/)) ts = substr($0, RSTART, RLENGTH-1)

    isret=0
    op=""
    if (index($0, P "access_ret")) { op="ACCESS"; isret=1 }
    else if (index($0, P "statx_ret")) { op="STAT"; isret=1 }
    else if (index($0, P "stat_ret")) { op="STAT"; isret=1 }
    else if (index($0, P "open_ret")) { op="OPEN"; isret=1 }
    else if (index($0, P "rlink_ret")) { op="RLINK"; isret=1 }
    else if (index($0, P "statx") || index($0, P "stat")) op="STAT"
    else if (index($0, P "access")) op="ACCESS"
    else if (index($0, P "open")) op="OPEN"
    else if (index($0, P "rlink")) op="RLINK"
    else if (index($0, P "conn")) op="CONN"
    else next

    comm=$1

    if (isret) {
      pending_key=pid SUBSEP op
      path=pending[pending_key]
      delete pending[pending_key]
      mode=pending_mode[pending_key]+0
      flags=pending_flags[pending_key]+0
      delete pending_mode[pending_key]
      delete pending_flags[pending_key]
      if (path == "") next
      ret=0
      if (match($0, /ret=-?[0-9]+/)) ret=substr($0, RSTART+4)+0
      if (ret >= 0) state="SUCCESS"
      else if (ret == -2) state="NOT_FOUND"
      else if (ret == -13 || ret == -1) state="DENIED"
      else state="ERROR"
      capability=state
      if (state == "SUCCESS") {
        if (op == "STAT") capability="EXISTS"
        else if (op == "RLINK") capability="READABLE"
        else if (op == "ACCESS") {
          if (mode == 0) capability="EXISTS"
          else if (mode == 4 || mode == 5 || mode == 6 || mode == 7) capability="READABLE"
          else capability="ACCESSIBLE"
        } else if (op == "OPEN") {
          accmode=flags % 4
          if (int(flags / 2097152) % 2 == 1) capability="EXISTS"
          else if (accmode == 0 || accmode == 2) capability="READABLE"
          else capability="WRITABLE"
        }
      }
      print "[" op "] " path " state=" state " capability=" capability " ret=" ret " count=1" >> resultf[key]
      n[key]++
      next
    }

    if (op == "CONN") {
      family=""; ab=""; su=""
      if (match($0, /family=[0-9]+/)) family=substr($0, RSTART+7, RLENGTH-7)
      if (match($0, /abspath="[^"]*"/)) ab=substr($0, RSTART+9, RLENGTH-10)
      if (match($0, /sunpath="[^"]*"/)) su=substr($0, RSTART+9, RLENGTH-10)
      sock=""; mark=""
      if (family=="1") {
        if (ab!="") { sock="@" ab; mark=" <!!ABS>" }
        else if (su!="") { sock=su; mark=" <UNIX>" }
        else { sock="@unix"; mark=" <!!ABS?>" }
      } else if (family=="2") { sock="AF_INET"; mark=" <NET>" }
      else if (family=="10") { sock="AF_INET6"; mark=" <NET>" }
      else sock="AF_" family
      # 系统 socket 合并计数，root 相关 socket 写明细
      if (sock ~ /magisk|ksu|lspd|zygisk|frida|xposed/) {
        mark=" <!!ROOT_SOCK>"
        print "[" ts "][CONN] " comm "  " sock mark >> riskf[key]
        n[key]++
        nrisk[key]++
      } else {
        # fwmarkd/dns 等：只计次
        biz[key SUBSEP "CONN"]++
        n[key]++
      }
      next
    }

    path=""
    if (match($0, /path="[^"]*"/)) path=substr($0, RSTART+6, RLENGTH-7)
    if (path == "" || path !~ /^\// || path == "(fault)") next
    pending[pid SUBSEP op] = path
    if (match($0, /mode=-?[0-9]+/)) pending_mode[pid SUBSEP op]=substr($0, RSTART+5)+0
    if (match($0, /flags=[0-9]+/)) pending_flags[pid SUBSEP op]=substr($0, RSTART+6)+0
    if (noise != "1") {
      if (path=="/dev/null" || path=="/dev/urandom" || path=="/dev/zero") next
    }

    if (is_own_path(path, pkg[pid], user[pid])) {
      if (op=="OPEN" || op=="STAT" || op=="ACCESS") biz[key SUBSEP op]++
      else biz[key SUBSEP "OTHER"]++
      n[key]++
      next
    }

    risk = is_risk_path(path)
    mark=""
    if (path ~ /data\/adb|magisk|\/ksu|\/modules|frida|xposed|lsposed|busybox|lspd/) mark=" <!!ROOT>"
    else if (path ~ /\/maps$/) mark=" <*MAPS>"
    else if (path ~ /cpu_capacity|cpuinfo_max_freq|\/system\/cpu/) mark=" <*CPU>"
    else if (path ~ /^\/sys\/|\/proc\/.*\/(mounts|cmdline|status|fd\/)|\/proc\/self\/|\/proc\/mounts/) mark=" <*SYS>"
    else if (path ~ /data\/local\//) mark=" <*DBG>"

    if (risk || mark != "") {
      print "[" ts "][" op "] " comm "  " path mark >> riskf[key]
      n[key]++
      nrisk[key]++
    } else {
      # 其它系统路径：标 SYS 写入风险日志（量不大）
      if (mark=="") mark=" <*SYS>"
      print "[" ts "][" op "] " comm "  " path mark >> riskf[key]
      n[key]++
      nrisk[key]++
    }
  }
  END {
    total=0
    for (k in n) {
      old=0
      if ((getline old < cntf[k]) > 0) {}
      close(cntf[k])
      print (old + n[k]) > cntf[k]
      close(cntf[k])
      total += n[k]
    }
    # 业务计数：按 key 合并写回 biz_counts.txt
    for (bk in biz) {
      split(bk, bx, SUBSEP)
      k = bx[1]; op = bx[2]
      if (!(k in bizf)) continue
      if (!(k in loaded)) {
        while ((getline bl < bizf[k]) > 0) {
          split(bl, ba, "\t")
          if (ba[1] != "") oldb[k SUBSEP ba[1]] = ba[2]+0
        }
        close(bizf[k])
        loaded[k] = 1
      }
      oldb[k SUBSEP op] += biz[bk]
      dirty[k] = 1
    }
    for (k in dirty) {
      # 清空重写
      print "OPEN\t" (oldb[k SUBSEP "OPEN"]+0) > bizf[k]
      print "STAT\t" (oldb[k SUBSEP "STAT"]+0) >> bizf[k]
      print "ACCESS\t" (oldb[k SUBSEP "ACCESS"]+0) >> bizf[k]
      print "CONN\t" (oldb[k SUBSEP "CONN"]+0) >> bizf[k]
      print "OTHER\t" (oldb[k SUBSEP "OTHER"]+0) >> bizf[k]
      close(bizf[k])
    }
    print total+0
  }
  ' "$RUN_DIR/trace.chunk" 2>/dev/null)

  wrote=$(echo "$wrote" | tr -d ' \r' | sed -n '$p')
  if [ -n "$wrote" ] && [ "$wrote" -gt 0 ] 2>/dev/null; then
    dlog "drain +$wrote events (chunk=${sz}B)"
  fi
  : > "$RUN_DIR/trace.chunk"
}

cleanup_all() {
  dlog "cleanup"
  for st in "$RUN_DIR"/sess_*; do
    [ -f "$st" ] || continue
    stop_session "${st##*/sess_}"
  done
  probe_off
  probe_rm
  bpf_stop
  release_lock
  exit 0
}
trap cleanup_all INT TERM HUP

# ---- main ----
acquire_lock
kill_other_daemons
echo $$ > "$LOCKFILE/pid"
echo $$ > "$PIDFILE"

load_config
export PROBE_PREFIX ENABLE_CONN ENABLE_DEATH
dlog "daemon start v1.4 MODDIR=$MODDIR POLL=$POLL_SEC death=$ENABLE_DEATH pid=$$"
PROBES_LIVE=0
LAST_PIDS=""
probe_rm
echo 0 > "$T/tracing_on" 2>/dev/null
echo > "$T/trace" 2>/dev/null

last_discover=0
last_maintain=0
while true; do
  lp=$(cat "$LOCKFILE/pid" 2>/dev/null)
  [ -n "$lp" ] && [ "$lp" != "$$" ] && exit 0

  now=$(date +%s)
  if [ $((now - last_maintain)) -ge 30 ] || [ "$last_maintain" -eq 0 ]; then
    maintain_storage
    last_maintain=$now
  fi
  if [ $((now - last_discover)) -ge "$POLL_SEC" ] || [ "$last_discover" -eq 0 ]; then
    load_config
    rebuild
    refresh_filter
    last_discover=$now
  fi

  drain_bpf
  drain_trace

  if [ "$PROBES_LIVE" = "1" ]; then
    sleep 0.5
  else
    sleep "$POLL_SEC"
  fi
done
