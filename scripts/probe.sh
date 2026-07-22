#!/system/bin/sh
# kprobe 注册/启停
T="${TRACE_DIR:-/sys/kernel/tracing}"
[ -d "$T" ] || T="/sys/kernel/debug/tracing"
P="${PROBE_PREFIX:-es_}"
ENABLE_CONN="${ENABLE_CONN:-1}"
ENABLE_DEATH="${ENABLE_DEATH:-0}"

PROBE_NAMES="${P}access ${P}access_ret ${P}stat ${P}stat_ret ${P}statx ${P}statx_ret ${P}open ${P}open_ret ${P}rlink ${P}rlink_ret ${P}conn ${P}exit ${P}tgkill ${P}kill"

probe_rm() {
  if [ -d "$T/events/kprobes" ]; then
    for d in "$T/events/kprobes"/${P}*; do
      [ -f "$d/enable" ] && echo 0 > "$d/enable" 2>/dev/null
    done
  fi
  for n in $PROBE_NAMES; do
    echo "-:$n" > "$T/kprobe_events" 2>/dev/null
  done
  for n in ${P}access ${P}access_ret ${P}stat ${P}stat_ret ${P}statx ${P}statx_ret ${P}open ${P}open_ret ${P}rlink ${P}rlink_ret ${P}conn ${P}exit ${P}tgkill ${P}kill; do
    echo "-:$n" > "$T/kprobe_events" 2>/dev/null
  done
  sleep 0.1
}

probe_add_one() {
  name="$1"
  rest="$2"
  first="$3"
  line="p:$name $rest"
  if [ "$first" = "1" ]; then
    echo "$line" > "$T/kprobe_events" 2>/dev/null || return 1
  else
    echo "$line" >> "$T/kprobe_events" 2>/dev/null || return 1
  fi
  grep -q "$name" "$T/kprobe_events" 2>/dev/null || return 1
  i=0
  while [ $i -lt 50 ]; do
    if [ -f "$T/events/kprobes/$name/enable" ]; then
      echo 1 > "$T/events/kprobes/$name/enable"
      return 0
    fi
    i=$((i + 1))
    usleep 20000 2>/dev/null || sleep 0.02
  done
  return 1
}

probe_add_ret() {
  name="$1"
  func="$2"
  line="r:$name $func ret=\$retval:s64"
  echo "$line" >> "$T/kprobe_events" 2>/dev/null || return 1
  grep -q "$name" "$T/kprobe_events" 2>/dev/null || return 1
  i=0
  while [ $i -lt 50 ]; do
    if [ -f "$T/events/kprobes/$name/enable" ]; then
      echo 1 > "$T/events/kprobes/$name/enable"
      return 0
    fi
    i=$((i + 1))
    usleep 20000 2>/dev/null || sleep 0.02
  done
  return 1
}

probe_setup() {
  # 关键：先关 tracing，再动探针；期间 set_event_pid 保持由调用方设置
  echo 0 > "$T/tracing_on" 2>/dev/null
  echo > "$T/trace" 2>/dev/null
  probe_rm
  sleep 0.2

  ok=0
  first=1

  if probe_add_one "${P}access" "do_faccessat path=+0(%x1):string mode=%x2:s32" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}access_ret" "do_faccessat" && ok=$((ok + 1))
  fi
  if probe_add_one "${P}stat" "vfs_fstatat path=+0(%x1):string" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}stat_ret" "vfs_fstatat" && ok=$((ok + 1))
  fi
  if probe_add_one "${P}statx" "vfs_statx path=+0(%x1):string" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}statx_ret" "vfs_statx" && ok=$((ok + 1))
  fi
  if probe_add_one "${P}open" "do_sys_openat2 path=+0(%x1):string flags=+0(%x2):u64" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}open_ret" "do_sys_openat2" && ok=$((ok + 1))
  fi
  if probe_add_one "${P}rlink" "do_readlinkat path=+0(%x1):string" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}rlink_ret" "do_readlinkat" && ok=$((ok + 1))
  elif probe_add_one "${P}rlink" "vfs_readlink path=+0(%x0):string" "$first"; then
    first=0; ok=$((ok + 1))
    probe_add_ret "${P}rlink_ret" "vfs_readlink" && ok=$((ok + 1))
  fi

  if [ "$ENABLE_CONN" = "1" ]; then
    if probe_add_one "${P}conn" "__sys_connect fd=%x0 family=+0(%x1):u16 abspath=+3(%x1):string sunpath=+2(%x1):string" "$first"; then
      first=0; ok=$((ok + 1))
    elif probe_add_one "${P}conn" "__arm64_sys_connect fd=+0(+0(%x0)):u32 family=+0(+8(%x0)):u16 abspath=+3(+8(%x0)):string" "$first"; then
      first=0; ok=$((ok + 1))
    fi
  fi

  if [ "$ENABLE_DEATH" = "1" ]; then
    if probe_add_one "${P}exit" "do_group_exit code=%x0:s32" "$first"; then
      first=0; ok=$((ok + 1))
    fi
  fi

  echo "$ok"
}

# 写 set_event_pid：先清空再写；必须在 tracing_on=0 时调用更安全
probe_set_pids() {
  echo 0 > "$T/tracing_on" 2>/dev/null
  echo > "$T/set_event_pid" 2>/dev/null
  n=0
  for t in $1; do
    case "$t" in *[!0-9]*|'') continue ;; esac
    echo "$t" >> "$T/set_event_pid" 2>/dev/null
    n=$((n + 1))
  done
  # 小缓冲，防止刷爆
  echo 4096 > "$T/buffer_size_kb" 2>/dev/null
  echo > "$T/trace" 2>/dev/null
  echo "$n"
}

probe_on() {
  echo 4096 > "$T/buffer_size_kb" 2>/dev/null
  echo > "$T/trace" 2>/dev/null
  echo 1 > "$T/tracing_on" 2>/dev/null
}

probe_off() {
  echo 0 > "$T/tracing_on" 2>/dev/null
  echo > "$T/set_event_pid" 2>/dev/null
  echo > "$T/trace" 2>/dev/null
}
