#!/system/bin/sh
MODDIR="${MODDIR:-${0%/*}/..}"
RUN_DIR="$MODDIR/run"
STATS_ROOT="$MODDIR/ebpf_statistics"

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    VFS\ *) ;;
    *) continue ;;
  esac
  tgid=""
  for token in $line; do
    case "$token" in
      tgid=*) tgid=${token#tgid=} ;;
    esac
  done
  case "$tgid" in ''|*[!0-9]*) continue ;; esac
  map=$(awk -v t="$tgid" '$1==t{print $2, $3; exit}' "$RUN_DIR/tidmap" 2>/dev/null)
  set -- $map
  pkg="$1"
  user="$2"
  [ -n "$pkg" ] && [ -n "$user" ] || continue
  key="${pkg}_u${user}"
  sess=$(sed -n 's/^sess=//p' "$RUN_DIR/sess_$key" 2>/dev/null)
  [ -n "$sess" ] || continue
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >> "$sess/vfs_events.log"
done
