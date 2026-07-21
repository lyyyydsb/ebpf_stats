#!/system/bin/sh
# 卸载本模块全部 kprobe
T="/sys/kernel/tracing"
[ -d "$T" ] || T="/sys/kernel/debug/tracing"
[ -d "$T" ] || exit 0

PREFIX="es_"
[ -n "$1" ] && PREFIX="$1"

echo 0 > "$T/tracing_on" 2>/dev/null

if [ -d "$T/events/kprobes" ]; then
  for d in "$T/events/kprobes"/${PREFIX}*; do
    [ -f "$d/enable" ] && echo 0 > "$d/enable" 2>/dev/null
  done
fi

for n in ${PREFIX}access ${PREFIX}stat ${PREFIX}statx ${PREFIX}open ${PREFIX}rlink \
         ${PREFIX}conn ${PREFIX}exit ${PREFIX}tgkill ${PREFIX}kill ${PREFIX}sig; do
  echo "-:$n" > "$T/kprobe_events" 2>/dev/null
done
sleep 0.1

# 仅清本前缀
if [ -f "$T/kprobe_events" ]; then
  tmp="/dev/es_kp_tmp_$$"
  grep -v ":${PREFIX}" "$T/kprobe_events" > "$tmp" 2>/dev/null
  echo > "$T/kprobe_events" 2>/dev/null
  if [ -s "$tmp" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      echo "$line" >> "$T/kprobe_events" 2>/dev/null
    done < "$tmp"
  fi
  rm -f "$tmp"
fi
