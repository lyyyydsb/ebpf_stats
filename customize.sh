#!/system/bin/sh
# 安装时：恢复旧数据、装权限、安装 EnvProbe APK
SKIPUNZIP=0
ui_print " "
ui_print "********************************"
ui_print "  eBPF Stats + EnvProbe v1.5.5"
ui_print "********************************"
ui_print " "

OLD_MOD="/data/adb/modules/ebpf_stats"
if [ -d "$OLD_MOD/ebpf_statistics" ] && [ "$(ls -A "$OLD_MOD/ebpf_statistics" 2>/dev/null)" ]; then
  ui_print "- 备份已有统计数据..."
  mkdir -p "$TMPDIR/ebpf_stats_bak"
  cp -a "$OLD_MOD/ebpf_statistics/." "$TMPDIR/ebpf_stats_bak/" 2>/dev/null
fi
if [ -f "$OLD_MOD/scope.list" ]; then
  cp -af "$OLD_MOD/scope.list" "$TMPDIR/scope.list.bak" 2>/dev/null
fi
if [ -f "$OLD_MOD/config.prop" ]; then
  cp -af "$OLD_MOD/config.prop" "$TMPDIR/config.prop.bak" 2>/dev/null
fi

if [ -d "$TMPDIR/ebpf_stats_bak" ]; then
  mkdir -p "$MODPATH/ebpf_statistics"
  cp -a "$TMPDIR/ebpf_stats_bak/." "$MODPATH/ebpf_statistics/" 2>/dev/null
  ui_print "- 已恢复 ebpf_statistics"
fi
if [ -f "$TMPDIR/scope.list.bak" ]; then
  cp -af "$TMPDIR/scope.list.bak" "$MODPATH/scope.list"
  ui_print "- 已保留 scope.list"
fi
if [ -f "$TMPDIR/config.prop.bak" ]; then
  cp -af "$TMPDIR/config.prop.bak" "$MODPATH/config.prop"
  ui_print "- 已保留 config.prop"
fi

mkdir -p "$MODPATH/ebpf_statistics" "$MODPATH/run" "$MODPATH/apk" "$MODPATH/scripts"

# 兼容错误 zip（反斜杠文件名）自动修复
if [ ! -f "$MODPATH/apk/EnvProbe.apk" ]; then
  for bad in "$MODPATH"/apk\\EnvProbe.apk "$MODPATH"/apk*EnvProbe.apk; do
    [ -f "$bad" ] || continue
    ui_print "- 修复 APK 路径: $bad"
    mkdir -p "$MODPATH/apk"
    mv -f "$bad" "$MODPATH/apk/EnvProbe.apk" 2>/dev/null || cp -f "$bad" "$MODPATH/apk/EnvProbe.apk"
  done
fi
for s in daemon probe cleanup ctl check_status; do
  if [ ! -f "$MODPATH/scripts/${s}.sh" ]; then
    for bad in "$MODPATH"/scripts\\${s}.sh "$MODPATH"/scripts*${s}.sh; do
      [ -f "$bad" ] || continue
      mkdir -p "$MODPATH/scripts"
      mv -f "$bad" "$MODPATH/scripts/${s}.sh" 2>/dev/null || cp -f "$bad" "$MODPATH/scripts/${s}.sh"
    done
  fi
done

if command -v set_perm_recursive >/dev/null 2>&1; then
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  set_perm_recursive "$MODPATH/scripts" 0 0 0755 0755
  set_perm "$MODPATH/service.sh" 0 0 0755
  set_perm "$MODPATH/uninstall.sh" 0 0 0755
  set_perm_recursive "$MODPATH/ebpf_statistics" 0 0 0755 0644
else
  chmod 755 "$MODPATH/service.sh" "$MODPATH/uninstall.sh" 2>/dev/null
  chmod 755 "$MODPATH/scripts"/*.sh 2>/dev/null
fi

APK=""
for c in \
  "$MODPATH/apk/EnvProbe.apk" \
  "$MODPATH/EnvProbe.apk" \
  "$MODPATH/system/priv-app/EnvProbe/EnvProbe.apk"
do
  [ -f "$c" ] && APK="$c" && break
done

ui_print "- MODPATH=$MODPATH"
ui_print "- 查找 APK: $(ls -la "$MODPATH/apk" 2>/dev/null | tr '\n' ' ')"

if [ -n "$APK" ] && [ -f "$APK" ]; then
  ui_print "- 安装 EnvProbe: $APK"
  cp -f "$APK" /data/local/tmp/EnvProbe.apk 2>/dev/null
  chmod 644 /data/local/tmp/EnvProbe.apk 2>/dev/null
  ok=0
  out=""
  if out=$(pm install -r -t -g /data/local/tmp/EnvProbe.apk 2>&1); then
    ok=1
  elif out=$(pm install -r -t /data/local/tmp/EnvProbe.apk 2>&1); then
    ok=1
  elif out=$(/system/bin/pm install -r -t /data/local/tmp/EnvProbe.apk 2>&1); then
    ok=1
  elif out=$(cmd package install -r -t /data/local/tmp/EnvProbe.apk 2>&1); then
    ok=1
  fi
  if [ "$ok" = "1" ]; then
    ui_print "- EnvProbe 安装成功 (com.envprobe)"
  else
    ui_print "! EnvProbe 安装失败: $out"
    ui_print "  开机 service 会重试"
  fi
else
  ui_print "! 未找到 EnvProbe.apk"
  ui_print "  ls MODPATH: $(ls "$MODPATH" 2>/dev/null | tr '\n' ' ')"
fi

ui_print " "
ui_print "- 编辑 scope.list 添加包名 (支持 包名:用户)"
ui_print "- 重启后自动监控"
ui_print "- 数据: /data/adb/modules/ebpf_stats/ebpf_statistics/"
ui_print "- 复扫: 打开 EnvProbe App"
ui_print " "
