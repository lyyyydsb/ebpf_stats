#!/system/bin/sh
# 安装时恢复旧数据并设置权限
SKIPUNZIP=0
ui_print " "
ui_print "********************************"
ui_print "  eBPF Stats WebUI v1.7.4"
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

mkdir -p "$MODPATH/ebpf_statistics" "$MODPATH/run" "$MODPATH/scripts" "$MODPATH/bin" "$MODPATH/lib"
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
  set_perm "$MODPATH/bin/file_monitor" 0 0 0755
  set_perm_recursive "$MODPATH/ebpf_statistics" 0 0 0755 0644
else
  chmod 755 "$MODPATH/service.sh" "$MODPATH/uninstall.sh" 2>/dev/null
  chmod 755 "$MODPATH/scripts"/*.sh 2>/dev/null
  chmod 755 "$MODPATH/bin/file_monitor" 2>/dev/null
fi

ui_print "- MODPATH=$MODPATH"
ui_print "- WebUI 已安装到 KernelSU 模块页面"

ui_print " "
ui_print "- 编辑 scope.list 添加包名 (支持 包名:用户)"
ui_print "- 重启后自动监控"
ui_print "- 数据: /data/adb/modules/ebpf_stats/ebpf_statistics/"
ui_print "- 查看: 在 KernelSU Manager 打开本模块 WebUI"
ui_print " "
