# eBPF Stats WebUI v1.7.4

## 刷入后

1. 重启
2. 编辑 `/data/adb/modules/ebpf_stats/scope.list` 加包名
3. 打开目标 App → 杀后台 → 自动出汇总
4. 在 KernelSU Manager 打开本模块 WebUI → 查看真实返回结果

## 目录

```
/data/adb/modules/ebpf_stats/
  scope.list / config.prop / scripts/ / bin/ / lib/
  ebpf_statistics/<包>_u0/session_*/
    events_risk.log   # 外部路径事件（兼容旧文件名）
    biz_counts.txt    # 自身私有路径合并计数
    vfs_events.log   # security_inode_permission 每秒聚合
    paths_external.txt
    summary.txt
    paths_risk.txt
  webroot/index.html   # KernelSU WebUI 主入口
```

v1.7.0 在原 tracefs 路径探针之外增加 BPF kprobe，挂载
`security_inode_permission` 并按 TGID 聚合读、写、执行、打开和权限检查次数。
同时对 open/stat/access/readlink 增加返回值配对，结果分为 `SUCCESS`、`NOT_FOUND`、
`DENIED` 和 `ERROR`；能力进一步标注为 `EXISTS`、`READABLE`、`WRITABLE` 或
`ACCESSIBLE`，不会把单纯的 stat 成功误报成内容可读。

v1.7.1 修复 WebUI 未打包导致一直加载的问题，并增加存储控制：结果达到 512KB
自动按相同结果聚合、每个软件保留 3 个会话、latest 使用软链接、daemon 日志轮转。

v1.7.2 在 WebUI 中按高风险、中风险、低风险和未命中分组。敏感路径只有在
实际访问成功时才列为高风险；四组均支持独立折叠，并提供全部展开和全部折叠。

v1.7.3 将详情控制栏固定在页面顶部，并增加常驻的全部折叠和回到顶部按钮，
长列表中无需返回开头操作。

v1.7.4 改为当前展开的风险标题吸顶，点击吸顶标题即可折叠当前分组；全局工具栏
恢复普通滚动。详情支持导出完整摘要、路径结果和 VFS 数据到 `/sdcard/Download/`。

## 命令

```sh
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh status
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh push
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh restart
```

## 路径状态含义

- `SUCCESS + EXISTS`：路径存在，但尚未证明内容可读
- `SUCCESS + READABLE`：目标 App 成功以读取方式打开或读取链接
- `SUCCESS + WRITABLE`：目标 App 成功以写入方式打开
- `NOT_FOUND`：目标 App 的实际系统调用返回 `ENOENT`
- `DENIED`：实际返回 `EACCES` 或 `EPERM`
- `ERROR`：其他系统调用错误

WebUI 风险分组：

- 高风险：Root、注入或调试产物实际访问成功
- 中风险：系统环境探针、权限拒绝或结果不确定
- 低风险：普通系统文件和运行时依赖
- 未命中：目标软件探测过，但路径不存在

## 兼容性

已验证 ARM64 Android 15 / Linux 6.6 / KernelSU。其他设备需要可用的 tracefs、
kprobe、kretprobe、BPF ring buffer 以及对应内核符号；不满足时部分探针会不可用。
