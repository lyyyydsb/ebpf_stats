# eBPF Stats + EnvProbe

KernelSU / Magisk 模块：对 `scope.list` 内 App 做 kprobe 文件/Socket 统计，按包名会话落盘；自动安装 **EnvProbe**，逐项复扫目标实际访问的外部路径是否可见。

## 安装

1. 下载 Release 中的 `ebpf_stats_EnvProbe_vX.Y.Z.zip`
2. KernelSU / Magisk → 模块 → 从本地安装 → 重启
3. 编辑 `/data/adb/modules/ebpf_stats/scope.list` 添加包名
4. 打开目标 App → 杀后台 → 打开 **EnvProbe** 点扫描

## 目录

```
/data/adb/modules/ebpf_stats/
  scope.list / config.prop / scripts/
  ebpf_statistics/<包>_u0/session_*/
    events_risk.log   # 外部路径事件（兼容旧文件名）
    biz_counts.txt    # 自身私有路径合并计数
    paths_external.txt # 实际探测的全部外部路径
    paths_risk.txt    # 过滤后的风险路径
    unique_external.txt
    unique_risk.txt   # 路径频次
    socks.txt         # root 相关 socket
    summary.txt       # 汇总
  apk/EnvProbe.apk
```

EnvProbe 数据：`/data/data/com.envprobe/files/from_module/by_pkg/<包>_uN/`

## 命令

```sh
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh status
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh push
su 0 sh /data/adb/modules/ebpf_stats/scripts/ctl.sh restart
```

## 路径状态含义

模块排除目标自身 `/proc` 和私有目录后生成 `paths_external.txt`。EnvProbe 对每条路径执行 `exists()`：

- `可见`：`exists=true`
- `不可见`：`exists=false`
- `环境特征`：可见路径同时命中 su/Magisk/KSU/LSPosed 等特征词

## 版本

- v1.5.3：按目标实际外部路径全量复扫；按软件分组；软件、可见列表、不可见列表均可独立折叠
- v1.5.2：修复 Windows zip 反斜杠路径；修复 summary 半截；修复 EnvProbe push 源路径

## 限制

- 看不到 Binder Parcel、KeyAttestation、纯 Java/ART 内存检测
- 不替代 HMA / KSU Umount modules 等隐藏方案
