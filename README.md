# eBPF Stats + EnvProbe

KernelSU / Magisk 模块：对 `scope.list` 内 App 做 kprobe 文件/Socket 统计，按包名会话落盘；自动安装 **EnvProbe**，用普通 App 身份复扫风险路径是否仍可见。

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
    events_risk.log   # 风险事件全文
    biz_counts.txt    # 业务路径合并计数
    paths_risk.txt    # 过滤后的风险路径
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

## 暴露列表含义

模块 kprobe 记到的风险路径，再用 EnvProbe 以普通 App 身份 `exists()` 复扫仍可见的项。

## 版本

- v1.5.2：修复 Windows zip 反斜杠路径；修复 summary 半截；修复 EnvProbe push 源路径

## 限制

- 看不到 Binder Parcel、KeyAttestation、纯 Java/ART 内存检测
- 不替代 HMA / KSU Umount modules 等隐藏方案