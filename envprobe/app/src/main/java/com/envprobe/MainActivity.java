package com.envprobe;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 按包名分开展示；只列「有问题」的路径。
 * 数据来自: files/from_module/by_pkg/<pkg>_uN/paths_risk.txt
 */
public class MainActivity extends Activity {

    private TextView tvSummary;
    private TextView tvResult;
    private ScrollView scroll;
    private String lastReport = "";

    // 无模块数据时的兜底探针（也只测风险）
    private static final String[] BUILTIN_RISK = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/bin/magisk", "/sbin/magisk",
            "/data/adb", "/data/adb/ksu", "/data/adb/modules", "/data/adb/lspd",
            "/data/adb/magisk",
            "/sbin/.magisk/modules/zygisk_lsposed",
            "/system/lib64/libriruloader.so", "/system/xposed.prop",
            "/sys/fs/selinux/enforce", "/proc/mounts"
    };

    private static final String[] SUS_PKGS = {
            "me.weishu.kernelsu", "org.frknkrc44.hma_oss",
            "icu.nullptr.applistdetector", "org.lsposed.manager",
            "bin.mt.plus", "com.topjohnwu.magisk"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.activity_main);

        View root = findViewById(R.id.root);
        if (root != null) root.setBackgroundColor(Color.WHITE);
        if (Build.VERSION.SDK_INT >= 23) {
            getWindow().setStatusBarColor(Color.WHITE);
            getWindow().getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LAYOUT_STABLE);
        }

        tvSummary = findViewById(R.id.tvSummary);
        tvResult = findViewById(R.id.tvResult);
        scroll = findViewById(R.id.scroll);
        findViewById(R.id.btnScan).setOnClickListener(v -> runScan());
        findViewById(R.id.btnShare).setOnClickListener(v -> share());

        File byPkg = new File(getFilesDir(), "from_module/by_pkg");
        int n = byPkg.isDirectory() && byPkg.list() != null ? byPkg.list().length : 0;
        if (n > 0) {
            tvSummary.setText("已有 " + n + " 个软件的风险路径，点「开始扫描」");
            tvResult.setText("目录: " + byPkg.getAbsolutePath()
                    + "\n\n只显示有问题的路径（su/magisk/lspd/modules…）\n"
                    + "业务内部目录不会列出。");
        } else {
            tvSummary.setText("暂无模块数据（或先 ctl.sh push）");
            tvResult.setText("用法:\n1. ebpf 监控目标 App 后杀后台\n"
                    + "2. 或: su 0 sh .../ctl.sh push\n"
                    + "3. 再点扫描\n\n也可扫内置风险表。");
        }
    }

    private void runScan() {
        tvSummary.setText("扫描中…");
        tvResult.setText("扫描中…");
        new Thread(() -> {
            final String report = buildReport();
            runOnUiThread(() -> {
                lastReport = report;
                tvResult.setText(report);
                tvSummary.setText(summaryLine(report));
                if (scroll != null) scroll.post(() -> scroll.scrollTo(0, 0));
                Toast.makeText(this, "完成", Toast.LENGTH_SHORT).show();
            });
        }).start();
    }

    private static String summaryLine(String report) {
        int apps = 0, problems = 0, clean = 0;
        for (String line : report.split("\n")) {
            if (line.startsWith("## ")) apps++;
            if (line.startsWith("问题数:")) {
                try {
                    int n = Integer.parseInt(line.replaceAll("[^0-9]", ""));
                    if (n > 0) problems++;
                    else clean++;
                } catch (Exception ignored) {
                }
            }
        }
        return String.format(Locale.CHINA, "软件 %d | 有问题 %d | 干净 %d",
                apps, problems, clean);
    }

    private String buildReport() {
        StringBuilder sb = new StringBuilder();
        File base = new File(getFilesDir(), "from_module");
        File byPkg = new File(base, "by_pkg");
        File index = new File(base, "index.txt");

        sb.append("EnvProbe 风险报告（仅问题项）\n");
        sb.append("uid=").append(android.os.Process.myUid()).append('\n');
        sb.append("时间=").append(System.currentTimeMillis()).append("\n\n");

        // 收集要扫的包列表
        List<String> keys = new ArrayList<>();
        if (index.exists()) {
            keys.addAll(readLines(index));
        }
        if (byPkg.isDirectory() && byPkg.list() != null) {
            String[] dirs = byPkg.list();
            if (dirs != null) {
                Arrays.sort(dirs);
                for (String d : dirs) {
                    if (!keys.contains(d) && new File(byPkg, d).isDirectory()) {
                        keys.add(d);
                    }
                }
            }
        }

        if (keys.isEmpty()) {
            sb.append("（无 by_pkg 数据，使用内置风险表作全局自检）\n\n");
            sb.append(scanOne("【内置表】本机 App 视角", null, Arrays.asList(BUILTIN_RISK)));
            sb.append(scanPackages());
            return sb.toString();
        }

        int problemApps = 0;
        for (String key : keys) {
            File dir = new File(byPkg, key);
            File riskFile = new File(dir, "paths_risk.txt");
            File meta = new File(dir, "meta.txt");
            List<String> paths = new ArrayList<>();
            if (riskFile.exists()) {
                paths.addAll(readLines(riskFile));
            }
            // 没有风险文件则跳过全量，只加内置
            for (String p : BUILTIN_RISK) {
                if (!paths.contains(p)) paths.add(p);
            }

            String pkgName = key;
            String user = "?";
            int idx = key.lastIndexOf("_u");
            if (idx > 0) {
                pkgName = key.substring(0, idx);
                user = key.substring(idx + 2);
            }
            String metaStr = meta.exists() ? readAll(meta).trim() : "";

            String block = scanOne(pkgName + "  (用户 u" + user + ")", metaStr, paths);
            if (block.contains("问题数: 0")) {
                sb.append("## ").append(pkgName).append(" u").append(user)
                        .append("\n状态: 干净（App 身份看不到风险路径）\n\n");
            } else {
                problemApps++;
                sb.append(block).append('\n');
            }
        }

        sb.append(scanPackages());
        sb.append("\n—— 共 ").append(keys.size()).append(" 个软件，")
                .append(problemApps).append(" 个有问题 ——\n");
        return sb.toString();
    }

    /** 对一组路径以 App 身份 exists，只输出命中的问题路径 */
    private String scanOne(String title, String meta, List<String> paths) {
        StringBuilder sb = new StringBuilder();
        sb.append("## ").append(title).append('\n');
        if (meta != null && !meta.isEmpty()) {
            for (String line : meta.split("\n")) {
                if (line.startsWith("paths_risk=") || line.startsWith("exported=")
                        || line.startsWith("session=")) {
                    sb.append(line).append('\n');
                }
            }
        }

        List<String> hits = new ArrayList<>();
        int checked = 0;
        for (String path : paths) {
            if (path == null || !path.startsWith("/")) continue;
            // 双保险：业务目录直接跳过
            if (isBizPath(path)) continue;
            if (!isRisk(path)) continue;
            checked++;
            File f = new File(path);
            boolean ex;
            try {
                ex = f.exists();
            } catch (Throwable t) {
                continue;
            }
            if (ex) {
                String tag = riskTag(path);
                hits.add("[" + tag + "] " + path);
            }
        }

        sb.append("候选风险路径: ").append(checked).append('\n');
        sb.append("问题数: ").append(hits.size()).append('\n');
        if (hits.isEmpty()) {
            sb.append("（App 身份复扫：均不可见）\n");
        } else {
            // 暴露 = 模块记录的风险路径里，本 App 用 exists() 仍能看到的
            sb.append("暴露列表（= 以本 App 身份 exists 仍为 true）:\n");
            for (String h : hits) sb.append("  ").append(h).append('\n');
        }
        return sb.toString();
    }

    private String scanPackages() {
        StringBuilder sb = new StringBuilder();
        sb.append("## 可疑包名（应用列表）\n");
        PackageManager pm = getPackageManager();
        int n = 0;
        for (String pkg : SUS_PKGS) {
            try {
                ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                n++;
                sb.append("  [包] ").append(pkg).append('\n');
            } catch (PackageManager.NameNotFoundException e) {
                // 隐藏成功
            } catch (Throwable ignored) {
            }
        }
        if (n == 0) sb.append("  （均不可见，HMA/隐藏有效）\n");
        sb.append("包问题数: ").append(n).append('\n');
        return sb.toString();
    }

    private static boolean isBizPath(String path) {
        return path.startsWith("/data/user/")
                || path.startsWith("/data/data/")
                || path.startsWith("/storage/")
                || path.startsWith("/sdcard/")
                || path.startsWith("/mnt/expand/");
    }

    private static boolean isRisk(String path) {
        String p = path.toLowerCase(Locale.US);
        return p.contains("magisk") || p.contains("ksu") || p.contains("kernelsu")
                || p.contains("xposed") || p.contains("lsposed") || p.contains("lspd")
                || p.contains("zygisk") || p.contains("frida") || p.contains("riru")
                || p.contains("shamiko") || p.contains("tricky")
                || p.contains("/data/adb") || p.endsWith("/su") || p.contains("/su/")
                || p.contains("busybox") || p.contains("modules")
                || p.contains("selinux") || p.contains("/proc/mounts")
                || p.contains("/proc/self/maps") || p.contains("data/local/tmp")
                || p.contains("data/local/su") || p.contains("libriruloader");
    }

    private static String riskTag(String path) {
        String p = path.toLowerCase(Locale.US);
        if (p.endsWith("/su") || p.contains("/su/")) return "SU";
        if (p.contains("magisk")) return "MAGISK";
        if (p.contains("lspd") || p.contains("lsposed") || p.contains("xposed")) return "LSP";
        if (p.contains("ksu") || p.contains("kernelsu")) return "KSU";
        if (p.contains("zygisk")) return "ZYGISK";
        if (p.contains("modules") || p.contains("/data/adb")) return "ADB";
        if (p.contains("selinux")) return "SELINUX";
        if (p.contains("mounts")) return "MOUNTS";
        if (p.contains("maps")) return "MAPS";
        if (p.contains("frida")) return "FRIDA";
        return "RISK";
    }

    private static List<String> readLines(File f) {
        List<String> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.matches("^\\d+\\s+/.*")) {
                    int sp = line.indexOf('/');
                    if (sp >= 0) line = line.substring(sp);
                }
                if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("===")) {
                    out.add(line);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String readAll(File f) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        } catch (Throwable t) {
            return "";
        }
        return sb.toString();
    }

    private void share() {
        if (lastReport == null || lastReport.isEmpty()) {
            Toast.makeText(this, "请先扫描", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_SUBJECT, "EnvProbe");
        i.putExtra(Intent.EXTRA_TEXT, lastReport);
        startActivity(Intent.createChooser(i, "分享"));
    }
}
