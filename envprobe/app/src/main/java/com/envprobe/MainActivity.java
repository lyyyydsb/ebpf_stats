package com.envprobe;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.LinearLayout;
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
 * 按包名展示目标实际探测的全部外部路径，并逐项标记当前 App 身份是否可见。
 * 数据来自: files/from_module/by_pkg/<pkg>_uN/paths_external.txt
 */
public class MainActivity extends Activity {

    private TextView tvSummary;
    private LinearLayout resultsContainer;
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
        resultsContainer = findViewById(R.id.resultsContainer);
        scroll = findViewById(R.id.scroll);
        findViewById(R.id.btnScan).setOnClickListener(v -> runScan());
        findViewById(R.id.btnShare).setOnClickListener(v -> share());

        File byPkg = new File(getFilesDir(), "from_module/by_pkg");
        int n = byPkg.isDirectory() && byPkg.list() != null ? byPkg.list().length : 0;
        if (n > 0) {
            tvSummary.setText("已有 " + n + " 个软件的外部路径，点「开始扫描」");
            showMessage("目录: " + byPkg.getAbsolutePath()
                    + "\n\n逐项显示目标实际探测的外部路径：\n"
                    + "可见（exists=true）/ 不可见（exists=false）。");
        } else {
            tvSummary.setText("暂无模块数据（或先 ctl.sh push）");
            showMessage("用法:\n1. ebpf 监控目标 App 后杀后台\n"
                    + "2. 或: su 0 sh .../ctl.sh push\n"
                    + "3. 再点扫描\n\n也可扫内置风险表。");
        }
    }

    private void runScan() {
        tvSummary.setText("扫描中…");
        showMessage("正在逐项检查路径…");
        new Thread(() -> {
            final String report = buildReport();
            runOnUiThread(() -> {
                lastReport = report;
                renderReport(report);
                tvSummary.setText(summaryLine(report));
                if (scroll != null) scroll.post(() -> scroll.scrollTo(0, 0));
                Toast.makeText(this, "完成", Toast.LENGTH_SHORT).show();
            });
        }).start();
    }

    private void showMessage(String message) {
        resultsContainer.removeAllViews();
        TextView text = createText(message, 14, Color.rgb(45, 55, 72));
        text.setPadding(dp(4), dp(8), dp(4), dp(8));
        resultsContainer.addView(text);
    }

    private void renderReport(String report) {
        resultsContainer.removeAllViews();
        String title = null;
        List<String> info = new ArrayList<>();
        List<String> visible = new ArrayList<>();
        List<String> invisible = new ArrayList<>();
        boolean footer = false;
        List<String> footerLines = new ArrayList<>();

        for (String line : report.split("\n")) {
            if (line.startsWith("## ")) {
                if (title != null) addAppCard(title, info, visible, invisible,
                        resultsContainer.getChildCount() == 0);
                title = line.substring(3).trim();
                info = new ArrayList<>();
                visible = new ArrayList<>();
                invisible = new ArrayList<>();
                footer = false;
            } else if (line.startsWith("### ")) {
                footer = true;
                footerLines.add(line.substring(4));
            } else if (line.startsWith("  [可见]")) {
                visible.add(line.trim());
            } else if (line.startsWith("  [不可见]")) {
                invisible.add(line.trim());
            } else if (footer) {
                if (!line.trim().isEmpty()) footerLines.add(line.trim());
            } else if (title != null && !line.equals("路径明细:") && !line.trim().isEmpty()) {
                info.add(line);
            }
        }
        if (title != null) addAppCard(title, info, visible, invisible,
                resultsContainer.getChildCount() == 0);
        if (!footerLines.isEmpty()) addFooterCard(footerLines);
    }

    private void addAppCard(String title, List<String> info, List<String> visible,
                            List<String> invisible, boolean expanded) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(1), dp(1), dp(1), dp(1));
        card.setBackground(rounded(Color.rgb(213, 220, 232), 12));
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, dp(12));
        resultsContainer.addView(card, cardParams);

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(10), dp(8), dp(10), dp(10));
        body.setBackgroundColor(Color.WHITE);

        TextView header = createText("", 16, Color.WHITE);
        header.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(12), dp(11), dp(12), dp(11));
        header.setBackground(rounded(Color.rgb(32, 48, 73), 11));
        updateToggleTitle(header, expanded, title, visible.size(), invisible.size());
        header.setOnClickListener(v -> {
            boolean show = body.getVisibility() != View.VISIBLE;
            body.setVisibility(show ? View.VISIBLE : View.GONE);
            updateToggleTitle(header, show, title, visible.size(), invisible.size());
        });
        card.addView(header);

        if (!info.isEmpty()) {
            TextView meta = createText(join(info), 12, Color.rgb(77, 88, 106));
            meta.setPadding(dp(2), 0, dp(2), dp(8));
            body.addView(meta);
        }
        addPathSection(body, "可见", visible, Color.rgb(34, 111, 75), Color.rgb(231, 246, 237));
        addPathSection(body, "不可见", invisible, Color.rgb(76, 87, 104), Color.rgb(241, 244, 248));
        body.setVisibility(expanded ? View.VISIBLE : View.GONE);
        card.addView(body);
    }

    private void addPathSection(LinearLayout parent, String label, List<String> paths,
                                int accent, int background) {
        LinearLayout pathBody = new LinearLayout(this);
        pathBody.setOrientation(LinearLayout.VERTICAL);
        pathBody.setVisibility(View.GONE);

        TextView header = createText("▶ " + label + "  " + paths.size(), 14, accent);
        header.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        header.setPadding(dp(10), dp(10), dp(10), dp(10));
        header.setBackground(rounded(background, 9));
        header.setOnClickListener(v -> {
            boolean show = pathBody.getVisibility() != View.VISIBLE;
            pathBody.setVisibility(show ? View.VISIBLE : View.GONE);
            header.setText((show ? "▼ " : "▶ ") + label + "  " + paths.size());
        });

        LinearLayout.LayoutParams headerParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        headerParams.setMargins(0, dp(5), 0, 0);
        parent.addView(header, headerParams);

        TextView content = createText(paths.isEmpty() ? "无" : join(paths), 12,
                Color.rgb(32, 38, 48));
        content.setTypeface(Typeface.MONOSPACE);
        content.setTextIsSelectable(true);
        content.setPadding(dp(10), dp(8), dp(6), dp(10));
        pathBody.addView(content);
        parent.addView(pathBody);
    }

    private void addFooterCard(List<String> lines) {
        TextView footer = createText(join(lines), 12, Color.rgb(77, 88, 106));
        footer.setPadding(dp(10), dp(10), dp(10), dp(10));
        footer.setBackground(rounded(Color.rgb(241, 244, 248), 9));
        resultsContainer.addView(footer);
    }

    private void updateToggleTitle(TextView view, boolean expanded, String title,
                                   int visible, int invisible) {
        view.setText((expanded ? "▼ " : "▶ ") + title
                + "\n可见 " + visible + "  ·  不可见 " + invisible);
    }

    private TextView createText(String value, float size, int color) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextSize(size);
        text.setTextColor(color);
        text.setLineSpacing(dp(2), 1f);
        return text;
    }

    private GradientDrawable rounded(int color, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        return drawable;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static String join(List<String> lines) {
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            if (out.length() > 0) out.append('\n');
            out.append(line);
        }
        return out.toString();
    }

    private static String summaryLine(String report) {
        int apps = 0, featureHits = 0, clean = 0;
        for (String line : report.split("\n")) {
            if (line.startsWith("## ")) apps++;
            if (line.startsWith("环境特征可见:")) {
                try {
                    int n = Integer.parseInt(line.replaceAll("[^0-9]", ""));
                    if (n > 0) featureHits++;
                    else clean++;
                } catch (Exception ignored) {
                }
            }
        }
        return String.format(Locale.CHINA, "软件 %d | 环境特征可见 %d | 未见环境特征 %d",
                apps, featureHits, clean);
    }

    private String buildReport() {
        StringBuilder sb = new StringBuilder();
        File base = new File(getFilesDir(), "from_module");
        File byPkg = new File(base, "by_pkg");
        File index = new File(base, "index.txt");

        sb.append("EnvProbe 外部路径可见性报告\n");
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
            sb.append("（无目标采集数据，仅执行 EnvProbe 内置环境自检）\n\n");
            sb.append(scanOne("【内置自检】EnvProbe App 视角", null,
                    Arrays.asList(BUILTIN_RISK), null, null));
            sb.append(scanPackages());
            return sb.toString();
        }

        int featureHitApps = 0;
        for (String key : keys) {
            File dir = new File(byPkg, key);
            File externalFile = new File(dir, "paths_external.txt");
            File riskFile = new File(dir, "paths_risk.txt");
            File meta = new File(dir, "meta.txt");
            List<String> paths = new ArrayList<>();
            if (externalFile.exists()) {
                paths.addAll(readLines(externalFile));
            } else if (riskFile.exists()) {
                paths.addAll(readLines(riskFile));
            }

            String pkgName = key;
            String user = "?";
            int idx = key.lastIndexOf("_u");
            if (idx > 0) {
                pkgName = key.substring(0, idx);
                user = key.substring(idx + 2);
            }
            String metaStr = meta.exists() ? readAll(meta).trim() : "";

            String block = scanOne(pkgName + "  (用户 u" + user + ")", metaStr,
                    paths, pkgName, user);
            if (!block.contains("环境特征可见: 0")) featureHitApps++;
            sb.append(block).append('\n');
        }

        sb.append(scanPackages());
        sb.append("\n—— 共 ").append(keys.size()).append(" 个软件，")
                .append(featureHitApps).append(" 个存在可见环境特征 ——\n");
        return sb.toString();
    }

    /** 对目标实际访问的外部路径逐项执行 exists，并同时输出可见和不可见结果。 */
    private String scanOne(String title, String meta, List<String> paths,
                           String packageName, String user) {
        StringBuilder sb = new StringBuilder();
        sb.append("## ").append(title).append('\n');
        if (meta != null && !meta.isEmpty()) {
            for (String line : meta.split("\n")) {
                if (line.startsWith("paths_external=") || line.startsWith("paths_risk=")
                        || line.startsWith("exported=")
                        || line.startsWith("session=")) {
                    sb.append(line).append('\n');
                }
            }
        }

        Set<String> uniquePaths = new LinkedHashSet<>(paths);
        List<String> results = new ArrayList<>();
        int visible = 0;
        int invisible = 0;
        int visibleFeatures = 0;
        int checked = 0;
        for (String path : uniquePaths) {
            if (path == null || !path.startsWith("/")) continue;
            if (packageName != null && isOwnPath(path, packageName, user)) continue;
            checked++;
            File f = new File(path);
            boolean ex;
            try {
                ex = f.exists();
            } catch (Throwable t) {
                continue;
            }
            if (ex) {
                visible++;
                String tag = "";
                if (isRisk(path)) {
                    visibleFeatures++;
                    tag = "[环境特征:" + riskTag(path) + "]";
                }
                results.add("[可见]" + tag + " " + path);
            } else {
                invisible++;
                results.add("[不可见] " + path);
            }
        }

        sb.append("目标实际外部路径: ").append(checked).append('\n');
        sb.append("可见路径: ").append(visible).append("（exists=true）\n");
        sb.append("不可见路径: ").append(invisible).append("（exists=false）\n");
        sb.append("环境特征可见: ").append(visibleFeatures).append('\n');
        sb.append("路径明细:\n");
        for (String result : results) sb.append("  ").append(result).append('\n');
        return sb.toString();
    }

    private String scanPackages() {
        StringBuilder sb = new StringBuilder();
        sb.append("### 可疑包名（应用列表）\n");
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

    private static boolean isOwnPath(String path, String packageName, String user) {
        String userId = user == null || !user.matches("\\d+") ? "0" : user;
        if (path.startsWith("/proc/self/") || path.startsWith("/proc/thread-self/")) {
            return true;
        }
        if (path.startsWith("/data/data/" + packageName + "/")
                || path.startsWith("/data/user/" + userId + "/" + packageName + "/")
                || path.startsWith("/data/user_de/" + userId + "/" + packageName + "/")) {
            return true;
        }
        return path.startsWith("/storage/emulated/" + userId + "/Android/data/" + packageName + "/")
                || path.startsWith("/storage/emulated/" + userId + "/Android/media/" + packageName + "/")
                || path.startsWith("/storage/emulated/" + userId + "/Android/obb/" + packageName + "/")
                || path.startsWith("/sdcard/Android/data/" + packageName + "/")
                || path.startsWith("/sdcard/Android/media/" + packageName + "/")
                || path.startsWith("/sdcard/Android/obb/" + packageName + "/");
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
