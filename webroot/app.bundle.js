(() => {
  // node_modules/kernelsu/index.js
  var callbackCounter = 0;
  function getUniqueCallbackName(prefix) {
    return `${prefix}_callback_${Date.now()}_${callbackCounter++}`;
  }
  function exec(command2, options) {
    if (typeof options === "undefined") {
      options = {};
    }
    return new Promise((resolve, reject) => {
      const callbackFuncName = getUniqueCallbackName("exec");
      window[callbackFuncName] = (errno, stdout, stderr) => {
        resolve({ errno, stdout, stderr });
        cleanup(callbackFuncName);
      };
      function cleanup(successName) {
        delete window[successName];
      }
      try {
        ksu.exec(command2, JSON.stringify(options), callbackFuncName);
      } catch (error) {
        reject(error);
        cleanup(callbackFuncName);
      }
    });
  }
  function Stdio() {
    this.listeners = {};
  }
  Stdio.prototype.on = function(event, listener) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  };
  Stdio.prototype.emit = function(event, ...args) {
    if (this.listeners[event]) {
      this.listeners[event].forEach((listener) => listener(...args));
    }
  };
  function ChildProcess() {
    this.listeners = {};
    this.stdin = new Stdio();
    this.stdout = new Stdio();
    this.stderr = new Stdio();
  }
  ChildProcess.prototype.on = function(event, listener) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  };
  ChildProcess.prototype.emit = function(event, ...args) {
    if (this.listeners[event]) {
      this.listeners[event].forEach((listener) => listener(...args));
    }
  };

  // ../../../../Desktop/wzry_reverse/module_ebpf_stats/webroot/app.js
  var root = "/data/adb/modules/ebpf_stats/ebpf_statistics";
  var run = "/data/adb/modules/ebpf_stats/run";
  var apps = document.querySelector("#apps");
  var detail = document.querySelector("#detail");
  var results = document.querySelector("#results");
  var status = document.querySelector("#status");
  var detailTitle = document.querySelector("#detail-title");
  var selectedApp = null;
  var command = `ROOT='${root}'; RUN='${run}'; for f in "$ROOT"/*_u*/latest_summary.txt; do [ -f "$f" ] || continue; d=$(dirname "$f"); key=$(basename "$d"); pkg=\${key%_u*}; user=\${key##*_u}; echo "APP|$key|$pkg|$user"; [ -f "$RUN/sess_$key" ] && echo ACTIVE=1 || echo ACTIVE=0; sed -n -E '/^(VFS_PERMISSION_TOTAL|PATH_SUCCESS|PATH_NOT_FOUND|PATH_DENIED|PATH_ERROR)=/p' "$f"; done`;
  function number(value) {
    const match = String(value || "").match(/=([0-9]+)/);
    return match ? Number(match[1]) : 0;
  }
  function metric(line, key) {
    const match = line.match(new RegExp(`${key}=([0-9]+)`));
    return match ? Number(match[1]) : 0;
  }
  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;"
    })[char]);
  }
  function classifyRisk(row) {
    const path = row.path.toLowerCase();
    const rootArtifact = /\/data\/adb|magisk|kernelsu|(^|\/)ksu(\/|$)|\/su(\/|$)|xposed|lsposed|lspd|zygisk|frida|riru|shamiko|tricky|busybox/.test(path);
    const environmentProbe = /\/proc\/(self|thread-self|[0-9]+)\/(maps|mounts|mountinfo|status|cmdline|fd)|\/proc\/(cpuinfo|mounts)|^\/sys\/|selinux|cpu_capacity|cpuinfo_max_freq|\/dev\/__properties__|overlay|verified.?boot|\/data\/local\//.test(path);
    if (row.state === "NOT_FOUND") return "miss";
    if (rootArtifact && row.state === "SUCCESS") return "high";
    if (rootArtifact || environmentProbe || row.state === "DENIED" || row.state === "ERROR") return "medium";
    return "low";
  }
  var riskGroups = [
    { key: "high", label: "\u9AD8\u98CE\u9669", description: "Root\u3001\u6CE8\u5165\u6216\u8C03\u8BD5\u4EA7\u7269\u5B9E\u9645\u8BBF\u95EE\u6210\u529F", open: true },
    { key: "medium", label: "\u4E2D\u98CE\u9669", description: "\u73AF\u5883\u63A2\u9488\u3001\u6743\u9650\u62D2\u7EDD\u6216\u7ED3\u679C\u4E0D\u786E\u5B9A", open: true },
    { key: "low", label: "\u4F4E\u98CE\u9669", description: "\u666E\u901A\u7CFB\u7EDF\u6587\u4EF6\u548C\u8FD0\u884C\u65F6\u4F9D\u8D56", open: false },
    { key: "miss", label: "\u672A\u547D\u4E2D", description: "\u76EE\u6807\u8F6F\u4EF6\u63A2\u6D4B\u8FC7\uFF0C\u4F46\u8DEF\u5F84\u4E0D\u5B58\u5728", open: false }
  ];
  function resultTable(rows) {
    return `<div class="table-wrap"><table><thead><tr><th>\u64CD\u4F5C</th><th>\u8DEF\u5F84</th><th>\u7ED3\u679C</th><th>\u80FD\u529B</th><th>\u8FD4\u56DE\u503C</th><th>\u6B21\u6570</th></tr></thead><tbody>${rows.map((row) => {
      const cls = row.state === "SUCCESS" ? "ok" : row.state === "DENIED" ? "bad" : row.state === "NOT_FOUND" ? "warn" : "blue";
      return `<tr><td>${escapeHtml(row.operation)}</td><td class="path">${escapeHtml(row.path)}</td><td class="${cls}">${escapeHtml(row.state)}</td><td>${escapeHtml(row.capability)}</td><td>${row.ret}</td><td>${row.count}</td></tr>`;
    }).join("")}</tbody></table></div>`;
  }
  function renderRiskGroups(rows) {
    const grouped = Object.fromEntries(riskGroups.map((group) => [group.key, []]));
    for (const row of rows) grouped[classifyRisk(row)].push(row);
    for (const group of riskGroups) grouped[group.key].sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
    return `<div class="risk-stack">${riskGroups.map((group) => {
      const items = grouped[group.key];
      const total = items.reduce((sum, item) => sum + item.count, 0);
      return `<details class="risk-group ${group.key}" ${group.open ? "open" : ""}><summary><span><span class="risk-name">${group.label}</span><span class="sub"> \xB7 ${group.description}</span></span><span class="risk-meta">${items.length} \u6761 \xB7 ${total} \u6B21</span></summary>${items.length ? resultTable(items) : '<div class="empty">\u5F53\u524D\u6CA1\u6709\u6B64\u7C7B\u7ED3\u679C</div>'}</details>`;
    }).join("")}</div>`;
  }
  function parseApps(text) {
    const list = [];
    let current;
    for (const line of text.split(/\r?\n/)) {
      if (line.startsWith("APP|")) {
        const [, key, pkg, user] = line.split("|");
        current = { key, pkg, user, active: false, vfs: 0, success: 0, missing: 0, denied: 0, error: 0 };
        list.push(current);
        continue;
      }
      if (!current) continue;
      if (line === "ACTIVE=1") current.active = true;
      if (line.startsWith("VFS_PERMISSION_TOTAL=")) current.vfs = number(line);
      if (line.includes("PATH_SUCCESS=")) current.success = metric(line, "PATH_SUCCESS");
      if (line.includes("PATH_NOT_FOUND=")) current.missing = metric(line, "PATH_NOT_FOUND");
      if (line.includes("PATH_DENIED=")) current.denied = metric(line, "PATH_DENIED");
      if (line.includes("PATH_ERROR=")) current.error = metric(line, "PATH_ERROR");
    }
    return list;
  }
  function card(app) {
    const el = document.createElement("article");
    el.className = "card";
    el.innerHTML = `<div class="title">${escapeHtml(app.pkg)}</div><div class="sub">\u7528\u6237 ${escapeHtml(app.user)}${app.active ? " \xB7 \u91C7\u96C6\u4E2D" : ""}</div><div class="metrics">
    <div class="metric"><b class="ok">${app.success}</b><span>\u8BBF\u95EE\u6210\u529F</span></div>
    <div class="metric"><b class="warn">${app.missing}</b><span>\u8DEF\u5F84\u4E0D\u5B58\u5728</span></div>
    <div class="metric"><b class="bad">${app.denied}</b><span>\u6743\u9650\u62D2\u7EDD</span></div>
    <div class="metric"><b class="blue">${app.vfs}</b><span>VFS \u6743\u9650\u68C0\u67E5</span></div>
  </div>`;
    el.addEventListener("click", () => showDetails(app));
    return el;
  }
  async function showDetails(app) {
    const safeKey = /^[A-Za-z0-9._-]+_u[0-9]+$/.test(app.key) ? app.key : "";
    if (!safeKey) return;
    selectedApp = app;
    const current = `${run}/sess_${safeKey}`;
    const { stdout, errno } = await exec(`sf='${current}'; sess=$(sed -n 's/^sess=//p' "$sf" 2>/dev/null); if [ -n "$sess" ] && [ -f "$sess/path_results.log" ]; then tail -n 500 "$sess/path_results.log"; else tail -n 500 '${root}/${safeKey}/latest_path_results.txt' 2>/dev/null; fi`);
    detailTitle.textContent = `${app.pkg} \u8DEF\u5F84\u7ED3\u679C`;
    detail.hidden = false;
    apps.hidden = true;
    if (errno !== 0 || !stdout.trim()) {
      results.innerHTML = '<div class="empty">\u5F53\u524D\u6CA1\u6709\u6355\u83B7\u5230\u5E26\u8FD4\u56DE\u503C\u7684\u8DEF\u5F84\u4E8B\u4EF6\u3002\u8BF7\u542F\u52A8\u76EE\u6807\u8F6F\u4EF6\u5E76\u64CD\u4F5C\u540E\u5237\u65B0\u3002</div>';
      return;
    }
    const rows = [];
    for (const line of stdout.trim().split(/\r?\n/)) {
      const match = line.match(/^\[([^\]]+)\]\s+(.*?)\s+state=(\S+)\s+capability=(\S+)\s+ret=(-?\d+)(?:\s+count=(\d+))?/);
      if (match) rows.push({ operation: match[1], path: match[2], state: match[3], capability: match[4], ret: Number(match[5]), count: Number(match[6] || 1) });
    }
    results.innerHTML = renderRiskGroups(rows);
  }
  async function exportReport() {
    if (!selectedApp) return;
    const safeKey = /^[A-Za-z0-9._-]+_u[0-9]+$/.test(selectedApp.key) ? selectedApp.key : "";
    if (!safeKey) return;
    const button = document.querySelector("#export");
    button.disabled = true;
    button.textContent = "\u5BFC\u51FA\u4E2D...";
    const appDir = `${root}/${safeKey}`;
    const sessionFile = `${run}/sess_${safeKey}`;
    const command2 = `OUT=/sdcard/Download; mkdir -p "$OUT"; ts=$(date +%Y%m%d_%H%M%S); file="$OUT/eBPF_Stats_${safeKey}_$ts.txt"; sf='${sessionFile}'; sess=$(sed -n 's/^sess=//p' "$sf" 2>/dev/null); { echo 'eBPF Stats report'; echo 'package=${safeKey}'; echo "exported=$(date)"; echo; echo '[SUMMARY]'; cat '${appDir}/latest_summary.txt' 2>/dev/null; echo; echo '[PATH_RESULTS]'; if [ -n "$sess" ] && [ -f "$sess/path_results.log" ]; then cat "$sess/path_results.log"; else cat '${appDir}/latest_path_results.txt' 2>/dev/null; fi; echo; echo '[VFS_EVENTS]'; if [ -n "$sess" ] && [ -f "$sess/vfs_events.log" ]; then cat "$sess/vfs_events.log"; else cat '${appDir}/latest_vfs_events.txt' 2>/dev/null; fi; } > "$file"; chmod 0644 "$file"; echo "$file"`;
    try {
      const { stdout, errno } = await exec(command2);
      status.textContent = errno === 0 ? `\u5DF2\u5BFC\u51FA\uFF1A${stdout.trim()}` : "\u5BFC\u51FA\u5931\u8D25\uFF0C\u8BF7\u68C0\u67E5 Download \u76EE\u5F55\u6743\u9650\u3002";
    } catch (error) {
      status.textContent = `\u5BFC\u51FA\u5931\u8D25\uFF1A${error.message}`;
    } finally {
      button.disabled = false;
      button.textContent = "\u5BFC\u51FA";
    }
  }
  async function load() {
    status.textContent = "\u6B63\u5728\u8BFB\u53D6\u6A21\u5757\u6570\u636E...";
    const { stdout, errno } = await exec(command);
    if (errno !== 0) {
      status.textContent = "\u8BFB\u53D6\u5931\u8D25\uFF0C\u8BF7\u786E\u8BA4\u5F53\u524D\u4F7F\u7528\u7684\u662F KernelSU Manager\u3002";
      apps.innerHTML = '<div class="empty">KernelSU WebUI \u9700\u8981\u7531 KernelSU Manager \u6253\u5F00\u3002</div>';
      return;
    }
    const list = parseApps(stdout);
    apps.replaceChildren(...list.map(card));
    status.textContent = list.length ? `\u5DF2\u8BB0\u5F55 ${list.length} \u4E2A\u8F6F\u4EF6\uFF0C\u70B9\u51FB\u5361\u7247\u67E5\u770B\u771F\u5B9E\u8FD4\u56DE\u7ED3\u679C\u3002` : "\u8FD8\u6CA1\u6709\u5DF2\u7ED3\u675F\u7684\u626B\u63CF\u4F1A\u8BDD\u3002";
  }
  document.querySelector("#refresh").addEventListener("click", load);
  document.querySelector("#back").addEventListener("click", () => {
    detail.hidden = true;
    apps.hidden = false;
  });
  document.querySelector("#export").addEventListener("click", exportReport);
  document.querySelector("#expand-all").addEventListener("click", () => document.querySelectorAll(".risk-group").forEach((group) => {
    group.open = true;
  }));
  document.querySelector("#collapse-all").addEventListener("click", () => document.querySelectorAll(".risk-group").forEach((group) => {
    group.open = false;
  }));
  load();
})();
