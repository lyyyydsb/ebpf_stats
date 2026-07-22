import { exec } from 'kernelsu';

const root = '/data/adb/modules/ebpf_stats/ebpf_statistics';
const run = '/data/adb/modules/ebpf_stats/run';
const apps = document.querySelector('#apps');
const detail = document.querySelector('#detail');
const results = document.querySelector('#results');
const status = document.querySelector('#status');
const detailTitle = document.querySelector('#detail-title');
let selectedApp = null;

const command = `ROOT='${root}'; RUN='${run}'; for f in "$ROOT"/*_u*/latest_summary.txt; do [ -f "$f" ] || continue; d=$(dirname "$f"); key=$(basename "$d"); pkg=\${key%_u*}; user=\${key##*_u}; echo "APP|$key|$pkg|$user"; [ -f "$RUN/sess_$key" ] && echo ACTIVE=1 || echo ACTIVE=0; sed -n -E '/^(VFS_PERMISSION_TOTAL|PATH_SUCCESS|PATH_NOT_FOUND|PATH_DENIED|PATH_ERROR)=/p' "$f"; done`;

function number(value) {
  const match = String(value || '').match(/=([0-9]+)/);
  return match ? Number(match[1]) : 0;
}

function metric(line, key) {
  const match = line.match(new RegExp(`${key}=([0-9]+)`));
  return match ? Number(match[1]) : 0;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;',
  })[char]);
}

function classifyRisk(row) {
  const path = row.path.toLowerCase();
  const rootArtifact = /\/data\/adb|magisk|kernelsu|(^|\/)ksu(\/|$)|\/su(\/|$)|xposed|lsposed|lspd|zygisk|frida|riru|shamiko|tricky|busybox/.test(path);
  const environmentProbe = /\/proc\/(self|thread-self|[0-9]+)\/(maps|mounts|mountinfo|status|cmdline|fd)|\/proc\/(cpuinfo|mounts)|^\/sys\/|selinux|cpu_capacity|cpuinfo_max_freq|\/dev\/__properties__|overlay|verified.?boot|\/data\/local\//.test(path);
  if (row.state === 'NOT_FOUND') return 'miss';
  if (rootArtifact && row.state === 'SUCCESS') return 'high';
  if (rootArtifact || environmentProbe || row.state === 'DENIED' || row.state === 'ERROR') return 'medium';
  return 'low';
}

const riskGroups = [
  { key:'high', label:'高风险', description:'Root、注入或调试产物实际访问成功', open:true },
  { key:'medium', label:'中风险', description:'环境探针、权限拒绝或结果不确定', open:true },
  { key:'low', label:'低风险', description:'普通系统文件和运行时依赖', open:false },
  { key:'miss', label:'未命中', description:'目标软件探测过，但路径不存在', open:false },
];

function resultTable(rows) {
  return `<div class="table-wrap"><table><thead><tr><th>操作</th><th>路径</th><th>结果</th><th>能力</th><th>返回值</th><th>次数</th></tr></thead><tbody>${rows.map((row) => {
    const cls = row.state === 'SUCCESS' ? 'ok' : row.state === 'DENIED' ? 'bad' : row.state === 'NOT_FOUND' ? 'warn' : 'blue';
    return `<tr><td>${escapeHtml(row.operation)}</td><td class="path">${escapeHtml(row.path)}</td><td class="${cls}">${escapeHtml(row.state)}</td><td>${escapeHtml(row.capability)}</td><td>${row.ret}</td><td>${row.count}</td></tr>`;
  }).join('')}</tbody></table></div>`;
}

function renderRiskGroups(rows) {
  const grouped = Object.fromEntries(riskGroups.map((group) => [group.key, []]));
  for (const row of rows) grouped[classifyRisk(row)].push(row);
  for (const group of riskGroups) grouped[group.key].sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
  return `<div class="risk-stack">${riskGroups.map((group) => {
    const items = grouped[group.key];
    const total = items.reduce((sum, item) => sum + item.count, 0);
    return `<details class="risk-group ${group.key}" ${group.open ? 'open' : ''}><summary><span><span class="risk-name">${group.label}</span><span class="sub"> · ${group.description}</span></span><span class="risk-meta">${items.length} 条 · ${total} 次</span></summary>${items.length ? resultTable(items) : '<div class="empty">当前没有此类结果</div>'}</details>`;
  }).join('')}</div>`;
}

function parseApps(text) {
  const list = [];
  let current;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('APP|')) {
      const [, key, pkg, user] = line.split('|');
      current = { key, pkg, user, active:false, vfs:0, success:0, missing:0, denied:0, error:0 };
      list.push(current);
      continue;
    }
    if (!current) continue;
    if (line === 'ACTIVE=1') current.active = true;
    if (line.startsWith('VFS_PERMISSION_TOTAL=')) current.vfs = number(line);
    if (line.includes('PATH_SUCCESS=')) current.success = metric(line, 'PATH_SUCCESS');
    if (line.includes('PATH_NOT_FOUND=')) current.missing = metric(line, 'PATH_NOT_FOUND');
    if (line.includes('PATH_DENIED=')) current.denied = metric(line, 'PATH_DENIED');
    if (line.includes('PATH_ERROR=')) current.error = metric(line, 'PATH_ERROR');
  }
  return list;
}

function card(app) {
  const el = document.createElement('article');
  el.className = 'card';
  el.innerHTML = `<div class="title">${escapeHtml(app.pkg)}</div><div class="sub">用户 ${escapeHtml(app.user)}${app.active ? ' · 采集中' : ''}</div><div class="metrics">
    <div class="metric"><b class="ok">${app.success}</b><span>访问成功</span></div>
    <div class="metric"><b class="warn">${app.missing}</b><span>路径不存在</span></div>
    <div class="metric"><b class="bad">${app.denied}</b><span>权限拒绝</span></div>
    <div class="metric"><b class="blue">${app.vfs}</b><span>VFS 权限检查</span></div>
  </div>`;
  el.addEventListener('click', () => showDetails(app));
  return el;
}

async function showDetails(app) {
  const safeKey = /^[A-Za-z0-9._-]+_u[0-9]+$/.test(app.key) ? app.key : '';
  if (!safeKey) return;
  selectedApp = app;
  const current = `${run}/sess_${safeKey}`;
  const { stdout, errno } = await exec(`sf='${current}'; sess=$(sed -n 's/^sess=//p' "$sf" 2>/dev/null); if [ -n "$sess" ] && [ -f "$sess/path_results.log" ]; then tail -n 500 "$sess/path_results.log"; else tail -n 500 '${root}/${safeKey}/latest_path_results.txt' 2>/dev/null; fi`);
  detailTitle.textContent = `${app.pkg} 路径结果`;
  detail.hidden = false;
  apps.hidden = true;
  if (errno !== 0 || !stdout.trim()) {
    results.innerHTML = '<div class="empty">当前没有捕获到带返回值的路径事件。请启动目标软件并操作后刷新。</div>';
    return;
  }
  const rows = [];
  for (const line of stdout.trim().split(/\r?\n/)) {
    const match = line.match(/^\[([^\]]+)\]\s+(.*?)\s+state=(\S+)\s+capability=(\S+)\s+ret=(-?\d+)(?:\s+count=(\d+))?/);
    if (match) rows.push({ operation:match[1], path:match[2], state:match[3], capability:match[4], ret:Number(match[5]), count:Number(match[6] || 1) });
  }
  results.innerHTML = renderRiskGroups(rows);
}

async function exportReport() {
  if (!selectedApp) return;
  const safeKey = /^[A-Za-z0-9._-]+_u[0-9]+$/.test(selectedApp.key) ? selectedApp.key : '';
  if (!safeKey) return;
  const button = document.querySelector('#export');
  button.disabled = true;
  button.textContent = '导出中...';
  const appDir = `${root}/${safeKey}`;
  const sessionFile = `${run}/sess_${safeKey}`;
  const command = `OUT=/sdcard/Download; mkdir -p "$OUT"; ts=$(date +%Y%m%d_%H%M%S); file="$OUT/eBPF_Stats_${safeKey}_$ts.txt"; sf='${sessionFile}'; sess=$(sed -n 's/^sess=//p' "$sf" 2>/dev/null); { echo 'eBPF Stats report'; echo 'package=${safeKey}'; echo "exported=$(date)"; echo; echo '[SUMMARY]'; cat '${appDir}/latest_summary.txt' 2>/dev/null; echo; echo '[PATH_RESULTS]'; if [ -n "$sess" ] && [ -f "$sess/path_results.log" ]; then cat "$sess/path_results.log"; else cat '${appDir}/latest_path_results.txt' 2>/dev/null; fi; echo; echo '[VFS_EVENTS]'; if [ -n "$sess" ] && [ -f "$sess/vfs_events.log" ]; then cat "$sess/vfs_events.log"; else cat '${appDir}/latest_vfs_events.txt' 2>/dev/null; fi; } > "$file"; chmod 0644 "$file"; echo "$file"`;
  try {
    const { stdout, errno } = await exec(command);
    status.textContent = errno === 0 ? `已导出：${stdout.trim()}` : '导出失败，请检查 Download 目录权限。';
  } catch (error) {
    status.textContent = `导出失败：${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = '导出';
  }
}

async function load() {
  status.textContent = '正在读取模块数据...';
  const { stdout, errno } = await exec(command);
  if (errno !== 0) {
    status.textContent = '读取失败，请确认当前使用的是 KernelSU Manager。';
    apps.innerHTML = '<div class="empty">KernelSU WebUI 需要由 KernelSU Manager 打开。</div>';
    return;
  }
  const list = parseApps(stdout);
  apps.replaceChildren(...list.map(card));
  status.textContent = list.length ? `已记录 ${list.length} 个软件，点击卡片查看真实返回结果。` : '还没有已结束的扫描会话。';
}

document.querySelector('#refresh').addEventListener('click', load);
document.querySelector('#back').addEventListener('click', () => { detail.hidden = true; apps.hidden = false; });
document.querySelector('#export').addEventListener('click', exportReport);
document.querySelector('#expand-all').addEventListener('click', () => document.querySelectorAll('.risk-group').forEach((group) => { group.open = true; }));
document.querySelector('#collapse-all').addEventListener('click', () => document.querySelectorAll('.risk-group').forEach((group) => { group.open = false; }));
load();
