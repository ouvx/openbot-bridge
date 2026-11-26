const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

const statusClass = (status) =>
  status === "ready" || status === "completed" ? "ok" : status === "working" || status === "running" || status === "queued" ? "busy" : status === "needs_person" ? "warn" : "bad";

/**
 * The optional ChatGPT dashboard. It is a single static HTML document with
 * inline CSS only: no scripts, no network loads, so the plugin CSP stays tight.
 */
export function renderDashboard(payload) {
  const agents = Array.isArray(payload.agents) ? payload.agents : [];
  const tasks = Array.isArray(payload.tasks) ? payload.tasks : [];
  const resources = payload.resources ?? {};
  const connection = payload.connection ?? {};
  const bar = (percent) => Math.max(0, Math.min(100, Number(percent) || 0));

  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenBot Bridge</title>
<style>
:root{color-scheme:dark}
body{margin:0;padding:16px;font:14px/1.5 system-ui,-apple-system,"Noto Sans JP",sans-serif;background:#0f1115;color:#e6e8ee}
h1{font-size:16px;margin:0 0 2px}
.muted{color:#9aa3b2;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.card{margin-top:14px;background:#161a21;border:1px solid #232936;border-radius:10px;padding:12px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid}
.ok{color:#7ee2a8;border-color:#245c3f;background:#11241a}
.busy{color:#8fc4ff;border-color:#274a70;background:#111d2b}
.warn{color:#ffd479;border-color:#6b5220;background:#241d0f}
.bad{color:#ff9a9a;border-color:#6b2626;background:#241111}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #232936;font-weight:400}
th{color:#9aa3b2;font-size:12px;font-weight:600}
.meter{height:6px;background:#232936;border-radius:3px;overflow:hidden;margin-top:4px}
.meter>span{display:block;height:100%;background:#4d8dff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.big{font-size:18px;font-weight:600}
code{font-size:11px;color:#9aa3b2}
</style></head>
<body>
<div class="row" style="justify-content:space-between">
  <div><h1>OpenBot Bridge</h1><div class="muted">更新 ${escapeHtml(payload.updated_at ?? "")}</div></div>
  <div class="row">
    <span class="badge ${connection.automation ? "ok" : "bad"}">automation ${connection.automation ? "接続" : "切断"}</span>
    <span class="badge ${connection.database ? "ok" : "bad"}">DB ${connection.database ? "読取可" : "なし"}</span>
    <span class="badge ${connection.read_only ? "warn" : "ok"}">${connection.read_only ? "read-only" : "書き込み可"}</span>
  </div>
</div>

<div class="card">
  <div class="row" style="justify-content:space-between"><strong>エージェント</strong><span class="muted">${agents.length} 体</span></div>
  <table><thead><tr><th>名前</th><th>ランタイム / モデル</th><th>状態</th></tr></thead><tbody>
  ${agents
    .map(
      (agent) => `<tr><td>${escapeHtml(agent.name)}${agent.focus ? " ★" : ""}<br><code>${escapeHtml(agent.agent_id)}</code></td><td>${escapeHtml(agent.provider ?? "?")} / ${escapeHtml(agent.model ?? "?")}</td><td><span class="badge ${statusClass(agent.status)}">${escapeHtml(agent.status)}</span></td></tr>`,
    )
    .join("") || `<tr><td colspan="3" class="muted">エージェントが見つかりません</td></tr>`}
  </tbody></table>
</div>

<div class="card">
  <div class="row" style="justify-content:space-between"><strong>タスク</strong><span class="muted">直近 ${tasks.length} 件</span></div>
  <table><thead><tr><th>タイトル</th><th>状態</th><th>更新</th></tr></thead><tbody>
  ${tasks
    .map(
      (task) => `<tr><td>${escapeHtml(task.title)}<br><code>${escapeHtml(task.task_id)}</code></td><td><span class="badge ${statusClass(task.status)}">${escapeHtml(task.status)}</span></td><td class="muted">${escapeHtml((task.updated_at ?? "").replace("T", " ").slice(0, 19))}</td></tr>`,
    )
    .join("") || `<tr><td colspan="3" class="muted">タスクはまだありません</td></tr>`}
  </tbody></table>
</div>

<div class="card">
  <strong>サーバー</strong>
  <div class="grid" style="margin-top:8px">
    <div><div class="muted">CPU</div><div class="big">${resources.cpu_percent ?? "–"}%</div><div class="meter"><span style="width:${bar(resources.cpu_percent)}%"></span></div></div>
    <div><div class="muted">メモリ</div><div class="big">${resources.memory_percent ?? "–"}%</div><div class="meter"><span style="width:${bar(resources.memory_percent)}%"></span></div></div>
    <div><div class="muted">ディスク空き</div><div class="big">${resources.disk_free_gb ?? "–"} GB</div></div>
    <div><div class="muted">稼働時間</div><div class="big">${resources.uptime_hours ?? "–"} h</div></div>
  </div>
</div>
</body></html>`;
}

export const DASHBOARD_URI = "ui://openbot-dashboard/v1.html";
export const DASHBOARD_MIME = "text/html;profile=mcp-app";
