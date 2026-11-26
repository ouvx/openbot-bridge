import { createServer } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfig } from "../src/config.mjs";
import { OperationStore } from "../src/operations.mjs";

// This short-lived operator UI is never mounted on the MCP server. The URL
// fragment is issued on the local terminal and is not sent on the initial GET.
function page(nonce) {
  return `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenBot Bridge 操作承認</title><style nonce="${nonce}">
body{font:1rem/1.6 system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem}
pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid;padding:1rem}
button{font:inherit;min-height:44px;margin-right:1rem;padding:0 1rem}
</style><main><h1>操作の承認</h1><p id="details"></p><pre id="summary" dir="ltr"></pre>
<p>宛先・操作・引数を確認してください。承認後、呼び出し元が同じ操作を再送すると1回だけ実行されます。</p>
<button id="no" disabled>拒否する</button><button id="yes" disabled>この内容で承認する</button>
<p id="status" role="status"></p></main><script nonce="${nonce}">
const key = location.hash.slice(1);
history.replaceState(null, "", "/");
const get = id => document.getElementById(id);
const buttons = disabled => { get("yes").disabled = disabled; get("no").disabled = disabled; };
async function post(path, data) {
  const res = await fetch(path, {method:"POST", headers:{"authorization":"Bearer " + key,"content-type":"application/json"},body:JSON.stringify(data)});
  if (!res.ok) {
    let message = "承認画面を開き直すか、依頼の有効期限を確認してください。";
    try { const body = await res.json(); if (body && typeof body.message === "string") message = body.message; } catch {}
    buttons(true); get("status").textContent = message;
    throw new Error(message);
  }
  return res.json();
}
async function digest(text) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(text))), b=>b.toString(16).padStart(2,"0")).join("");
}
async function show() {
  const card = await post("/card", {});
  get("details").textContent = "依頼 " + card.approvalId + "　有効期限 " + new Date(card.expiresAt).toLocaleTimeString() + "　クライアント " + card.clientId + "　同意 " + card.grantId;
  get("summary").textContent = card.summary;
  if (await digest(get("summary").textContent) !== card.summaryHash) throw new Error("表示内容が一致しません。");
  buttons(false);
}
async function decide(approved) {
  buttons(true);
  try {
    const summaryHash = await digest(get("summary").textContent);
    await post("/decision", { approved, summaryHash });
    get("status").textContent = approved ? "承認を記録しました。この画面を閉じてください。" : "拒否を記録しました。この画面を閉じてください。";
  } catch (e) { get("status").textContent = e.message; }
}
get("yes").onclick = () => decide(true);
get("no").onclick = () => decide(false);
show().catch(e => {get("status").textContent = e.message;});
</script></html>`;
}

async function jsonBody(req) {
  let text = "";
  for await (const part of req) {
    text += part.toString("utf8");
    if (Buffer.byteLength(text) > 2048) throw new Error("body_too_large");
  }
  return JSON.parse(text);
}

const EXPIRED_MESSAGE = "この承認は期限切れです(実行されません)。新しく依頼し直してください。";
const STALE_MESSAGE = "この承認画面は新しい画面に置き換えられました。ターミナルに表示された新しい URL を開いてください。";

// 期限切れや決定済みでも「サーバーが閉じて Failed to fetch」にしない。
// 期限後は猶予のあいだ画面を生かしたまま 410 を返し、その後に終了する。
const CARD_GRACE_MS = 5 * 60 * 1000;

const refusal = error => ({
  approval_expired: [410, "approval_expired", EXPIRED_MESSAGE],
  approval_card_stale: [410, "approval_card_stale", STALE_MESSAGE],
  approval_used: [409, "approval_used", "この承認は既に実行済みです(実行されません)。"],
  approval_not_pending: [409, "approval_not_pending", "この承認は既に決定済みです(実行されません)。"],
  approval_declined: [409, "approval_declined", "この承認は拒否済みです(実行されません)。"],
}[error?.code] ?? [409, "decision_refused", "承認画面を開き直すか、依頼の有効期限を確認してください。"]);

export async function openApprovalCard(store, approvalId, { replace = false, graceMs = CARD_GRACE_MS } = {}) {
  // 発行は DB の条件付き更新で予約する。2 回目の起動はここで止まる。
  const reserved = store.reserveCard(approvalId, { replace });
  const openedAt = reserved.cardOpenedAt;
  const card = store.card(approvalId, openedAt);
  const key = randomBytes(32).toString("hex");
  const expected = Buffer.from("Bearer " + key);
  const nonce = randomBytes(18).toString("base64");
  let origin;
  let timer;
  const server = createServer(async (req, res) => {
    const send = (status, data, type = "application/json") => {
      res.writeHead(status, { "content-type": type + "; charset=utf-8", "cache-control": "no-store",
        "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "DENY",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` });
      res.end(type === "text/html" ? data : JSON.stringify(data));
    };
    if (!origin || req.headers.host !== new URL(origin).host || req.socket.remoteAddress !== "127.0.0.1") return send(403, {});
    if (req.method === "GET" && req.url === "/") return send(200, page(nonce), "text/html");
    const provided = Buffer.from(req.headers.authorization || "");
    if (req.method !== "POST" || req.headers.origin !== origin || req.headers["content-type"] !== "application/json" ||
        provided.length !== expected.length || !timingSafeEqual(provided, expected)) return send(403, {});
    try {
      if (req.url === "/card") return send(200, store.card(approvalId, openedAt));
      if (req.url !== "/decision") return send(404, { error: "not_found", message: "この画面は使えません。" });
      const input = await jsonBody(req);
      const decision = store.decide(approvalId, input.summaryHash, input.approved, openedAt);
      send(200, decision);
      stop();
    } catch (error) {
      const [status, code, message] = refusal(error);
      send(status, { error: code, message });
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  const closed = new Promise(resolve => server.once("close", resolve));
  function stop() {
    clearTimeout(timer);
    if (server.listening) server.close();
  }
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  origin = "http://127.0.0.1:" + server.address().port;
  timer = setTimeout(() => { stop(); server.closeAllConnections(); }, Math.max(1, card.expiresAt + graceMs - Date.now()));
  return { url: origin + "/#" + key, stop, closed, openedAt, expiresAt: card.expiresAt, replaced: reserved.replaced };
}

async function main() {
  const args = process.argv.slice(2);
  const replace = args.includes("--replace");
  const approvalId = args.find(arg => arg !== "--replace");
  if (!process.stdin.isTTY || !process.stdout.isTTY || args.length < 1 || args.length > 2 ||
      !approvalId || !/^[a-f0-9-]{36}$/.test(approvalId)) {
    throw new Error("Open a local terminal and run: node scripts/approve.mjs APPROVAL_ID [--replace]");
  }
  try { process.loadEnvFile(process.env.BRIDGE_ENV_FILE || ".env"); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  const config = loadConfig();
  if (config.readOnly || !config.extendedTools) throw new Error("Write tools are disabled.");
  const store = new OperationStore({ dataDir: config.dataDir });
  try {
    const card = await openApprovalCard(store, approvalId, { replace });
    console.log((card.replaced ? "以前の画面を無効にして、新しい承認画面を発行しました。\n" : "") +
      "このパソコンのブラウザで開いてください。URL は共有しないでください。\n" + card.url);
    await card.closed;
  } catch (error) {
    if (error?.code === "approval_card_open") {
      const state = store.cardState(approvalId);
      const until = state ? new Date(state.expiresAt).toLocaleTimeString("ja-JP") : "不明";
      console.error("この承認のカードは既に開いています(approvalId " + approvalId + "、期限 " + until + ")。\n" +
        "別の画面で開いていないか確認してください。置き換えるときは --replace を付けて実行します。");
      process.exitCode = 3;
    } else if (error?.code === "approval_expired") {
      console.error(EXPIRED_MESSAGE);
      process.exitCode = 4;
    } else {
      throw error;
    }
  } finally { store.close(); }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
}
