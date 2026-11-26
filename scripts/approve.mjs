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
  if (!res.ok) throw new Error("承認画面を開き直すか、依頼の有効期限を確認してください。");
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

export async function openApprovalCard(store, approvalId) {
  const card = store.card(approvalId);
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
      if (req.url === "/card") return send(200, store.card(approvalId));
      if (req.url !== "/decision") return send(404, {});
      const input = await jsonBody(req);
      const decision = store.decide(approvalId, input.summaryHash, input.approved);
      send(200, decision);
      stop();
    } catch { send(409, { error: "decision_refused" }); }
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
  timer = setTimeout(() => { stop(); server.closeAllConnections(); }, Math.max(1, card.expiresAt - Date.now()));
  return { url: origin + "/#" + key, stop, closed };
}

async function main() {
  if (!process.stdin.isTTY || !process.stdout.isTTY || process.argv.length !== 3 ||
      !/^[a-f0-9-]{36}$/.test(process.argv[2])) throw new Error("Open a local terminal and run: node scripts/approve.mjs APPROVAL_ID");
  try { process.loadEnvFile(process.env.BRIDGE_ENV_FILE || ".env"); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  const config = loadConfig();
  if (config.readOnly || !config.extendedTools) throw new Error("Write tools are disabled.");
  const store = new OperationStore({ dataDir: config.dataDir });
  try {
    const card = await openApprovalCard(store, process.argv[2]);
    console.log("このパソコンのブラウザで開いてください。URL は共有しないでください。\n" + card.url);
    await card.closed;
  } finally { store.close(); }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
}
