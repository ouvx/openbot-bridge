import { parseArgs } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { open, unlink } from "node:fs/promises";
import { resolve } from "node:path";

async function main() {
  const { values } = parseArgs({
    options: {
      output: { type: "string" }, port: { type: "string" }, write: { type: "boolean" },
      admin: { type: "boolean" }, help: { type: "boolean" },
    }, allowPositionals: false,
  });
  if (values.help) {
    console.log("node scripts/token.mjs --output NEW_PRIVATE_FILE [--port LOCAL_PORT] [--write] [--admin]");
    return;
  }
  if (!values.output) throw new Error("The --output option is required.");
  try {
    process.loadEnvFile(".env");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const port = Number(values.port ?? process.env.BRIDGE_PORT ?? 8790);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error("Invalid loopback port.");
  const base = "http://127.0.0.1:" + port;
  const resource = process.env.BRIDGE_PUBLIC_URL || base;
  const passcode = process.env.BRIDGE_ADMIN_SECRET;
  if (!passcode) throw new Error("A local consent passcode is required.");
  const scopes = ["openbot.read"];
  if (values.write) scopes.push("openbot.write");
  if (values.admin) scopes.push("openbot.admin");
  if (scopes.length > 1) console.error("Warning: explicitly requested elevated scopes: " + scopes.slice(1).join(", "));

  // All requests stay on this loopback origin. The callback is inspected but
  // never visited. In particular, no passcode or token follows a redirect.
  const send = (path, body, headers) => fetch(base + path, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(10000), body, headers,
  });
  const output = resolve(values.output);
  const file = await open(output, "wx", 0o600);
  let complete = false;
  try {
    const redirectUri = "http://127.0.0.1/callback";
    const register = await send("/oauth/register", JSON.stringify({ client_name: "Local token utility", redirect_uris: [redirectUri] }),
      { "content-type": "application/json" });
    if (register.status !== 201) throw new Error("Client registration failed.");
    const { client_id: clientId } = await register.json();
    if (typeof clientId !== "string" || !clientId) throw new Error("Missing client id.");
    const verifier = randomBytes(48).toString("base64url");
    const state = randomBytes(24).toString("base64url");
    const params = {
      response_type: "code", client_id: clientId, redirect_uri: redirectUri, resource, state,
      scope: scopes.join(" "), code_challenge_method: "S256",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    };
    const approval = await send("/oauth/authorize/approve", new URLSearchParams({ ...params, passcode }));
    if (approval.status !== 302) throw new Error("Local consent failed.");
    const callback = new URL(approval.headers.get("location"));
    const code = callback.searchParams.get("code");
    if (callback.origin + callback.pathname !== redirectUri || callback.searchParams.get("state") !== state || !code) {
      throw new Error("Unexpected callback.");
    }
    const exchange = await send("/oauth/token", new URLSearchParams({
      grant_type: "authorization_code", client_id: clientId, redirect_uri: redirectUri, resource, code_verifier: verifier, code,
    }));
    if (exchange.status !== 200) throw new Error("Token exchange failed.");
    const { access_token, refresh_token, token_type, expires_in, scope } = await exchange.json();
    if (typeof access_token !== "string" || typeof refresh_token !== "string" || token_type !== "Bearer") {
      throw new Error("Invalid token response.");
    }
    await file.writeFile(JSON.stringify({ access_token, refresh_token, token_type, expires_in, scope, client_id: clientId, redirect_uri: redirectUri, resource }) + "\n");
    await file.sync();
    complete = true;
  } finally {
    await file.close();
    if (!complete) await unlink(output);
  }
  console.log(output);
}

main().catch(() => {
  console.error("Token utility failed. Check --help, the local Bridge, its configuration and the new output path.");
  process.exitCode = 1;
});
