import { test } from "node:test";
import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import { maskSecrets, maskDeep, truncate } from "../src/log.mjs";
import { assertPublicHttps, isPrivateAddress, EventBus } from "../src/events.mjs";
import { loadConfig } from "../src/config.mjs";

test("maskSecrets hides credentials but keeps the rest readable", () => {
  const masked = maskSecrets("token=super-secret-value and Bearer abcdefghijkl mnop sk-test-12345678");
  assert.ok(!masked.includes("super-secret-value"));
  assert.ok(!masked.includes("abcdefghijkl"));
  assert.ok(masked.includes("mnop"));
  assert.match(masked, /Bearer \*\*\*/);
});

test("maskDeep replaces values of secret-looking keys", () => {
  const masked = maskDeep({ authorization: "Bearer abc", nested: { apiKey: "k-123", keep: "ok" } });
  assert.equal(masked.authorization, "***");
  assert.equal(masked.nested.apiKey, "***");
  assert.equal(masked.nested.keep, "ok");
});

test("truncate keeps results bounded", () => {
  const value = "x".repeat(100);
  assert.equal(truncate(value, 20).length <= 80, true);
});

test("private callbacks are refused", async () => {
  assert.equal(isPrivateAddress("127.0.0.1"), true);
  assert.equal(isPrivateAddress("10.1.2.3"), true);
  assert.equal(isPrivateAddress("192.168.1.5"), true);
  assert.equal(isPrivateAddress("172.20.0.1"), true);
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  await assert.rejects(() => assertPublicHttps("http://example.com/callback"), /HTTPS/);
  await assert.rejects(() => assertPublicHttps("https://127.0.0.1/callback"), /private address/);
  await assert.rejects(() => assertPublicHttps("https://user:pass@example.com/callback"), /credentials/);
});

test("event subscribe refuses bad input before touching the network", async () => {
  const auth = { ok: true, clientId: "c", grantId: "g", scopes: ["openbot.read"], allowedAgentIds: ["a"] };
  const bus = new EventBus({ dataDir: "/tmp/openbot-bridge-unused", logger: { info() {}, warn() {} }, jobs: { list: () => [] }, db: {} });
  await assert.rejects(() => bus.subscribe({ name: "nope", delivery: { mode: "webhook", url: "https://example.com", secret: "whsec_x" } }, auth), /does not offer/);
  await assert.rejects(
    () => bus.subscribe({ name: "task.status_changed", arguments: { agent_id: "a" }, delivery: { mode: "webhook", url: "http://example.com", secret: `whsec_${"a".repeat(32)}` } }, auth),
    /HTTPS/,
  );
  await assert.rejects(
    () => bus.subscribe({ name: "task.status_changed", arguments: { agent_id: "a" }, delivery: { mode: "webhook", url: "https://example.com", secret: "short" } }, auth),
    /whsec_/,
  );
});

test("config requires an admin passcode", () => {
  assert.throws(() => loadConfig({ HOME: "/tmp" }), /BRIDGE_ADMIN_SECRET/);
  const config = loadConfig({ HOME: "/tmp", BRIDGE_ADMIN_SECRET: randomBytes(32).toString("hex"), BRIDGE_RPM: "5" });
  assert.equal(config.port, 8790);
  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.limits.requestsPerMinute, 5);
});
