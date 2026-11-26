import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { EventBus } from "../src/events.mjs";
import { postPinned, postToAddress, resolveCallback } from "../src/callback.mjs";

const target = "https://callback.example/hook";
const records = address => async () => [{ address, family: 4 }];

test("DNS address changes or lookup failure refuse delivery before transport", async () => {
  const approved = await resolveCallback(target, records("8.8.8.8"));
  let calls = 0;
  const send = async () => { calls++; };
  const unavailable = async () => { throw new Error("unavailable"); };
  for (const lookup of [records("8.8.4.4"), records("127.0.0.1"), unavailable]) {
    await assert.rejects(() => postPinned(target, approved, {}, "", lookup, send));
  }
  assert.equal(calls, 0);
});

test("approved callback uses a single resolved address and retains the TLS hostname", async () => {
  let lookups = 0;
  const lookup = async () => { lookups++; return [{ address: "8.8.8.8" }]; };
  await postPinned(target, ["8.8.8.8"], {}, "", lookup, (url, address) => {
    assert.equal(address, "8.8.8.8");
    assert.equal(url.hostname, "callback.example");
  });
  assert.equal(lookups, 1);
});

test("event subscriptions reject missing scope, unspecified or unauthorized agent, and unsupported type", async () => {
  const bus = new EventBus({ dataDir: ".", logger: {}, db: {}, jobs: {} });
  const auth = { ok: true, clientId: "a", grantId: "g", scopes: ["openbot.read"], allowedAgentIds: ["mine"] };
  const params = { name: "task.needs_person", arguments: { agent_id: "mine" } };
  for (const id of [null, "other"]) {
    await assert.rejects(bus.subscribe({ ...params, arguments: { agent_id: id } }, auth), { reason: "forbidden" });
  }
  await assert.rejects(bus.subscribe(params, { ...auth, scopes: [] }), { reason: "forbidden" });
  await assert.rejects(bus.subscribe({ ...params, name: "unknown" }, auth), { reason: "unknown_event" });
});

test("TLS transport withholds the body from a peer that differs from the pinned IP", async (t) => {
  let wrote = false;
  const req = new EventEmitter();
  req.end = () => { wrote = true; };
  req.destroy = err => req.emit("error", err);
  const connect = options => {
    assert.equal(options.hostname, "8.8.8.8");
    assert.equal(options.servername, "callback.example");
    assert.equal(options.headers.host, "callback.example");
    assert.equal(options.rejectUnauthorized, true);
    return req;
  };
  // The stand-in never emits a response, so this promise only settles through the
  // peer check or the error path. If that check is removed the promise stays
  // pending forever, which used to hang the whole run: bound the wait here and
  // close the request in t.after, so the same change now fails this test fast.
  const guardMs = 2000;
  let timer;
  const guard = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`the pinned-peer check did not run within ${guardMs}ms`)), guardMs);
  });
  t.after(() => {
    clearTimeout(timer);
    req.destroy(new Error("test cleanup"));
  });
  try {
    const result = postToAddress(new URL(target), "8.8.8.8", {}, "fixture", connect);
    const socket = new EventEmitter();
    socket.remoteAddress = "8.8.4.4";
    req.emit("socket", socket);
    socket.emit("secureConnect");
    await assert.rejects(Promise.race([result, guard]), /differs from approved/);
    assert.equal(wrote, false);
  } finally {
    clearTimeout(timer);
  }
});
