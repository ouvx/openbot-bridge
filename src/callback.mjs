import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { BlockList, isIPv4 } from "node:net";

const denied = new BlockList();
for (const [start, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]) denied.addSubnet(start, prefix, "ipv4");

export function isPrivateAddress(address) {
  // The delivery transport supports IPv4 only. All other families fail closed.
  return !isIPv4(address) || denied.check(address, "ipv4");
}

export async function resolveCallback(url, resolve = lookup) {
  const target = new URL(url);
  if (target.protocol !== "https:") throw new Error("The callback URL must be HTTPS.");
  if (target.username || target.password) throw new Error("The callback URL must not contain credentials.");
  if (target.hash || target.hostname.includes(":")) throw new Error("Unsupported callback address.");
  const records = isIPv4(target.hostname)
    ? [{ address: target.hostname }]
    : await resolve(target.hostname, { family: 4, all: true });
  const addresses = [...new Set(records.map(record => record.address))].sort();
  if (!addresses.length || addresses.some(isPrivateAddress)) {
    throw new Error("The callback URL must not point at a private address or unsupported address.");
  }
  return addresses;
}

export class CallbackValidationError extends Error {}

export async function postPinned(url, approved, headers, body, resolve = lookup, send = postToAddress) {
  let current;
  try {
    current = await resolveCallback(url, resolve);
  } catch {
    throw new CallbackValidationError("Callback address verification failed.");
  }
  if (!Array.isArray(approved) || approved.length !== current.length ||
      current.some((address, index) => address !== approved[index])) {
    throw new CallbackValidationError("Callback address set changed.");
  }
  return send(new URL(url), current[0], headers, body);
}

export function postToAddress(url, address, headers, body, connect = request) {
  return new Promise((resolve, reject) => {
    const req = connect({
      protocol: "https:", hostname: address, family: 4, port: url.port || 443,
      method: "POST", path: url.pathname + url.search, agent: false,
      servername: isIPv4(url.hostname) ? "" : url.hostname,
      headers: { ...headers, host: url.host, "content-length": Buffer.byteLength(body) },
      rejectUnauthorized: true, signal: AbortSignal.timeout(10000),
    }, res => {
      const chunks = [];
      let size = 0;
      res.on("data", chunk => {
        size += chunk.length;
        if (size > 16384) res.destroy(new Error("Callback response too large."));
        else chunks.push(chunk);
      });
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.on("socket", socket => socket.once("secureConnect", () => {
      if (socket.remoteAddress !== address) req.destroy(new CallbackValidationError("Callback peer differs from approved address."));
      else req.end(body);
    }));
  });
}
