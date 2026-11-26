import { constants } from "node:fs";
import { open, realpath, readdir } from "node:fs/promises";
import { basename, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

const extensions = new Set([".md", ".txt", ".csv", ".tsv", ".diff", ".patch"]);
const unavailable = () => new Error("Artifact unavailable.");

export function isTextFile(path) {
  const parts = path.split(sep);
  return parts.every(part => !part.startsWith(".") && !/^credentials/i.test(part) &&
    !/^(?:state\.json)$|\.(?:sqlite[^/]*|key|pem|log)(?:\.|$)/i.test(part)) &&
    extensions.has(extname(path).toLowerCase());
}

async function exportRoot(sharedDir, agentId) {
  if (!sharedDir || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(agentId)) throw unavailable();
  const root = resolve(await realpath(sharedDir), "bridge-artifacts", agentId);
  if (await realpath(root) !== root) throw unavailable();
  return root;
}

function inside(root, file) {
  const path = relative(root, file);
  return path && path !== ".." && !path.startsWith(".." + sep) && !isAbsolute(path);
}

async function openArtifact(sharedDir, agentId, path, limit) {
  const root = await exportRoot(sharedDir, agentId);
  const target = resolve(root, path);
  if (!inside(root, target) || !isTextFile(relative(root, target)) || await realpath(target) !== target) throw unavailable();
  const handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await handle.stat();
    // Check the opened descriptor, including its parent directories, before reading bytes.
    if (!info.isFile() || info.nlink !== 1 || info.size > limit ||
        await realpath("/proc/self/fd/" + handle.fd) !== target) throw unavailable();
    return { handle, size: info.size, path: relative(root, target), name: basename(target) };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

export async function readArtifact(sharedDir, agentId, path, limit) {
  try {
    const { handle, path: name, size } = await openArtifact(sharedDir, agentId, path, limit);
    try {
      const buffer = Buffer.alloc(size + 1);
      let used = 0;
      while (used < buffer.length) {
        const { bytesRead } = await handle.read(buffer, used, buffer.length - used);
        if (!bytesRead) break;
        used += bytesRead;
      }
      if (used !== size || buffer.subarray(0, used).includes(0)) throw unavailable();
      return { name: basename(name), path: name, size, text: new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, used)) };
    } finally { await handle.close(); }
  } catch { throw unavailable(); }
}

export async function listArtifacts(sharedDir, agentId, limit, byteLimit) {
  let dir;
  try {
    dir = await exportRoot(sharedDir, agentId);
    const names = await readdir(dir, { withFileTypes: true });
    const results = [];
    for (const item of names) {
      if (results.length >= limit) break;
      if (!item.isFile() || !isTextFile(item.name)) continue;
      const file = await openArtifact(sharedDir, agentId, join(dir, item.name), byteLimit).catch(() => null);
      if (!file) continue;
      await file.handle.close();
      results.push({ agent_id: agentId, path: file.path, name: file.name, size: file.size });
    }
    return results;
  } catch { return []; }
}
