import { readFile, readdir } from "node:fs/promises";
import { statfsSync } from "node:fs";
import os from "node:os";

/** Reads one CPU sample from /proc/stat. */
async function cpuSample() {
  const text = await readFile("/proc/stat", "utf8");
  const line = text.split("\n").find((row) => row.startsWith("cpu "));
  if (!line) return null;
  const values = line.trim().split(/\s+/).slice(1).map(Number);
  const idle = (values[3] ?? 0) + (values[4] ?? 0);
  const total = values.reduce((sum, value) => sum + value, 0);
  return { idle, total };
}

export async function cpuPercent(sampleMs = 150) {
  const first = await cpuSample();
  if (!first) return null;
  await new Promise((resolve) => setTimeout(resolve, sampleMs));
  const second = await cpuSample();
  if (!second) return null;
  const total = second.total - first.total;
  const idle = second.idle - first.idle;
  if (total <= 0) return null;
  return Math.round((1 - idle / total) * 1000) / 10;
}

async function memory() {
  const text = await readFile("/proc/meminfo", "utf8");
  const read = (key) => {
    const match = new RegExp(`^${key}:\\s+(\\d+) kB`, "m").exec(text);
    return match ? Number(match[1]) * 1024 : null;
  };
  const total = read("MemTotal");
  const available = read("MemAvailable");
  if (total === null || available === null) return null;
  return { totalBytes: total, usedBytes: total - available, availableBytes: available };
}

function disk(path = "/") {
  try {
    const stats = statfsSync(path);
    const total = Number(stats.blocks) * Number(stats.bsize);
    const free = Number(stats.bavail) * Number(stats.bsize);
    return { path, totalBytes: total, freeBytes: free, usedBytes: total - free };
  } catch {
    return null;
  }
}

/** Finds the OpenBot desktop process without spawning a shell. */
async function openbotProcess() {
  try {
    const entries = await readdir("/proc");
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        const comm = await readFile(`/proc/${entry}/comm`, "utf8");
        if (comm.trim() === "openbot") return { running: true, pid: Number(entry) };
      } catch {
        // The process disappeared while scanning.
      }
    }
  } catch {
    // /proc is unavailable (not Linux).
  }
  return { running: false, pid: null };
}

/** The resource summary ChatGPT sees. Bounded and free of personal data. */
export async function systemSnapshot() {
  const [cpu, mem, process] = await Promise.all([cpuPercent(), memory(), openbotProcess()]);
  const uptimeSeconds = Math.round(os.uptime());
  const load = os.loadavg().map((value) => Math.round(value * 100) / 100);
  const root = disk("/");
  const home = disk("/home");
  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()}`,
    cpu: {
      cores: os.cpus().length,
      loadAvg: load,
      percent: cpu,
    },
    memory: mem
      ? {
          totalBytes: mem.totalBytes,
          usedBytes: mem.usedBytes,
          availableBytes: mem.availableBytes,
          usedPercent: Math.round((mem.usedBytes / mem.totalBytes) * 1000) / 10,
        }
      : null,
    disk: { root, home },
    uptimeSeconds,
    openbotProcess: process,
    collectedAt: new Date().toISOString(),
  };
}
