#!/usr/bin/env python3
"""Offline release scan. Inspect the staged blobs AND files eligible for git add."""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

LIMIT = 2 * 1024 * 1024
DENIED = re.compile(
    r"(?:^|/)(?:node_modules|node-compile-cache|data|\.npm)(?:/|$)|"
    r"(?:^|/)(?:\.env(?!\.example$)(?:\..*)?|\.tunnel[^/]*|\.npmrc|id_(?:rsa|ed25519)|"
    r"credentials(?:\.json)?|cookies(?:\.txt)?|state\.json)$|"
    r"\.(?:db|sqlite3?)(?:-\w+)?$|\.(?:zip|tgz|gz|bz2|xz|tar|jsonl|out|key|pem|p12)$|\.log(?:\..*)?$", re.I)
RULES = {
    "private key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "token": re.compile(r"\b(?:(?:obr_|obf_|gh[pousr]_|github_pat_|xox[baprs]-|sk-(?:proj-)?)[A-Za-z0-9_-]{20,}|code_[A-Za-z0-9_-]{32}(?![A-Za-z0-9_-])|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{32,}|eyJ[\w-]{10,}\.[\w-]{8,}\.[\w-]{8,})"),
    "bearer credential": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.I),
    "credential literal": re.compile(r"""(?ix)\b(?:BRIDGE_ADMIN_SECRET|adminSecret|client_secret|refresh_token|access_token|api[_-]?key|password|session[_-]?cookie)["']?\s*[:=]\s*["']([\w/+=.-]{16,})["']"""),
    "environment credential": re.compile(r"^\s*(?:export\s+)?[\w]*(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*[A-Za-z0-9+/=_-]{12,}\s*$", re.I),
    "cookie header": re.compile(r"""(?i)["']?(?:set-cookie|cookie)["']?\s*:\s*["']?\w+=[A-Za-z0-9._/+=-]{12,}"""),
    "private tunnel": re.compile(r"\b[\w-]+\.(?:ngrok-free\.(?:app|dev)|ngrok\.io|trycloudflare\.com)\b", re.I),
    "installation identity": re.compile(r"\bagent-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\b|/(?:home|Users)/[\w.-]+/", re.I),
}

def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)

def check(path, mode, read_size, read_contents, source):
    def issue(reason, line=None):
        location = ascii(path)
        print(f"{source} {location}{':' + str(line) if line else ''} {reason}")
        return 1

    if DENIED.search(path):
        return issue("excluded runtime or credential path")
    if not mode:
        return issue("non-regular file")
    if read_size() > LIMIT:
        return issue("oversized file requires review")
    try:
        raw = read_contents()
        if b"\0" in raw:
            return issue("binary file requires review")
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return issue("non-UTF-8 file requires review")
    count = 0
    for n, line in enumerate(lines, 1):
        for reason, pattern in RULES.items():
            if pattern.search(line):
                count += issue(reason, n)
    return count

def main():
    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel").rstrip(b"\n")))
    os.chdir(root)
    hits = 0
    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, oid, stage = metadata.decode().split()
        if stage != "0":
            raise ValueError("unresolved index")
        hits += check(os.fsdecode(raw_path), mode in {"100644", "100755"},
                      lambda: int(git("cat-file", "-s", oid)),
                      lambda: git("cat-file", "blob", oid), "index")
    for raw_path in set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""}:
        name = os.fsdecode(raw_path)
        path = root / name
        if path.parent.resolve() != path.parent:
            print(f"worktree {ascii(name)} indirect parent path")
            hits += 1
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue  # Deletions remain covered by the index.
        hits += check(name, stat.S_ISREG(info.st_mode), lambda: info.st_size, path.read_bytes, "worktree")
    print(f"Release scan: {hits} finding(s).")
    return 1 if hits else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        sys.exit("Release scan incomplete. Check the repository and permissions.")
