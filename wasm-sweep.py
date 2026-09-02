#!/usr/bin/env python3
"""Enumerate the WHOLE wasm compile surface in one pass.

Iterating one build error per rebuild is the wrong shape for this: xmake stops at
the first failing target and you learn one fact per minute. Replaying every
compile_commands entry with -fsyntax-only, in parallel, gives every file's verdict
at once. -ferror-limit=0 so a file reports all its errors rather than the first 20.

NOTE the schema: xmake emits `arguments` (a list), NOT `command` (a string). A
sweep written against `command` gets a KeyError on entry 0 and looks like a broken
script rather than a wrong assumption.
"""
import json, subprocess, sys, os, collections
from concurrent.futures import ThreadPoolExecutor

CC = sys.argv[1] if len(sys.argv) > 1 else "compile_commands.json"
JOBS = int(sys.argv[2]) if len(sys.argv) > 2 else 24   # bounded: shared host

entries = json.load(open(CC))

def run(e):
    args = list(e["arguments"])
    out = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-c", "-o"):
            if a == "-o":
                skip_next = True
            continue
        out.append(a)
    out += ["-fsyntax-only", "-ferror-limit=0"]
    try:
        p = subprocess.run(out, cwd=e["directory"], capture_output=True,
                           text=True, timeout=300)
        return e["file"], p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        return e["file"], 124, "TIMEOUT"

results = []
with ThreadPoolExecutor(max_workers=JOBS) as ex:
    for r in ex.map(run, entries):
        results.append(r)

bad = [r for r in results if r[1] != 0]
print(f"TOTAL {len(results)}  OK {len(results)-len(bad)}  FAILED {len(bad)}")

# What is actually blocking, aggregated by the missing header or the error text.
missing = collections.Counter()
othererr = collections.Counter()
for f, rc, err in bad:
    for line in err.splitlines():
        if "file not found" in line:
            missing[line.split("'")[1] if "'" in line else line.strip()] += 1
        elif " error: " in line:
            msg = line.split(" error: ", 1)[1].strip()
            othererr[msg[:110]] += 1

print("\n=== MISSING HEADERS (count = files blocked by it) ===")
for h, n in missing.most_common(40):
    print(f"{n:4d}  {h}")

print("\n=== OTHER ERRORS ===")
for m, n in othererr.most_common(30):
    print(f"{n:4d}  {m}")

print("\n=== FAILING FILES BY DIRECTORY ===")
byd = collections.Counter(os.path.dirname(f) for f, _, _ in bad)
for d, n in byd.most_common(30):
    print(f"{n:4d}  {d or '.'}")

with open("/tmp/wasm-sweep-detail.txt", "w") as fh:
    for f, rc, err in bad:
        fh.write(f"===== {f} (rc={rc})\n{err}\n")
print("\nfull stderr per failing file -> /tmp/wasm-sweep-detail.txt")
