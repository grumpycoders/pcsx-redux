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
    # -ferror-limit is CLANG-ONLY. gcc rejects it outright, so on any arm that
    # uses gcc every entry fails on MY OWN FLAG and the sweep reports 0/259 with
    # no information about the code whatsoever. That used to be six entries
    # (LuaJIT's host tools) and read as a footnote; run the same script against
    # the desktop arm, which is gcc throughout, and it is the entire result.
    # An instrument that fails on 100% of its subjects is not a measurement.
    cc = os.path.basename(out[0]) if out else ""
    is_gcc = ("gcc" in cc or cc.endswith("g++")) and "clang" not in cc
    out += ["-fsyntax-only", "-fmax-errors=0" if is_gcc else "-ferror-limit=0"]
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

# A top-N is a SAMPLE. Print the distinct total beside every itemisation, and
# say out loud when the tail was cut - in a failure histogram the
# single-occurrence tail is the interesting part, and an aggregate that is
# correct is exactly what makes a truncated list beside it read as complete.
def show(title, counter, n=40):
    total = len(counter)
    print(f"\n=== {title} === ({total} distinct)")
    for k, v in counter.most_common(n):
        print(f"{v:4d}  {k}")
    if total > n:
        print(f"  ... SAMPLE: {total - n} more distinct entries NOT SHOWN")

show("MISSING HEADERS (count = files blocked by it)", missing)
show("OTHER ERRORS", othererr)
show("FAILING FILES BY DIRECTORY",
     collections.Counter(os.path.dirname(f) for f, _, _ in bad))

with open("/tmp/wasm-sweep-detail.txt", "w") as fh:
    for f, rc, err in bad:
        fh.write(f"===== {f} (rc={rc})\n{err}\n")
print("\nfull stderr per failing file -> /tmp/wasm-sweep-detail.txt")
