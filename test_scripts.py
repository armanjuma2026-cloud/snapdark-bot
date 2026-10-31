#!/usr/bin/env python3
"""Batch-test every decryptor: which ones actually produce a fresh JSON."""
import os, subprocess, sys, time

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script_test.log")

def snapshot():
    seen = {}
    for d in ("/sdcard/VPNs", "/sdcard"):
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for fn in names:
            if fn.lower().endswith(".json"):
                p = os.path.join(d, fn)
                try:
                    seen[p] = (os.path.getmtime(p), os.path.getsize(p))
                except OSError:
                    pass
    return seen


def newest_json(started, seen):
    best, best_m = None, 0
    for d in ("/sdcard/VPNs", "/sdcard"):
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for fn in names:
            if not fn.lower().endswith(".json"):
                continue
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_size <= 32 or st.st_mtime < started:
                continue
            if seen.get(p) == (st.st_mtime, st.st_size):
                continue
            if st.st_mtime > best_m:
                best, best_m = p, st.st_mtime
    return best

results = []
names = sorted((f for f in os.listdir(BASE) if f.endswith(".py") and not f.startswith("_")), key=str.lower)
for i, fn in enumerate(names, 1):
    seen = snapshot()
    started = time.time() - 1
    line = f"[{i}/{len(names)}] {fn[:-3]} ... "
    print(line, end="", flush=True)
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(BASE, fn)],
            cwd=BASE, capture_output=True, stdin=subprocess.DEVNULL, timeout=90,
        )
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc = "TIMEOUT"
    out = newest_json(started, seen) if rc == 0 else None
    if out:
        res = f"OK {os.path.getsize(out)//1024}KB {os.path.basename(out)}"
    elif rc == "TIMEOUT":
        res = "TIMEOUT (>90s, likely hangs)"
    elif rc == 0:
        res = "ran but no new JSON"
    else:
        res = f"FAIL rc={rc}"
    results.append((fn[:-3], res))
    print(res, flush=True)
    with open(OUT, "w") as fh:
        fh.write(f"# decryptor test {time.strftime('%Y-%m-%d %H:%M')}\n")
        ok = sum(1 for _, r in results if r.startswith("OK"))
        fh.write(f"# working {ok}/{len(names)} (tested {len(results)})\n")
        for n, r in results:
            fh.write(f"{'✅' if r.startswith('OK') else '❌'} {n}: {r}\n")

ok = sum(1 for _, r in results if r.startswith("OK"))
print(f"\nDONE {ok}/{len(names)} working")
