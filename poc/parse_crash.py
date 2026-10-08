#!/usr/bin/env python3
import sys, json

if len(sys.argv) < 2:
    print("usage: parse_crash.py <crash.ips>")
    sys.exit(1)

try:
    with open(sys.argv[1]) as f:
        raw = f.read()
    try:
        d = json.loads(raw)
        print("exception:", d.get("exception", {}).get("message", ""))
        for t in d.get("threads", []):
            if t.get("triggered"):
                for fr in t.get("frames", []):
                    print(" ", fr.get("symbol", ""), fr.get("sourceFile", ""), fr.get("sourceLine", ""))
    except json.JSONDecodeError:
        print(raw[:3000])
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
