#!/usr/bin/env python3
"""Check that a finding ledger covers every validated finding of the 2026-11-15 review.

usage: python3 check_coverage.py <ledger.md>

The ledger is a Markdown table with rows `| <finding id> | <commit hash> | <note> |`.
Expected ids: every non-refuted finding in db.json plus the critic-raised items
N1-N5, N7-N9, N11, N12, N16, N17 and H4a. Exit 0 only when every expected id appears
exactly once, no unknown id appears, and every commit hash exists in `git log`.
"""
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
db = json.loads((HERE / "db.json").read_text())
expected = {k for k, v in db.items() if not v["verdict"].startswith("REFUTED")}
expected |= {"N1", "N2", "N3", "N4", "N5", "N7", "N8", "N9", "N11", "N12", "N16", "N17", "H4a"}

ledger = pathlib.Path(sys.argv[1]).read_text()
rows = re.findall(r"^\|\s*`?([A-Z0-9]+-?\d*[a-z]?)`?\s*\|\s*`?([0-9a-f]{7,40})`?\s*\|", ledger, re.M)
seen = {}
for fid, commit in rows:
    seen.setdefault(fid, []).append(commit)

errors = []
for fid in sorted(expected - set(seen)):
    errors.append(f"missing: {fid}")
for fid in sorted(set(seen) - expected):
    errors.append(f"unknown id: {fid}")
for fid, commits in sorted(seen.items()):
    if len(commits) > 1:
        errors.append(f"listed {len(commits)} times: {fid}")
for commit in sorted({c for cs in seen.values() for c in cs}):
    ok = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True).returncode == 0
    if not ok:
        errors.append(f"unknown commit: {commit}")

print(f"expected {len(expected)} ids, ledger rows {len(rows)}")
for e in errors:
    print(e)
sys.exit(1 if errors else 0)
