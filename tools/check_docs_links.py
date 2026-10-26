#!/usr/bin/env python3
"""Check local Markdown links without fetching external sites.

Run: python tools/check_docs_links.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / name for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md")]
FILES += list((ROOT / "docs").rglob("*.md"))
LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\n]+)\)")

issues: list[str] = []
relative_links = 0
for file in FILES:
    if not file.exists():
        continue
    content = file.read_text(encoding="utf-8-sig")
    for raw in LINK.findall(content):
        target = raw.strip().split(" ", 1)[0].strip("<>")
        if target.startswith(("https://", "http://", "mailto:", "data:", "#")):
            continue
        path = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not path:
            continue
        relative_links += 1
        full = (file.parent / path).resolve()
        if not full.is_relative_to(ROOT.resolve()) or not full.exists():
            issues.append(f"{file.relative_to(ROOT)} -> {target}")

print(f"Markdown: {sum(p.exists() for p in FILES)} | Links locais: {relative_links} | Quebrados: {len(issues)}")
for issue in issues:
    print(issue)
sys.exit(1 if issues else 0)
