#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, sys
script = pathlib.Path(sys.argv[1])
source = script.read_text()
patterns = [
  ('tap', re.compile(r'xenoid\.tap\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)')),
  ('swipe', re.compile(r'xenoid\.swipe\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*(\d+))?\s*\)')),
  ('sleep', re.compile(r'xenoid\.sleep\s*\(\s*(\d+)\s*\)')),
  ('shell', re.compile(r'xenoid\.shell\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)')),
  ('launch', re.compile(r'xenoid\.launch\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)')),
  ('install', re.compile(r'xenoid\.install\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)')),
  ('uninstall', re.compile(r'xenoid\.uninstall\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)')),
  ('set', re.compile(r'xenoid\.set\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]\s*\)')),
]
calls=[]
for op, pat in patterns:
    for m in pat.finditer(source):
        calls.append({'index': m.start(), 'op': op, 'args': list(m.groups())})
calls.sort(key=lambda x:x['index'])
print(json.dumps({'ok': True, 'script': str(script), 'calls': calls, 'count': len(calls)}, indent=2))
