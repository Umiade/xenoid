#!/usr/bin/env python3
import json, sys
try:
    data=json.load(sys.stdin)
    sys.exit(0 if data.get('ok') is True else 1)
except Exception:
    sys.exit(1)
