#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.gates import main as gates_main


if __name__ == "__main__":
    raise SystemExit(gates_main(["audit", "--fresh"]))
