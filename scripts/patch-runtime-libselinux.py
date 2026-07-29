#!/usr/bin/env python3
"""Restore standard file/process context APIs in redroid's arm64 libselinux."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

STOCK_SHA256 = "91c4c689626fa00d28a0e7c0b7af208c9188e3003b0da905945e678d175cea34"
PATCHED_SHA256 = "936a738bc6d6c180ac859096cc39e27d1be6417e8da00eda76a05a9105327ec4"

PATCHES = (
    (
        0xBE28,
        "280000d008212d91080140f91f0100f1e0079f1ac0035fd6",
        "20008052c0035fd62f70726f632f73656c662f6578650000",
    ),
    (
        0xC934,
        "fd7bbea9f30b00f9fd030091f30301aae000805221008052f5090094e80300aa"
        "092988526968a972aa888852e0031f2a680200f9f30b40f9090100b90a090079"
        "fd7bc2a8c0035fd6",
        "f353bea9fe0b00f9f30300aaf40301aa0008805221008052f5090094800200f9"
        "e20300aae00313aa1f2003d5e120fb10e3078052280180d2010000d4fe0b40f9"
        "f353c2a8c0035fd6",
    ),
    (
        0xCDB4,
        "fd7bbea9f30b00f9fd030091f30300aae000805221008052d5080094e80300aa"
        "092988526968a972aa888852e0031f2a680200f9f30b40f9090100b90a090079"
        "fd7bc2a8c0035fd6",
        "fd7bbfa9fd030091e10300aa8083ff10dcfeff971f0000f1e0a3809afd7bc1a8"
        "c0035fd61f2003d51f2003d51f2003d51f2003d51f2003d51f2003d51f2003d5"
        "1f2003d51f2003d5",
    ),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch(source: Path, destination: Path) -> None:
    original = source.read_bytes()
    digest = sha256(original)
    if digest == PATCHED_SHA256:
        destination.write_bytes(original)
        return
    if digest != STOCK_SHA256:
        raise SystemExit(
            f"SHA256 mismatch for {source}: expected {STOCK_SHA256}, got {digest}"
        )

    data = bytearray(original)
    for offset, expected_hex, replacement_hex in PATCHES:
        expected = bytes.fromhex(expected_hex)
        replacement = bytes.fromhex(replacement_hex)
        if len(expected) != len(replacement):
            raise AssertionError(f"patch length mismatch at {offset:#x}")
        actual = bytes(data[offset : offset + len(expected)])
        if actual != expected:
            raise SystemExit(
                f"unexpected bytes at {offset:#x}: expected {expected.hex()}, got {actual.hex()}"
            )
        data[offset : offset + len(expected)] = replacement

    patched = bytes(data)
    patched_digest = sha256(patched)
    if patched_digest != PATCHED_SHA256:
        raise SystemExit(
            f"patched SHA256 mismatch: expected {PATCHED_SHA256}, got {patched_digest}"
        )
    destination.write_bytes(patched)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    patch(args.source, args.destination or args.source)
    print(PATCHED_SHA256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
