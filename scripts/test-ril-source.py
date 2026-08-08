#!/usr/bin/env python3
"""Runtime-free canonical profile and legacy RIL ABI contracts."""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.cellular import encode_profile_v1, generate_cellular_profile

COUNTRY = "SG"
MAGIC = b"XENOID_PROFILE_V1\0"


def require(value: bool) -> None:
    if not value:
        raise AssertionError


def parse_profile(payload: bytes) -> dict[int, bytes]:
    require(payload.startswith(MAGIC))
    version, count = struct.unpack_from(">II", payload, len(MAGIC))
    require(version == 1 and count == 21)
    cursor = len(MAGIC) + 8
    digest_offset = len(payload) - 32
    require(hashlib.sha256(payload[cursor:digest_offset]).digest() == payload[digest_offset:])
    fields: dict[int, bytes] = {}
    previous = 0
    while cursor < digest_offset:
        field_id, length = struct.unpack_from(">HI", payload, cursor)
        cursor += 6
        require(previous < field_id <= 21 and 0 < length <= 8192)
        require(cursor + length <= digest_offset)
        fields[field_id] = payload[cursor:cursor + length]
        cursor += length
        previous = field_id
    require(cursor == digest_offset and len(fields) == count)
    return fields


def test_canonical_binary_profile() -> None:
    profile = generate_cellular_profile(COUNTRY, b"r" * 32)
    encoded = encode_profile_v1(profile)
    fields = parse_profile(encoded)
    require(fields[1].decode() == profile["carrier"]["mcc"])
    require(fields[2].decode() == profile["carrier"]["mnc"])
    require(fields[3].decode() == profile["sim"]["imsi"])
    require(fields[4].decode() == profile["sim"]["iccid"])
    require(fields[5].decode() == profile["sim"]["msisdn"])
    require(fields[5].decode().startswith(profile["callingCode"]))
    require(fields[19].decode() == profile["timezone"])
    require(struct.unpack(">I", fields[11])[0] == profile["cell"]["earfcn"])
    require(struct.unpack(">I", fields[12])[0] == profile["cell"]["band"])
    require(struct.unpack(">I", fields[21])[0] == profile["cell"]["bandwidthKhz"])
    corrupt = bytearray(encoded)
    corrupt[-1] ^= 1
    try:
        parse_profile(bytes(corrupt))
    except AssertionError:
        pass
    else:
        raise AssertionError


def test_ril_source_contract() -> None:
    source = (ROOT / "native/xenoid-ril/xenoid_ril.c").read_text()
    required = [
        "RIL_Init", "radio_functions={15", "RIL_REQUEST_GET_SIM_STATUS",
        "RIL_REQUEST_SIM_IO", "RIL_REQUEST_GET_IMSI", "RIL_REQUEST_OPERATOR",
        "RIL_REQUEST_VOICE_REGISTRATION_STATE", "RIL_REQUEST_DATA_REGISTRATION_STATE",
        "RIL_REQUEST_SIGNAL_STRENGTH", "RIL_REQUEST_GET_CELL_INFO_LIST",
        "RIL_REQUEST_SETUP_DATA_CALL", "RIL_REQUEST_DEACTIVATE_DATA_CALL",
        "RIL_REQUEST_DATA_CALL_LIST", "RIL_E_REQUEST_NOT_SUPPORTED",
        "RIL_Data_Call_Response_v11", "RIL_CellInfo_v12", "RIL_SignalStrength_v10",
        "RIL_UNSOL_CELL_INFO_LIST",
        "O_NOFOLLOW", "S_ISREG", "PROFILE_FIELDS", "sha256_final",
        '"rmnet_data0"',
        "bcd_pair", "0x2fe2", "0x6f07", "0x6fad", "0x6f46", "0x6f40", "0x91",
    ]
    require(all(token in source for token in required))
    require("json" not in source.lower())
    require("su " not in source and "/system/xbin/su" not in source)
    library = ROOT / "native/xenoid-ril/libxenoid-ril.so"
    require(library.is_file() and library.read_bytes().startswith(b"\x7fELF"))


def main() -> int:
    test_canonical_binary_profile()
    test_ril_source_contract()
    print(json.dumps({"ok": True, "tests": 2}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
