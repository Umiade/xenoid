"""Xenoid daemon purpose-channel AEAD v1.

All failures are redacted: neither keys nor envelope/plaintext data are included
in exceptions.  Callers should keep one :class:`ReplayWindow` per peer channel.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
from typing import Any, Dict, Mapping, Optional


PROTOCOL_VERSION = 1
MAX_SEQUENCE = (1 << 63) - 1
MAX_SESSIONS = 32
MAX_PLAINTEXT_BYTES = 6 * 1024 * 1024 + 4096
MAX_TIMESTAMP = 253402300799
_HEX_32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_IDENTITY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
_TOKEN = re.compile(r"^[A-Za-z0-9._/-]{1,128}$", re.ASCII)
_OPERATIONS = frozenset({"desired", "report", "probe"})
_CODES = frozenset({"agent_rejected", "protocol_dependency_missing"})


class ProxyProtocolError(Exception):
    """A stable, secret-free purpose-channel failure."""

    def __init__(self, code: str):
        self.code = code if code in _CODES else "agent_rejected"
        super().__init__(self.code)


class ReplayWindow:
    """Strict per-session high-water marks with a bounded session set."""

    def __init__(self, maximum_sessions: int = MAX_SESSIONS):
        if (not isinstance(maximum_sessions, int) or isinstance(maximum_sessions, bool)
                or maximum_sessions < 1 or maximum_sessions > MAX_SESSIONS):
            raise ProxyProtocolError("agent_rejected") from None
        self._maximum_sessions = maximum_sessions
        self._high_water: Dict[str, int] = {}
        self._lock = threading.Lock()

    def check(self, session: str, sequence: int) -> None:
        _session(session)
        _sequence(sequence)
        with self._lock:
            prior = self._high_water.get(session)
            if prior is not None and sequence <= prior:
                raise ProxyProtocolError("agent_rejected") from None
            if prior is None and len(self._high_water) >= self._maximum_sessions:
                raise ProxyProtocolError("agent_rejected") from None

    def commit(self, session: str, sequence: int) -> None:
        _session(session)
        _sequence(sequence)
        with self._lock:
            prior = self._high_water.get(session)
            if prior is not None and sequence <= prior:
                raise ProxyProtocolError("agent_rejected") from None
            if prior is None and len(self._high_water) >= self._maximum_sessions:
                raise ProxyProtocolError("agent_rejected") from None
            self._high_water[session] = sequence

    def accept(self, session: str, sequence: int) -> None:
        """Atomically accept an already-authenticated record."""
        self.commit(session, sequence)


# RFC 5869 implemented with stdlib HMAC so key derivation remains available to
# bootstrap code before the optional AES-GCM dependency is loaded.
def _hkdf_sha256(input_key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    pseudorandom_key = hmac.new(salt, input_key, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def _key(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _identity(value: Any) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _session(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _request_id(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _sequence(value: Any) -> int:
    if (not isinstance(value, int) or isinstance(value, bool)
            or value < 1 or value > MAX_SEQUENCE):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _status(value: Any, *, request: bool = False) -> int:
    if request:
        if value != 0:
            raise ProxyProtocolError("agent_rejected") from None
        return 0
    if (not isinstance(value, int) or isinstance(value, bool)
            or value < 100 or value > 599):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _operation(value: Any) -> str:
    if not isinstance(value, str) or value not in _OPERATIONS:
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _timestamp(value: Any) -> int:
    if (not isinstance(value, int) or isinstance(value, bool)
            or value < 0 or value > MAX_TIMESTAMP):
        raise ProxyProtocolError("agent_rejected") from None
    return value


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ProxyProtocolError("agent_rejected") from None
    if not encoded or len(encoded) > MAX_PLAINTEXT_BYTES:
        raise ProxyProtocolError("agent_rejected") from None
    return encoded


def _json_object(value: bytes) -> Dict[str, Any]:
    if len(value) > MAX_PLAINTEXT_BYTES:
        raise ProxyProtocolError("agent_rejected") from None
    try:
        document = json.loads(value.decode("utf-8"), object_pairs_hook=_pairs)
    except ProxyProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError,
            RecursionError):
        raise ProxyProtocolError("agent_rejected") from None
    if not isinstance(document, dict):
        raise ProxyProtocolError("agent_rejected") from None
    # Re-encoding also rejects NaN/infinity and non-JSON-compatible values.
    _canonical(document)
    return document


def _pairs(items: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if not isinstance(key, str) or key in result:
            raise ProxyProtocolError("agent_rejected") from None
        result[key] = value
    return result


def _aesgcm(key: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ProxyProtocolError("protocol_dependency_missing") from None
    try:
        return AESGCM(_key(key))
    except Exception:
        raise ProxyProtocolError("agent_rejected") from None


def derive_key(master: bytes, instance_id: str, runtime_epoch: str,
               direction: str) -> bytes:
    """Derive the c2s or s2c AES-256-GCM direction key."""
    master_key = _key(master)
    instance = _identity(instance_id)
    epoch = _identity(runtime_epoch)
    if direction not in ("c2s", "s2c"):
        raise ProxyProtocolError("agent_rejected") from None
    salt = (instance + "\n" + epoch).encode("utf-8")
    info = ("xenoid-proxy-agent/" + direction).encode("utf-8")
    return _hkdf_sha256(master_key, salt, info, 32)


def _nonce(direction_key: bytes, session: str, sequence: int) -> bytes:
    key = _key(direction_key)
    session_value = _session(session)
    sequence_value = _sequence(sequence)
    prefix = hmac.new(key, session_value.encode("utf-8"), hashlib.sha256).digest()[:4]
    return prefix + sequence_value.to_bytes(8, "big", signed=False)


def _aad(direction: str, instance_id: str, runtime_epoch: str, session: str,
         sequence: int, request_id: str, status: int) -> bytes:
    if direction not in ("c2s", "s2c"):
        raise ProxyProtocolError("agent_rejected") from None
    instance = _identity(instance_id)
    epoch = _identity(runtime_epoch)
    session_value = _session(session)
    sequence_value = _sequence(sequence)
    request = _request_id(request_id)
    status_value = _status(status, request=direction == "c2s")
    return (
        "XENOID-PROXY-AEAD-V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}".format(
            direction, instance, epoch, session_value, sequence_value, request,
            status_value
        )
    ).encode("utf-8")


def _encode_ciphertext(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_ciphertext(value: Any) -> bytes:
    if (not isinstance(value, str) or not value or len(value) >
            ((MAX_PLAINTEXT_BYTES + 16 + 2) // 3) * 4
            or any(character.isspace() for character in value)):
        raise ProxyProtocolError("agent_rejected") from None
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ProxyProtocolError("agent_rejected") from None
    if len(decoded) < 16 or len(decoded) > MAX_PLAINTEXT_BYTES + 16:
        raise ProxyProtocolError("agent_rejected") from None
    if base64.b64encode(decoded) != encoded:
        raise ProxyProtocolError("agent_rejected") from None
    return decoded


def _outer(envelope: Any, response: bool) -> Dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ProxyProtocolError("agent_rejected") from None
    keys = {
        "version", "instanceId", "runtimeEpoch", "session", "seq",
        "requestId", "ciphertext",
    }
    if response:
        keys.add("status")
    if (set(envelope) != keys or type(envelope.get("version")) is not int
            or envelope.get("version") != PROTOCOL_VERSION):
        raise ProxyProtocolError("agent_rejected") from None
    _identity(envelope.get("instanceId"))
    _identity(envelope.get("runtimeEpoch"))
    _session(envelope.get("session"))
    _sequence(envelope.get("seq"))
    _request_id(envelope.get("requestId"))
    _decode_ciphertext(envelope.get("ciphertext"))
    if response:
        _status(envelope.get("status"))
    return envelope


def _match(value: Any, expected: Any) -> None:
    if not hmac.compare_digest(str(value).encode("utf-8"),
                               str(expected).encode("utf-8")):
        raise ProxyProtocolError("agent_rejected") from None


def seal_request(direction_key: bytes, instance_id: str, runtime_epoch: str,
                 session: str, seq: int, request_id: str, operation: str,
                 timestamp: int, body: Any) -> Dict[str, Any]:
    """Seal canonical ``{operation,timestamp,body}`` as a c2s record."""
    key = _key(direction_key)
    instance = _identity(instance_id)
    epoch = _identity(runtime_epoch)
    session_value = _session(session)
    sequence = _sequence(seq)
    request = _request_id(request_id)
    inner = {"operation": _operation(operation), "timestamp": _timestamp(timestamp),
             "body": body}
    plaintext = _canonical(inner)
    aad = _aad("c2s", instance, epoch, session_value, sequence, request, 0)
    try:
        ciphertext = _aesgcm(key).encrypt(
            _nonce(key, session_value, sequence), plaintext, aad
        )
    except ProxyProtocolError:
        raise
    except Exception:
        raise ProxyProtocolError("agent_rejected") from None
    return {
        "version": PROTOCOL_VERSION,
        "instanceId": instance,
        "runtimeEpoch": epoch,
        "session": session_value,
        "seq": sequence,
        "requestId": request,
        "ciphertext": _encode_ciphertext(ciphertext),
    }


def open_request(direction_key: bytes, envelope: Mapping[str, Any],
                 expected_instance_id: str, expected_runtime_epoch: str,
                 replay: Optional[ReplayWindow] = None) -> Dict[str, Any]:
    """Authenticate and open a c2s record (server-side helper)."""
    key = _key(direction_key)
    outer = _outer(envelope, False)
    _match(outer["instanceId"], _identity(expected_instance_id))
    _match(outer["runtimeEpoch"], _identity(expected_runtime_epoch))
    session = outer["session"]
    sequence = outer["seq"]
    if replay is not None:
        replay.check(session, sequence)
    aad = _aad("c2s", outer["instanceId"], outer["runtimeEpoch"], session,
               sequence, outer["requestId"], 0)
    try:
        plaintext = _aesgcm(key).decrypt(
            _nonce(key, session, sequence), _decode_ciphertext(outer["ciphertext"]),
            aad
        )
    except ProxyProtocolError:
        raise
    except Exception:
        raise ProxyProtocolError("agent_rejected") from None
    inner = _json_object(plaintext)
    if set(inner) != {"operation", "timestamp", "body"}:
        raise ProxyProtocolError("agent_rejected") from None
    _operation(inner["operation"])
    _timestamp(inner["timestamp"])
    if replay is not None:
        replay.commit(session, sequence)
    return inner


def seal_response(direction_key: bytes, instance_id: str, runtime_epoch: str,
                  session: str, seq: int, request_id: str, status: int,
                  body: Any = None, *, ok: bool = True,
                  error: Optional[str] = None) -> Dict[str, Any]:
    """Seal canonical ``{ok,body}`` or ``{ok,error}`` as an s2c record."""
    key = _key(direction_key)
    instance = _identity(instance_id)
    epoch = _identity(runtime_epoch)
    session_value = _session(session)
    sequence = _sequence(seq)
    request = _request_id(request_id)
    status_value = _status(status)
    if not isinstance(ok, bool):
        raise ProxyProtocolError("agent_rejected") from None
    if ok:
        if error is not None:
            raise ProxyProtocolError("agent_rejected") from None
        inner = {"ok": True, "body": body}
    else:
        if body is not None or not isinstance(error, str) or not _TOKEN.fullmatch(error):
            raise ProxyProtocolError("agent_rejected") from None
        inner = {"ok": False, "error": error}
    plaintext = _canonical(inner)
    aad = _aad("s2c", instance, epoch, session_value, sequence, request,
               status_value)
    try:
        ciphertext = _aesgcm(key).encrypt(
            _nonce(key, session_value, sequence), plaintext, aad
        )
    except ProxyProtocolError:
        raise
    except Exception:
        raise ProxyProtocolError("agent_rejected") from None
    return {
        "version": PROTOCOL_VERSION,
        "instanceId": instance,
        "runtimeEpoch": epoch,
        "session": session_value,
        "seq": sequence,
        "requestId": request,
        "status": status_value,
        "ciphertext": _encode_ciphertext(ciphertext),
    }


def open_response(direction_key: bytes, envelope: Mapping[str, Any],
                  expected_instance_id: str, expected_runtime_epoch: str,
                  expected_session: str, expected_seq: int,
                  expected_request_id: str,
                  replay: Optional[ReplayWindow] = None) -> Dict[str, Any]:
    """Authenticate an s2c response and bind it to one outstanding request."""
    key = _key(direction_key)
    outer = _outer(envelope, True)
    _match(outer["instanceId"], _identity(expected_instance_id))
    _match(outer["runtimeEpoch"], _identity(expected_runtime_epoch))
    _match(outer["session"], _session(expected_session))
    _match(outer["seq"], _sequence(expected_seq))
    _match(outer["requestId"], _request_id(expected_request_id))
    session = outer["session"]
    sequence = outer["seq"]
    if replay is not None:
        replay.check(session, sequence)
    aad = _aad("s2c", outer["instanceId"], outer["runtimeEpoch"], session,
               sequence, outer["requestId"], outer["status"])
    try:
        plaintext = _aesgcm(key).decrypt(
            _nonce(key, session, sequence), _decode_ciphertext(outer["ciphertext"]),
            aad
        )
    except ProxyProtocolError:
        raise
    except Exception:
        raise ProxyProtocolError("agent_rejected") from None
    inner = _json_object(plaintext)
    if set(inner) == {"ok", "body"}:
        if inner["ok"] is not True:
            raise ProxyProtocolError("agent_rejected") from None
    elif set(inner) == {"ok", "error"}:
        if inner["ok"] is not False or not isinstance(inner["error"], str) \
                or not _TOKEN.fullmatch(inner["error"]):
            raise ProxyProtocolError("agent_rejected") from None
    else:
        raise ProxyProtocolError("agent_rejected") from None
    if replay is not None:
        replay.commit(session, sequence)
    result = dict(inner)
    result["status"] = outer["status"]
    return result


__all__ = [
    "MAX_SEQUENCE", "PROTOCOL_VERSION", "ProxyProtocolError", "ReplayWindow",
    "derive_key", "open_request", "open_response", "seal_request",
    "seal_response",
]
