"""Strict deterministic Mihomo source compiler and pinned-address fetcher.

Compilation is side-effect free. Remote Clash providers are fetched only through
an injected callback; the pinned fetcher is a separate utility for the engine's
unprivileged fetch process.
"""
from __future__ import annotations

import base64
import contextvars
import binascii
import hashlib
import http.client
import inspect
import ipaddress
import json
import math
import re
import socket
import ssl
import unicodedata
import uuid
import time
import zlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urljoin, urlsplit

MAX_SOURCE_BYTES = 1024 * 1024
MAX_NODES = 512
MAX_NODE_NAME = 128
MAX_YAML_NODES = 65536
MAX_DEPTH = 32
FETCH_TIMEOUT = 15.0
MAX_REDIRECTS = 5

_ERROR_CODES = frozenset({
    "source_invalid", "source_fetch_denied", "source_dependency_missing",
    "provider_empty", "selection_missing",
})


class ProxySourceError(Exception):
    """Redacted source failure containing only a stable machine code."""

    def __init__(self, code: str):
        self.code = code if code in _ERROR_CODES else "source_invalid"
        super().__init__(self.code)


@dataclass(frozen=True)
class CompiledSource:
    config: Dict[str, Any]
    node_names: Tuple[str, ...]
    source_sha256: str


@dataclass(frozen=True)
class FetchResult:
    body: bytes
    status: int
    content_type: str
    etag: str = ""
    last_modified: str = ""


_DOH_NAME = "cloudflare-dns.com"
_DOH_BOOTSTRAP_IPS = ("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111")
_ALLOWED_FETCH_TYPES = frozenset({
    "application/json", "application/octet-stream", "application/x-yaml",
    "application/yaml", "text/plain", "text/x-yaml", "text/yaml",
})
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)
_HEX_PAIR = re.compile(r"%[0-9A-Fa-f]{2}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FETCH_DEADLINE: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "xenoid_proxy_fetch_deadline", default=None)
_FETCH_USER_AGENT = "clash.meta"


# -------------------------- pinned HTTP fetcher --------------------------


def _public_ip(value: str) -> ipaddress._BaseAddress:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        raise ProxySourceError("source_fetch_denied") from None
    if (not address.is_global or address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_reserved
            or address.is_unspecified):
        raise ProxySourceError("source_fetch_denied") from None
    return address


def _domain_name(value: str, *, fetch: bool = False) -> str:
    error = "source_fetch_denied" if fetch else "source_invalid"
    if not isinstance(value, str) or not value or len(value) > 253 or _CONTROL.search(value):
        raise ProxySourceError(error) from None
    candidate = value[:-1] if value.endswith(".") else value
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ProxySourceError(error) from None
    if not ascii_name or any(not _HOST_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        raise ProxySourceError(error) from None
    if "." not in ascii_name or ascii_name == "localhost" or ascii_name.endswith((".local", ".localhost")):
        raise ProxySourceError(error) from None
    return ascii_name


def _node_host(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or _CONTROL.search(value):
        raise ProxySourceError("source_invalid") from None
    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return _domain_name(candidate)
    if not address.is_global:
        raise ProxySourceError("source_invalid") from None
    return address.compressed


def _remaining_fetch_timeout(maximum: float) -> float:
    deadline = _FETCH_DEADLINE.get()
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProxySourceError("source_fetch_denied") from None
    return min(maximum, remaining)


def _numeric_socket(address: str, port: int, timeout: float) -> socket.socket:
    parsed = _public_ip(address)
    sock = socket.socket(socket.AF_INET6 if parsed.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        target: Any = ((parsed.compressed, port, 0, 0) if parsed.version == 6
                       else (parsed.compressed, port))
        sock.connect(target)
        return sock
    except Exception:
        sock.close()
        raise ProxySourceError("source_fetch_denied") from None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = _numeric_socket(
            self._address, self.port,
            _remaining_fetch_timeout(float(self.timeout)))
        self.sock.settimeout(_remaining_fetch_timeout(float(self.timeout)))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float,
                 context: ssl.SSLContext):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw = _numeric_socket(
            self._address, self.port,
            _remaining_fetch_timeout(float(self.timeout)))
        try:
            raw.settimeout(_remaining_fetch_timeout(float(self.timeout)))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            self.sock.settimeout(_remaining_fetch_timeout(float(self.timeout)))
        except Exception:
            raw.close()
            raise ProxySourceError("source_fetch_denied") from None


def _bounded_header(value: Optional[str], maximum: int) -> str:
    if value is None:
        return ""
    if (not isinstance(value, str) or len(value) > maximum
            or _CONTROL.search(value)):
        raise ProxySourceError("source_fetch_denied") from None
    return value

def _response_content_type(response: http.client.HTTPResponse) -> str:
    raw = response.getheader("Content-Type", "")
    if not isinstance(raw, str) or len(raw) > 256 or _CONTROL.search(raw):
        raise ProxySourceError("source_fetch_denied") from None
    return raw.split(";", 1)[0].strip().lower()


def _validate_fetch_url(url: str, allow_insecure_http: bool) -> Tuple[str, str, int, str]:
    if not isinstance(url, str) or not url or len(url) > 4096 or _CONTROL.search(url):
        raise ProxySourceError("source_fetch_denied") from None
    try:
        url.encode("ascii")
    except UnicodeEncodeError:
        raise ProxySourceError("source_fetch_denied") from None
    if "\\" in url or any(character.isspace() for character in url):
        raise ProxySourceError("source_fetch_denied") from None
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("https", "http") or (scheme == "http" and not allow_insecure_http):
            raise ProxySourceError("source_fetch_denied") from None
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ProxySourceError("source_fetch_denied") from None
        if scheme == "http" and parsed.query:
            # Plain HTTP is an explicit compatibility opt-in, not permission to
            # transmit subscription tokens or other query credentials in cleartext.
            raise ProxySourceError("source_fetch_denied") from None
        if not parsed.hostname:
            raise ProxySourceError("source_fetch_denied") from None
        port = parsed.port or (443 if scheme == "https" else 80)
    except (ValueError, UnicodeError):
        raise ProxySourceError("source_fetch_denied") from None
    for component in (parsed.path, parsed.query):
        index = 0
        while index < len(component):
            if component[index] == "%":
                if (index + 3 > len(component)
                        or not _HEX_PAIR.fullmatch(component[index:index + 3])):
                    raise ProxySourceError("source_fetch_denied") from None
                index += 3
            else:
                index += 1
    if port < 1 or port > 65535:
        raise ProxySourceError("source_fetch_denied") from None
    try:
        host = _public_ip(parsed.hostname).compressed
    except ProxySourceError:
        # Distinguish a hostname from an unsafe IP literal: if ip_address can
        # parse it, the failed public check is terminal.
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            host = _domain_name(parsed.hostname, fetch=True)
        else:
            raise
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    return scheme, host, port, target


def _host_header(host: str, port: int, scheme: str) -> str:
    rendered = "[{}]".format(host) if ":" in host else host
    default = 443 if scheme == "https" else 80
    return rendered if port == default else "{}:{}".format(rendered, port)


def _read_response_body(response: http.client.HTTPResponse, maximum: int) -> bytes:
    raw_length = response.getheader("Content-Length")
    declared_length: Optional[int] = None
    if raw_length:
        if (not isinstance(raw_length, str)
                or not re.fullmatch(r"[0-9]{1,16}", raw_length)):
            raise ProxySourceError("source_fetch_denied") from None
        declared_length = int(raw_length, 10)
        if declared_length > maximum:
            raise ProxySourceError("source_fetch_denied") from None
    raw_encoding = response.getheader("Content-Encoding", "identity")
    if (not isinstance(raw_encoding, str) or len(raw_encoding) > 64
            or _CONTROL.search(raw_encoding)):
        raise ProxySourceError("source_fetch_denied") from None
    encoding = raw_encoding.strip().lower()
    if encoding not in ("", "identity", "gzip"):
        raise ProxySourceError("source_fetch_denied") from None

    network_socket = getattr(
        getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    wire_length = 0
    output = bytearray()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    while True:
        if _FETCH_DEADLINE.get() is not None:
            remaining = _remaining_fetch_timeout(FETCH_TIMEOUT)
            if network_socket is not None:
                network_socket.settimeout(remaining)
        try:
            chunk = response.read(min(65536, maximum - wire_length + 1))
        except Exception:
            raise ProxySourceError("source_fetch_denied") from None
        if type(chunk) is not bytes:
            raise ProxySourceError("source_fetch_denied") from None
        if not chunk:
            break
        wire_length += len(chunk)
        if wire_length > maximum:
            raise ProxySourceError("source_fetch_denied") from None
        if decoder is None:
            output.extend(chunk)
        else:
            if decoder.eof:
                raise ProxySourceError("source_fetch_denied") from None
            try:
                decoded = decoder.decompress(
                    chunk, maximum - len(output) + 1)
            except zlib.error:
                raise ProxySourceError("source_fetch_denied") from None
            output.extend(decoded)
            if decoder.unconsumed_tail or decoder.unused_data:
                raise ProxySourceError("source_fetch_denied") from None
        if len(output) > maximum:
            raise ProxySourceError("source_fetch_denied") from None
    if declared_length is not None and wire_length != declared_length:
        raise ProxySourceError("source_fetch_denied") from None
    if decoder is not None:
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ProxySourceError("source_fetch_denied") from None
        try:
            output.extend(decoder.flush(maximum - len(output) + 1))
        except zlib.error:
            raise ProxySourceError("source_fetch_denied") from None
        if len(output) > maximum:
            raise ProxySourceError("source_fetch_denied") from None
    if (_FETCH_DEADLINE.get() is not None
            and time.monotonic() > _FETCH_DEADLINE.get()):
        raise ProxySourceError("source_fetch_denied") from None
    return bytes(output)


class PinnedHTTPSFetcher:
    """Fetch without libc DNS for provider hosts, preserving SNI and Host."""

    def __init__(self, timeout: float = FETCH_TIMEOUT,
                 ssl_context: Optional[ssl.SSLContext] = None):
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout)
                or timeout <= 0 or timeout > FETCH_TIMEOUT):
            raise ProxySourceError("source_fetch_denied") from None
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise ProxySourceError("source_fetch_denied") from None
        self.timeout = float(timeout)
        context = ssl_context or ssl.create_default_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ProxySourceError("source_fetch_denied") from None
        self.ssl_context = context

    def _request(self, scheme: str, host: str, port: int, address: str,
                 target: str, headers: Mapping[str, str]) -> http.client.HTTPResponse:
        request_timeout = _remaining_fetch_timeout(self.timeout)
        connection: http.client.HTTPConnection
        if scheme == "https":
            connection = _PinnedHTTPSConnection(host, port, address, request_timeout,
                                                 self.ssl_context)
        else:
            connection = _PinnedHTTPConnection(host, port, address, request_timeout)
        try:
            connection.request("GET", target, headers=dict(headers))
            if connection.sock is not None:
                connection.sock.settimeout(_remaining_fetch_timeout(self.timeout))
            return connection.getresponse()
        except ProxySourceError:
            connection.close()
            raise
        except Exception:
            connection.close()
            raise ProxySourceError("source_fetch_denied") from None

    def _resolve(self, host: str) -> Tuple[str, ...]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return (_public_ip(literal.compressed).compressed,)
        answers: List[str] = []
        successful_types = 0
        for record_type in ("A", "AAAA"):
            query = "/dns-query?name={}&type={}".format(quote(host, safe=""), record_type)
            response: Optional[http.client.HTTPResponse] = None
            for bootstrap in _DOH_BOOTSTRAP_IPS:
                try:
                    response = self._request(
                        "https", _DOH_NAME, 443, bootstrap, query,
                        {"Accept": "application/dns-json", "Host": _DOH_NAME,
                         "User-Agent": "xenoid-proxy-fetch/1"},
                    )
                    break
                except ProxySourceError:
                    continue
            if response is None:
                continue
            try:
                if response.status != 200:
                    continue
                if type(response.status) is not int:
                    raise ProxySourceError("source_fetch_denied") from None
                content_type = _response_content_type(response)
                if content_type not in ("application/dns-json", "application/json"):
                    continue
                body = _read_response_body(response, 65536)
                document = json.loads(body.decode("utf-8"))
                if not isinstance(document, dict) or document.get("Status") != 0:
                    continue
                successful_types += 1
                records = document.get("Answer", [])
                if not isinstance(records, list) or len(records) > 128:
                    raise ProxySourceError("source_fetch_denied") from None
                wanted_type = 1 if record_type == "A" else 28
                for record in records:
                    if not isinstance(record, dict):
                        raise ProxySourceError("source_fetch_denied") from None
                    answer_type = record.get("type")
                    if answer_type in (1, 28):
                        address = _public_ip(record.get("data", "")).compressed
                        if answer_type == wanted_type:
                            answers.append(address)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                raise ProxySourceError("source_fetch_denied") from None
            finally:
                response.close()
        if successful_types != 2 or not answers:
            raise ProxySourceError("source_fetch_denied") from None
        return tuple(dict.fromkeys(answers))

    def __call__(self, url: str, *, headers: Optional[Mapping[str, str]] = None,
                 etag: str = "", last_modified: str = "",
                 allow_insecure_http: bool = False) -> FetchResult:
        _FETCH_DEADLINE.set(time.monotonic() + self.timeout)
        supplied: Dict[str, str] = {}
        if headers is not None:
            if not isinstance(headers, Mapping) or len(headers) > 1:
                raise ProxySourceError("source_fetch_denied") from None
            for key, value in headers.items():
                if (not isinstance(key, str) or key.lower() != "user-agent"
                        or not isinstance(value, str) or not value
                        or len(value) > 256 or _CONTROL.search(value)):
                    raise ProxySourceError("source_fetch_denied") from None
                supplied["User-Agent"] = value
        if etag:
            supplied["If-None-Match"] = _bounded_header(etag, 1024)
        if last_modified:
            supplied["If-Modified-Since"] = _bounded_header(last_modified, 128)

        current = url
        original_origin: Optional[Tuple[str, str, int]] = None
        forward_supplied_headers = True
        for redirect_count in range(MAX_REDIRECTS + 1):
            scheme, host, port, target = _validate_fetch_url(current, allow_insecure_http)
            origin = (scheme, host, port)
            if original_origin is None:
                original_origin = origin
            elif origin != original_origin:
                # Once a redirect crosses origin, validators stay stripped for
                # the remainder of the chain.
                forward_supplied_headers = False
            request_headers = dict(supplied if forward_supplied_headers else {})
            request_headers.update({
                "Accept": "application/yaml, application/json, text/yaml, text/plain, application/octet-stream",
                "Accept-Encoding": "gzip",
                "Host": _host_header(host, port, scheme),
            })
            request_headers.setdefault("User-Agent", _FETCH_USER_AGENT)
            response: Optional[http.client.HTTPResponse] = None
            for address in self._resolve(host):
                try:
                    response = self._request(scheme, host, port, address, target,
                                             request_headers)
                    break
                except ProxySourceError:
                    continue
            if response is None:
                raise ProxySourceError("source_fetch_denied") from None
            try:
                if type(response.status) is not int:
                    raise ProxySourceError("source_fetch_denied") from None
                if response.status in (301, 302, 303, 307, 308):
                    if redirect_count == MAX_REDIRECTS:
                        raise ProxySourceError("source_fetch_denied") from None
                    location = response.getheader("Location")
                    if (not isinstance(location, str) or not location
                            or len(location) > 4096 or _CONTROL.search(location)):
                        raise ProxySourceError("source_fetch_denied") from None
                    next_url = urljoin(current, location)
                    _validate_fetch_url(next_url, allow_insecure_http)
                    current = next_url
                    continue
                if response.status == 304:
                    return FetchResult(b"", 304, "",
                                       _bounded_header(response.getheader("ETag"), 1024),
                                       _bounded_header(response.getheader("Last-Modified"), 128))
                if response.status != 200:
                    raise ProxySourceError("source_fetch_denied") from None
                content_type = _response_content_type(response)
                if content_type not in _ALLOWED_FETCH_TYPES:
                    raise ProxySourceError("source_fetch_denied") from None
                return FetchResult(
                    _read_response_body(response, MAX_SOURCE_BYTES), 200, content_type,
                    _bounded_header(response.getheader("ETag"), 1024),
                    _bounded_header(response.getheader("Last-Modified"), 128),
                )
            finally:
                response.close()
        raise ProxySourceError("source_fetch_denied") from None


def fetch_pinned_url(url: str, *, headers: Optional[Mapping[str, str]] = None,
                     etag: str = "", last_modified: str = "",
                     allow_insecure_http: bool = False) -> FetchResult:
    return PinnedHTTPSFetcher()(url, headers=headers, etag=etag,
                                last_modified=last_modified,
                                allow_insecure_http=allow_insecure_http)

def fetch_url_cache_key(url: str, *,
                        allow_insecure_http: bool = False) -> str:
    """Return the only safe persistent cache key for a source URL."""
    _validate_fetch_url(url, allow_insecure_http)
    try:
        encoded = url.encode("utf-8")
    except UnicodeEncodeError:
        raise ProxySourceError("source_fetch_denied") from None
    return hashlib.sha256(encoded).hexdigest()


# ------------------------------- parsing --------------------------------


def _source_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ProxySourceError("source_invalid") from None
    elif isinstance(value, (dict, list)):
        try:
            raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise ProxySourceError("source_invalid") from None
    else:
        raise ProxySourceError("source_invalid") from None
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise ProxySourceError("source_invalid") from None
    return raw


def _text(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProxySourceError("source_invalid") from None
    if "\x00" in value:
        raise ProxySourceError("source_invalid") from None
    return value


def _strict_unquote(value: str) -> str:
    if not isinstance(value, str) or len(value) > 8192:
        raise ProxySourceError("source_invalid") from None
    index = 0
    while index < len(value):
        if value[index] == "%":
            if index + 3 > len(value) or not _HEX_PAIR.fullmatch(value[index:index + 3]):
                raise ProxySourceError("source_invalid") from None
            index += 3
        else:
            index += 1
    try:
        return unquote_to_bytes(value).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        raise ProxySourceError("source_invalid") from None


def _query(value: str, allowed: Iterable[str]) -> Dict[str, str]:
    if len(value) > 16384:
        raise ProxySourceError("source_invalid") from None
    index = 0
    while index < len(value):
        if value[index] == "%":
            if index + 3 > len(value) or not _HEX_PAIR.fullmatch(value[index:index + 3]):
                raise ProxySourceError("source_invalid") from None
            index += 3
        else:
            index += 1
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=64)
    except ValueError:
        if not value:
            return {}
        raise ProxySourceError("source_invalid") from None
    result: Dict[str, str] = {}
    allowed_set = set(allowed)
    for key, item in pairs:
        if (key not in allowed_set or key in result or _CONTROL.search(key)
                or _CONTROL.search(item)):
            raise ProxySourceError("source_invalid") from None
        result[key] = item
    return result


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in ("1", "true", "yes"):
            return True
        if lowered in ("0", "false", "no", ""):
            return False
    raise ProxySourceError("source_invalid") from None


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ProxySourceError("source_invalid") from None
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ProxySourceError("source_invalid") from None
    if not isinstance(value, int) and str(number) != str(value).strip():
        raise ProxySourceError("source_invalid") from None
    if number < minimum or number > maximum:
        raise ProxySourceError("source_invalid") from None
    return number


def _port(value: Any) -> int:
    return _integer(value, 1, 65535)


def _string(value: Any, maximum: int = 4096, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > maximum or _CONTROL.search(value):
        raise ProxySourceError("source_invalid") from None
    if nonempty and not value:
        raise ProxySourceError("source_invalid") from None
    return value


def _name(value: Any, fallback: str) -> str:
    candidate = fallback if value in (None, "") else _string(value, MAX_NODE_NAME)
    candidate = unicodedata.normalize("NFC", candidate.strip())
    if not candidate or len(candidate) > MAX_NODE_NAME or _CONTROL.search(candidate):
        raise ProxySourceError("source_invalid") from None
    if candidate.upper() in {"GLOBAL", "DIRECT", "REJECT", "REJECT-DROP", "PASS",
                             "COMPATIBLE", "XENOID-AUTO"}:
        raise ProxySourceError("source_invalid") from None
    return candidate


def _b64(value: str, *, whitespace: bool = False) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProxySourceError("source_invalid") from None
    encoded = "".join(value.split()) if whitespace else value
    if len(encoded) > MAX_SOURCE_BYTES * 2 or (not whitespace and any(c.isspace() for c in encoded)):
        raise ProxySourceError("source_invalid") from None
    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", encoded):
        raise ProxySourceError("source_invalid") from None
    if "=" in encoded[:-2] or len(encoded) % 4 == 1:
        raise ProxySourceError("source_invalid") from None
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        return base64.b64decode(padded.replace("-", "+").replace("_", "/"),
                                validate=True)
    except (binascii.Error, ValueError):
        raise ProxySourceError("source_invalid") from None


def _uri_parts(uri: str, schemes: Sequence[str]) -> Tuple[Any, str]:
    if not isinstance(uri, str) or len(uri) > 65536 or _CONTROL.search(uri):
        raise ProxySourceError("source_invalid") from None
    try:
        parts = urlsplit(uri)
    except (ValueError, UnicodeError):
        raise ProxySourceError("source_invalid") from None
    if parts.scheme.lower() not in schemes or not parts.hostname:
        raise ProxySourceError("source_invalid") from None
    return parts, (_strict_unquote(parts.fragment) if parts.fragment else "")


_SS_CIPHERS = frozenset({
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
    "aes-192-ctr", "aes-256-ctr", "aes-128-gcm", "aes-192-gcm",
    "aes-256-gcm", "camellia-128-cfb", "camellia-192-cfb",
    "camellia-256-cfb", "chacha20", "chacha20-ietf",
    "chacha20-ietf-poly1305", "xchacha20", "xchacha20-ietf-poly1305",
    "rc4-md5", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none",
})
_SSR_PROTOCOLS = frozenset({
    "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b",
})
_SSR_OBFS = frozenset({
    "plain", "http_simple", "http_post", "random_head",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth",
})


def _network_options(network: str, query: Mapping[str, str]) -> Dict[str, Any]:
    if network in ("", "tcp"):
        return {}
    if network == "ws":
        options: Dict[str, Any] = {"path": _string(query.get("path", "/"), 2048)}
        if query.get("host"):
            options["headers"] = {"Host": _string(query["host"], 253)}
        return {"network": "ws", "ws-opts": options}
    if network == "grpc":
        service = query.get("serviceName", query.get("service-name", ""))
        return {"network": "grpc",
                "grpc-opts": {"grpc-service-name": _string(service, 256)}}
    if network == "http":
        result: Dict[str, Any] = {
            "network": "http", "http-opts": {"path": [_string(query.get("path", "/"), 2048)]}}
        if query.get("host"):
            result["http-opts"]["headers"] = {"Host": [_string(query["host"], 253)]}
        return result
    raise ProxySourceError("source_invalid") from None


def _endpoint(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    parts, fragment = _uri_parts(uri, ("http", "https", "socks5", "socks5h"))
    try:
        port = parts.port
    except ValueError:
        raise ProxySourceError("source_invalid") from None
    scheme = parts.scheme.lower()
    if scheme in ("http", "https") and udp_allowed:
        raise ProxySourceError("source_invalid") from None
    if port is None:
        port = (443 if scheme == "https" else 80)
        if scheme.startswith("socks"):
            port = 1080
    if parts.path not in ("", "/") or parts.query:
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(fragment, "node-{:03d}".format(index)),
        "type": "http" if scheme in ("http", "https") else "socks5",
        "server": _node_host(parts.hostname), "port": _port(port),
    }
    if parts.username is not None:
        proxy["username"] = _strict_unquote(parts.username)
    if parts.password is not None:
        if parts.username is None:
            raise ProxySourceError("source_invalid") from None
        proxy["password"] = _strict_unquote(parts.password)
    if scheme == "https":
        proxy["tls"] = True
    if scheme.startswith("socks"):
        proxy["udp"] = bool(udp_allowed)
    return proxy


def _ss(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    parts, fragment = _uri_parts(uri, ("ss",))
    query = _query(parts.query, ("plugin",)) if parts.query else {}
    try:
        port = parts.port
    except ValueError:
        raise ProxySourceError("source_invalid") from None
    username, password, host = parts.username, parts.password, parts.hostname
    if username is not None and port is not None:
        try:
            credentials = _b64(username).decode("utf-8")
        except UnicodeDecodeError:
            raise ProxySourceError("source_invalid") from None
        if ":" not in credentials or password is not None:
            raise ProxySourceError("source_invalid") from None
        cipher, secret = credentials.split(":", 1)
    else:
        payload = uri[5:].split("#", 1)[0].split("?", 1)[0]
        try:
            decoded = _b64(payload).decode("utf-8")
        except UnicodeDecodeError:
            raise ProxySourceError("source_invalid") from None
        match = re.fullmatch(r"([^:]+):([^@]+)@(.+):(\d+)", decoded)
        if not match:
            raise ProxySourceError("source_invalid") from None
        cipher, secret, host, port_text = match.groups()
        port = _port(port_text)
    if cipher not in _SS_CIPHERS or not secret:
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(fragment, "node-{:03d}".format(index)), "type": "ss",
        "server": _node_host(host), "port": _port(port), "cipher": cipher,
        "password": _string(secret), "udp": bool(udp_allowed),
    }
    if query:
        segments = query["plugin"].split(";")
        if segments[0] not in ("obfs-local", "v2ray-plugin"):
            raise ProxySourceError("source_invalid") from None
        proxy["plugin"] = segments[0]
        options: Dict[str, Any] = {}
        for segment in segments[1:]:
            if not segment or "=" not in segment:
                raise ProxySourceError("source_invalid") from None
            key, item = segment.split("=", 1)
            if key not in {"obfs", "obfs-host", "mode", "host", "path", "tls"} or key in options:
                raise ProxySourceError("source_invalid") from None
            options[key] = _string(item, 2048, nonempty=False)
        proxy["plugin-opts"] = options
    return proxy


def _ssr(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    if not uri.startswith("ssr://"):
        raise ProxySourceError("source_invalid") from None
    try:
        decoded = _b64(uri[6:]).decode("utf-8")
    except UnicodeDecodeError:
        raise ProxySourceError("source_invalid") from None
    main, separator, query_text = decoded.partition("/?")
    fields = main.split(":")
    if len(fields) != 6:
        raise ProxySourceError("source_invalid") from None
    host, port_text, protocol, cipher, obfs, encoded_password = fields
    if protocol not in {"origin", "auth_sha1_v4", "auth_aes128_md5",
                         "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"}:
        raise ProxySourceError("source_invalid") from None
    if obfs not in {"plain", "http_simple", "http_post", "random_head",
                     "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}:
        raise ProxySourceError("source_invalid") from None
    if cipher not in _SS_CIPHERS:
        raise ProxySourceError("source_invalid") from None
    params = _query(query_text, ("remarks", "protoparam", "obfsparam")) if separator else {}
    try:
        password = _b64(encoded_password).decode("utf-8")
        remarks = _b64(params["remarks"]).decode("utf-8") if params.get("remarks") else ""
        proto_param = _b64(params["protoparam"]).decode("utf-8") if params.get("protoparam") else ""
        obfs_param = _b64(params["obfsparam"]).decode("utf-8") if params.get("obfsparam") else ""
    except UnicodeDecodeError:
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(remarks, "node-{:03d}".format(index)), "type": "ssr",
        "server": _node_host(host), "port": _port(port_text), "cipher": cipher,
        "password": _string(password), "protocol": protocol, "obfs": obfs,
        "udp": bool(udp_allowed),
    }
    if proto_param:
        proxy["protocol-param"] = _string(proto_param)
    if obfs_param:
        proxy["obfs-param"] = _string(obfs_param)
    return proxy


def _standard_uri(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    parts, fragment = _uri_parts(uri, (
        "trojan", "vless", "hysteria", "hysteria2", "hy2", "tuic", "anytls"))
    scheme = parts.scheme.lower()
    allowed = {
        "trojan": {"security", "sni", "peer", "allowInsecure", "insecure", "alpn", "type", "path", "host", "serviceName", "service-name", "fp", "udp"},
        "vless": {"encryption", "security", "sni", "flow", "fp", "pbk", "sid", "spx", "type", "path", "host", "serviceName", "service-name", "alpn", "allowInsecure", "insecure", "packetEncoding"},
        "hysteria": {"auth", "auth_str", "peer", "sni", "insecure", "allowInsecure", "upmbps", "downmbps", "up", "down", "obfs", "obfsParam", "protocol", "alpn"},
        "hysteria2": {"sni", "insecure", "allowInsecure", "obfs", "obfs-password", "obfsPassword", "pinSHA256", "alpn", "up", "down"},
        "hy2": {"sni", "insecure", "allowInsecure", "obfs", "obfs-password", "obfsPassword", "pinSHA256", "alpn", "up", "down"},
        "tuic": {"sni", "alpn", "congestion_control", "congestion-controller", "udp_relay_mode", "udp-relay-mode", "allow_insecure", "allowInsecure", "disable_sni", "reduce_rtt"},
        "anytls": {"sni", "alpn", "insecure", "allowInsecure", "fp", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"},
    }[scheme]
    params = _query(parts.query, allowed) if parts.query else {}
    try:
        port = _port(parts.port)
    except ValueError:
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(fragment, "node-{:03d}".format(index)),
        "server": _node_host(parts.hostname), "port": port, "udp": bool(udp_allowed),
    }
    insecure = params.get("insecure", params.get("allowInsecure",
                                                  params.get("allow_insecure", "")))
    if scheme == "trojan":
        if parts.username is None or parts.password is not None:
            raise ProxySourceError("source_invalid") from None
        proxy.update({"type": "trojan", "password": _strict_unquote(parts.username)})
        if params.get("security", "tls") not in ("tls", "none"):
            raise ProxySourceError("source_invalid") from None
        if params.get("sni", params.get("peer", "")):
            proxy["sni"] = _string(params.get("sni", params.get("peer", "")), 253)
        proxy.update(_network_options(params.get("type", "tcp"), params))
    elif scheme == "vless":
        if parts.username is None or parts.password is not None:
            raise ProxySourceError("source_invalid") from None
        try:
            identifier = str(uuid.UUID(_strict_unquote(parts.username)))
        except ValueError:
            raise ProxySourceError("source_invalid") from None
        if params.get("encryption", "none") != "none":
            raise ProxySourceError("source_invalid") from None
        security = params.get("security", "none")
        if security not in ("none", "tls", "reality"):
            raise ProxySourceError("source_invalid") from None
        proxy.update({"type": "vless", "uuid": identifier,
                      "tls": security in ("tls", "reality")})
        if params.get("sni"):
            proxy["servername"] = _string(params["sni"], 253)
        if params.get("flow"):
            if params["flow"] not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                raise ProxySourceError("source_invalid") from None
            proxy["flow"] = params["flow"]
        if security == "reality":
            if not params.get("pbk"):
                raise ProxySourceError("source_invalid") from None
            reality: Dict[str, Any] = {"public-key": _string(params["pbk"], 256)}
            if params.get("sid"):
                reality["short-id"] = _string(params["sid"], 32)
            proxy["reality-opts"] = reality
        proxy.update(_network_options(params.get("type", "tcp"), params))
        if params.get("packetEncoding"):
            if params["packetEncoding"] not in ("xudp", "packetaddr"):
                raise ProxySourceError("source_invalid") from None
            proxy["packet-encoding"] = params["packetEncoding"]
    elif scheme == "hysteria":
        if parts.password is not None:
            raise ProxySourceError("source_invalid") from None
        proxy["type"] = "hysteria"
        userinfo_auth = (_strict_unquote(parts.username)
                         if parts.username is not None else "")
        auth = params.get("auth", params.get("auth_str", userinfo_auth))
        if userinfo_auth and params.get("auth", params.get("auth_str", "")):
            raise ProxySourceError("source_invalid") from None
        if auth:
            proxy["auth-str"] = _string(auth)
        if params.get("sni", params.get("peer", "")):
            proxy["sni"] = _string(params.get("sni", params.get("peer", "")), 253)
        if params.get("upmbps", params.get("up", "")):
            proxy["up"] = _string(params.get("upmbps", params.get("up", "")), 32)
        if params.get("downmbps", params.get("down", "")):
            proxy["down"] = _string(params.get("downmbps", params.get("down", "")), 32)
        if params.get("obfs"):
            proxy["obfs"] = _string(params["obfs"], 256)
        if params.get("obfsParam"):
            proxy["obfs-param"] = _string(params["obfsParam"], 256)
        if params.get("protocol"):
            if params["protocol"] not in ("udp", "wechat-video", "faketcp"):
                raise ProxySourceError("source_invalid") from None
            proxy["protocol"] = params["protocol"]
    elif scheme in ("hysteria2", "hy2"):
        if parts.username is None or parts.password is not None:
            raise ProxySourceError("source_invalid") from None
        proxy.update({"type": "hysteria2", "password": _strict_unquote(parts.username)})
        if params.get("sni"):
            proxy["sni"] = _string(params["sni"], 253)
        if params.get("obfs"):
            if params["obfs"] != "salamander":
                raise ProxySourceError("source_invalid") from None
            proxy["obfs"] = "salamander"
            proxy["obfs-password"] = _string(
                params.get("obfs-password", params.get("obfsPassword", "")))
        for field in ("up", "down"):
            if params.get(field):
                proxy[field] = _string(params[field], 32)
    elif scheme == "tuic":
        if parts.username is None or parts.password is None:
            raise ProxySourceError("source_invalid") from None
        try:
            identifier = str(uuid.UUID(_strict_unquote(parts.username)))
        except ValueError:
            raise ProxySourceError("source_invalid") from None
        proxy.update({"type": "tuic", "uuid": identifier,
                      "password": _strict_unquote(parts.password)})
        if params.get("sni"):
            proxy["sni"] = _string(params["sni"], 253)
        congestion = params.get("congestion_control",
                                params.get("congestion-controller", "bbr"))
        relay = params.get("udp_relay_mode", params.get("udp-relay-mode", "native"))
        if congestion not in ("cubic", "new_reno", "bbr") or relay not in ("native", "quic"):
            raise ProxySourceError("source_invalid") from None
        proxy["congestion-controller"] = congestion
        proxy["udp-relay-mode"] = relay
        for source_field, target in (("disable_sni", "disable-sni"),
                                     ("reduce_rtt", "reduce-rtt")):
            if source_field in params:
                proxy[target] = _bool(params[source_field])
    else:
        if parts.username is None or parts.password is not None:
            raise ProxySourceError("source_invalid") from None
        proxy.update({"type": "anytls", "password": _strict_unquote(parts.username)})
        if params.get("sni"):
            proxy["sni"] = _string(params["sni"], 253)
        if params.get("fp"):
            proxy["client-fingerprint"] = _string(params["fp"], 64)
        for field in ("idle-session-check-interval", "idle-session-timeout",
                      "min-idle-session"):
            if field in params:
                proxy[field] = _integer(params[field], 1, 86400)
    if insecure:
        proxy["skip-cert-verify"] = _bool(insecure)
    if params.get("alpn"):
        alpn = [_string(item, 32) for item in params["alpn"].split(",") if item]
        if not alpn or len(alpn) > 8:
            raise ProxySourceError("source_invalid") from None
        proxy["alpn"] = alpn
    if params.get("fp") and "client-fingerprint" not in proxy:
        proxy["client-fingerprint"] = _string(params["fp"], 64)
    return proxy


def _reject_json_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise ProxySourceError("source_invalid") from None
        result[key] = value
    return result


def _vmess(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    if not uri.startswith("vmess://") or "#" in uri or "?" in uri:
        raise ProxySourceError("source_invalid") from None
    try:
        document = json.loads(_b64(uri[8:]).decode("utf-8"),
                              object_pairs_hook=_reject_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProxySourceError("source_invalid") from None
    if not isinstance(document, dict):
        raise ProxySourceError("source_invalid") from None
    allowed = {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type",
               "host", "path", "tls", "sni", "alpn", "fp"}
    if set(document) - allowed:
        raise ProxySourceError("source_invalid") from None
    try:
        identifier = str(uuid.UUID(_string(document.get("id"), 64)))
    except ValueError:
        raise ProxySourceError("source_invalid") from None
    cipher = document.get("scy", "auto")
    if cipher not in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"):
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(document.get("ps"), "node-{:03d}".format(index)),
        "type": "vmess", "server": _node_host(document.get("add")),
        "port": _port(document.get("port")), "uuid": identifier,
        "alterId": _integer(document.get("aid", 0), 0, 65535), "cipher": cipher,
        "udp": bool(udp_allowed),
    }
    tls = str(document.get("tls", "")).lower()
    if tls not in ("", "none", "tls"):
        raise ProxySourceError("source_invalid") from None
    if tls == "tls":
        proxy["tls"] = True
    if document.get("sni"):
        proxy["servername"] = _string(document["sni"], 253)
    proxy.update(_network_options(str(document.get("net", "tcp")), {
        "path": str(document.get("path", "")), "host": str(document.get("host", "")),
        "serviceName": str(document.get("path", "")),
    }))
    if document.get("alpn"):
        proxy["alpn"] = [_string(item, 32) for item in str(document["alpn"]).split(",") if item]
    if document.get("fp"):
        proxy["client-fingerprint"] = _string(document["fp"], 64)
    return proxy


def _mieru(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    parts, fragment = _uri_parts(uri, ("mierus",))
    try:
        explicit_port = parts.port
    except ValueError:
        raise ProxySourceError("source_invalid") from None
    if explicit_port is not None or parts.path not in ("", "/"):
        raise ProxySourceError("source_invalid") from None
    params = _query(parts.query, (
        "profile", "mtu", "multiplexing", "handshake-mode",
        "traffic-pattern", "port", "protocol",
    ))
    # A sharing link can describe multiple port/protocol pairs. Xenoid's
    # deterministic one-line/one-node contract accepts the common single-pair
    # form and rejects ambiguous multi-value links in _query.
    if "port" not in params or "-" in params["port"]:
        raise ProxySourceError("source_invalid") from None
    transport = params.get("protocol", "TCP").upper()
    if transport not in ("TCP", "UDP"):
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(fragment or params.get("profile"), "node-{:03d}".format(index)),
        "type": "mieru",
        "server": _node_host(parts.hostname),
        "port": _port(params["port"]),
        "transport": transport,
        "username": _strict_unquote(parts.username),
        "password": _strict_unquote(parts.password),
        "udp": bool(udp_allowed),
    }
    if not proxy["username"] or not proxy["password"]:
        raise ProxySourceError("source_invalid") from None
    if "mtu" in params:
        proxy["mtu"] = _integer(params["mtu"], 1280, 65535)
    if "multiplexing" in params:
        if params["multiplexing"] not in {
            "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE",
            "MULTIPLEXING_HIGH",
        }:
            raise ProxySourceError("source_invalid") from None
        proxy["multiplexing"] = params["multiplexing"]
    if "handshake-mode" in params:
        if params["handshake-mode"] not in {
            "HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT",
        }:
            raise ProxySourceError("source_invalid") from None
        proxy["handshake-mode"] = params["handshake-mode"]
    if "traffic-pattern" in params:
        proxy["traffic-pattern"] = _string(
            params["traffic-pattern"], 4096, nonempty=False)
    return proxy


def _parse_uri(uri: str, index: int, udp_allowed: bool) -> Dict[str, Any]:
    scheme = uri.partition(":")[0].lower()
    if scheme in ("http", "https", "socks5", "socks5h"):
        return _endpoint(uri, index, udp_allowed)
    if scheme == "ss":
        return _ss(uri, index, udp_allowed)
    if scheme == "ssr":
        return _ssr(uri, index, udp_allowed)
    if scheme == "vmess":
        return _vmess(uri, index, udp_allowed)
    if scheme == "mierus":
        return _mieru(uri, index, udp_allowed)
    if scheme in ("trojan", "vless", "hysteria", "hysteria2", "hy2", "tuic", "anytls"):
        return _standard_uri(uri, index, udp_allowed)
    raise ProxySourceError("source_invalid") from None


def _validate_tree(value: Any, depth: int = 0,
                   counter: Optional[List[int]] = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_YAML_NODES or depth > MAX_DEPTH:
        raise ProxySourceError("source_invalid") from None
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, str) and len(value) > MAX_SOURCE_BYTES:
            raise ProxySourceError("source_invalid") from None
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ProxySourceError("source_invalid") from None
        return
    if isinstance(value, list):
        for item in value:
            _validate_tree(item, depth + 1, counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProxySourceError("source_invalid") from None
            _validate_tree(item, depth + 1, counter)
        return
    raise ProxySourceError("source_invalid") from None


def _yaml_document(text: str) -> Any:
    try:
        import yaml
    except ImportError:
        raise ProxySourceError("source_dependency_missing") from None

    class StrictLoader(yaml.SafeLoader):
        node_count = 0
        compose_depth = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise ProxySourceError("source_invalid") from None
            event = self.peek_event()
            if (getattr(event, "tag", None) is not None
                    or getattr(event, "anchor", None) is not None):
                raise ProxySourceError("source_invalid") from None
            self.node_count += 1
            if self.node_count > MAX_YAML_NODES:
                raise ProxySourceError("source_invalid") from None
            self.compose_depth += 1
            if self.compose_depth > MAX_DEPTH:
                raise ProxySourceError("source_invalid") from None
            try:
                return super().compose_node(parent, index)
            finally:
                self.compose_depth -= 1

        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            if not isinstance(node, yaml.MappingNode):
                raise ProxySourceError("source_invalid") from None
            result: Dict[str, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in result:
                    raise ProxySourceError("source_invalid") from None
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        documents = list(yaml.load_all(text, Loader=StrictLoader))
    except ProxySourceError:
        raise
    except Exception:
        raise ProxySourceError("source_invalid") from None
    if len(documents) != 1:
        raise ProxySourceError("source_invalid") from None
    _validate_tree(documents[0])
    return documents[0]


def _structured(raw: bytes) -> Any:
    text = _text(raw)
    try:
        document = json.loads(text, object_pairs_hook=_reject_json_pairs)
    except ProxySourceError:
        raise
    except json.JSONDecodeError:
        return _yaml_document(text)
    _validate_tree(document)
    return document


_COMMON_PROXY_KEYS = {"name", "type", "server", "port", "udp"}
_PROXY_KEYS: Dict[str, set] = {
    "http": _COMMON_PROXY_KEYS | {"username", "password", "tls", "sni", "skip-cert-verify", "fingerprint", "alpn"},
    "socks5": _COMMON_PROXY_KEYS | {"username", "password", "tls", "sni", "skip-cert-verify", "fingerprint"},
    "ss": _COMMON_PROXY_KEYS | {"cipher", "password", "plugin", "plugin-opts", "udp-over-tcp"},
    "ssr": _COMMON_PROXY_KEYS | {"cipher", "password", "protocol", "protocol-param", "obfs", "obfs-param"},
    "trojan": _COMMON_PROXY_KEYS | {"password", "sni", "alpn", "skip-cert-verify", "network", "ws-opts", "grpc-opts", "client-fingerprint"},
    "vmess": _COMMON_PROXY_KEYS | {"uuid", "alterId", "cipher", "tls", "servername", "server-name", "skip-cert-verify", "network", "ws-opts", "grpc-opts", "http-opts", "alpn", "client-fingerprint", "packet-encoding", "global-padding", "authenticated-length"},
    "vless": _COMMON_PROXY_KEYS | {"uuid", "tls", "servername", "server-name", "flow", "skip-cert-verify", "network", "ws-opts", "grpc-opts", "reality-opts", "alpn", "client-fingerprint", "packet-encoding"},
    "hysteria": _COMMON_PROXY_KEYS | {"auth-str", "auth", "obfs", "protocol", "up", "down", "sni", "alpn", "skip-cert-verify", "recv-window-conn", "recv-window", "disable-mtu-discovery", "fast-open"},
    "hysteria2": _COMMON_PROXY_KEYS | {"password", "obfs", "obfs-password", "sni", "fingerprint", "alpn", "skip-cert-verify", "up", "down", "fast-open", "ports", "hop-interval"},
    "tuic": _COMMON_PROXY_KEYS | {"uuid", "password", "token", "ip", "congestion-controller", "udp-relay-mode", "udp-over-stream", "reduce-rtt", "sni", "alpn", "disable-sni", "skip-cert-verify", "heartbeat-interval", "request-timeout", "max-open-streams"},
    "anytls": _COMMON_PROXY_KEYS | {"password", "client-fingerprint", "sni", "alpn", "skip-cert-verify", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"},
    "mieru": _COMMON_PROXY_KEYS | {"transport", "username", "password", "multiplexing", "handshake-mode", "traffic-pattern", "mtu"},
    "snell": _COMMON_PROXY_KEYS | {"psk", "version", "obfs-opts"},
}


def _copy_bool(proxy: Dict[str, Any], source: Mapping[str, Any], field: str) -> None:
    if field in source:
        proxy[field] = _bool(source[field])


def _copy_string(proxy: Dict[str, Any], source: Mapping[str, Any], field: str,
                 maximum: int = 4096) -> None:
    if field in source:
        proxy[field] = _string(source[field], maximum)


def _normalize_transport(source: Mapping[str, Any], proxy: Dict[str, Any]) -> None:
    network = source.get("network")
    if network is None:
        return
    if network not in ("tcp", "ws", "grpc", "http"):
        raise ProxySourceError("source_invalid") from None
    if network == "tcp":
        return
    key = {"ws": "ws-opts", "grpc": "grpc-opts", "http": "http-opts"}[network]
    options = source.get(key)
    allowed = {
        "ws-opts": {"path", "headers", "max-early-data", "early-data-header-name", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"},
        "grpc-opts": {"grpc-service-name", "grpc-mode", "idle-timeout", "health-check-timeout", "permit-without-stream", "initial-windows-size"},
        "http-opts": {"method", "path", "headers"},
    }[key]
    if not isinstance(options, dict) or len(options) > 16 or set(options) - allowed:
        raise ProxySourceError("source_invalid") from None
    _validate_tree(options)
    proxy["network"] = network
    proxy[key] = json.loads(json.dumps(options, ensure_ascii=False,
                                       separators=(",", ":")))


def _normalize_clash_proxy(source: Any, index: int,
                           udp_allowed: bool) -> Dict[str, Any]:
    if not isinstance(source, dict) or not isinstance(source.get("type"), str):
        raise ProxySourceError("source_invalid") from None
    kind = source["type"].lower()
    if kind not in _PROXY_KEYS or set(source) - _PROXY_KEYS[kind]:
        raise ProxySourceError("source_invalid") from None
    proxy: Dict[str, Any] = {
        "name": _name(source.get("name"), "node-{:03d}".format(index)),
        "type": kind, "server": _node_host(source.get("server")),
        "port": _port(source.get("port")),
    }
    requested_udp = _bool(source["udp"]) if "udp" in source else True
    if kind == "http":
        if "udp" in source and requested_udp:
            raise ProxySourceError("source_invalid") from None
    else:
        proxy["udp"] = bool(udp_allowed and requested_udp)

    if kind in ("http", "socks5"):
        for field in ("username", "password", "sni", "fingerprint"):
            _copy_string(proxy, source, field, 512)
        for field in ("tls", "skip-cert-verify"):
            _copy_bool(proxy, source, field)
    elif kind == "ss":
        if source.get("cipher") not in _SS_CIPHERS:
            raise ProxySourceError("source_invalid") from None
        proxy["cipher"] = source["cipher"]
        _copy_string(proxy, source, "password")
        if "password" not in proxy:
            raise ProxySourceError("source_invalid") from None
        if "plugin" in source:
            plugin = source["plugin"]
            option_fields = {
                "obfs": {"mode", "host"},
                "obfs-local": {"mode", "host"},
                "v2ray-plugin": {
                    "mode", "tls", "host", "path", "mux",
                    "headers", "skip-cert-verify",
                },
                "shadow-tls": {"host", "password", "version", "strict"},
                "restls": {"host", "version-hint", "restls-script"},
            }
            options = source.get("plugin-opts", {})
            if (plugin not in option_fields or not isinstance(options, dict)
                    or set(options) - option_fields[plugin]):
                raise ProxySourceError("source_invalid") from None
            normalized_options: Dict[str, Any] = {}
            for option, value in options.items():
                if option in {"tls", "mux", "skip-cert-verify", "strict"}:
                    normalized_options[option] = _bool(value)
                else:
                    normalized_options[option] = _string(value, 4096)
            proxy["plugin"] = plugin
            proxy["plugin-opts"] = normalized_options
        _copy_bool(proxy, source, "udp-over-tcp")
    elif kind == "ssr":
        if source.get("cipher") not in _SS_CIPHERS:
            raise ProxySourceError("source_invalid") from None
        for field in ("cipher", "password", "protocol", "protocol-param", "obfs", "obfs-param"):
            _copy_string(proxy, source, field)
        if not all(field in proxy for field in ("password", "protocol", "obfs")):
            raise ProxySourceError("source_invalid") from None
        if proxy["protocol"] not in _SSR_PROTOCOLS or proxy["obfs"] not in _SSR_OBFS:
            raise ProxySourceError("source_invalid") from None
    elif kind == "mieru":
        for field in ("username", "password"):
            _copy_string(proxy, source, field, 512)
        if not all(field in proxy for field in ("username", "password")):
            raise ProxySourceError("source_invalid") from None
        transport = source.get("transport", "TCP")
        if transport not in ("TCP", "UDP"):
            raise ProxySourceError("source_invalid") from None
        proxy["transport"] = transport
        if "multiplexing" in source:
            multiplexing = _string(source["multiplexing"], 32)
            if multiplexing not in {
                "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE",
                "MULTIPLEXING_HIGH",
            }:
                raise ProxySourceError("source_invalid") from None
            proxy["multiplexing"] = multiplexing
        if "handshake-mode" in source:
            handshake = _string(source["handshake-mode"], 32)
            if handshake not in {"HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"}:
                raise ProxySourceError("source_invalid") from None
            proxy["handshake-mode"] = handshake
        if "traffic-pattern" in source:
            proxy["traffic-pattern"] = _string(
                source["traffic-pattern"], 4096, nonempty=False)
        if "mtu" in source:
            proxy["mtu"] = _integer(source["mtu"], 1280, 65535)
    elif kind in ("trojan", "anytls"):
        _copy_string(proxy, source, "password")
        if "password" not in proxy:
            raise ProxySourceError("source_invalid") from None
        for field in ("sni", "client-fingerprint"):
            _copy_string(proxy, source, field, 253)
        _copy_bool(proxy, source, "skip-cert-verify")
        if kind == "trojan":
            _normalize_transport(source, proxy)
    elif kind in ("vmess", "vless"):
        try:
            proxy["uuid"] = str(uuid.UUID(_string(source.get("uuid"), 64)))
        except ValueError:
            raise ProxySourceError("source_invalid") from None
        if kind == "vmess":
            proxy["alterId"] = _integer(source.get("alterId", 0), 0, 65535)
            cipher = source.get("cipher", "auto")
            if cipher not in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"):
                raise ProxySourceError("source_invalid") from None
            proxy["cipher"] = cipher
        for source_field, target in (("servername", "servername"),
                                     ("server-name", "servername"), ("flow", "flow"),
                                     ("client-fingerprint", "client-fingerprint"),
                                     ("packet-encoding", "packet-encoding")):
            if source_field in source:
                if target in proxy:
                    raise ProxySourceError("source_invalid") from None
                proxy[target] = _string(source[source_field], 253)
        if "flow" in proxy and proxy["flow"] not in (
                "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            raise ProxySourceError("source_invalid") from None
        if "packet-encoding" in proxy and proxy["packet-encoding"] not in (
                "xudp", "packetaddr"):
            raise ProxySourceError("source_invalid") from None
        for field in ("tls", "skip-cert-verify", "global-padding", "authenticated-length"):
            _copy_bool(proxy, source, field)
        if "reality-opts" in source:
            reality = source["reality-opts"]
            if (not isinstance(reality, dict)
                    or set(reality) - {"public-key", "short-id", "support-x25519mlkem768"}
                    or "public-key" not in reality):
                raise ProxySourceError("source_invalid") from None
            normalized_reality: Dict[str, Any] = {
                "public-key": _string(reality["public-key"], 256)
            }
            if "short-id" in reality:
                normalized_reality["short-id"] = _string(reality["short-id"], 32)
            if "support-x25519mlkem768" in reality:
                normalized_reality["support-x25519mlkem768"] = _bool(
                    reality["support-x25519mlkem768"])
            proxy["reality-opts"] = normalized_reality
        _normalize_transport(source, proxy)
    elif kind in ("hysteria", "hysteria2"):
        for field in ("auth-str", "auth", "password", "obfs", "obfs-password",
                      "protocol", "up", "down", "sni", "fingerprint", "hop-interval", "ports"):
            _copy_string(proxy, source, field, 512)
        if kind == "hysteria2" and "password" not in proxy:
            raise ProxySourceError("source_invalid") from None
        if kind == "hysteria":
            if "protocol" in proxy and proxy["protocol"] not in (
                    "udp", "wechat-video", "faketcp"):
                raise ProxySourceError("source_invalid") from None
        elif "obfs" in proxy:
            if proxy["obfs"] != "salamander" or "obfs-password" not in proxy:
                raise ProxySourceError("source_invalid") from None
        for field in ("skip-cert-verify", "disable-mtu-discovery", "fast-open"):
            _copy_bool(proxy, source, field)
        for field in ("recv-window-conn", "recv-window"):
            if field in source:
                proxy[field] = _integer(source[field], 1, 1 << 31)
    elif kind == "tuic":
        if "uuid" in source:
            try:
                proxy["uuid"] = str(uuid.UUID(_string(source["uuid"], 64)))
            except ValueError:
                raise ProxySourceError("source_invalid") from None
        for field in ("password", "token", "ip", "sni", "congestion-controller",
                      "udp-relay-mode"):
            _copy_string(proxy, source, field, 512)
        if not (("uuid" in proxy and "password" in proxy) or "token" in proxy):
            raise ProxySourceError("source_invalid") from None
        if ("congestion-controller" in proxy
                and proxy["congestion-controller"] not in (
                    "cubic", "new_reno", "bbr")):
            raise ProxySourceError("source_invalid") from None
        if ("udp-relay-mode" in proxy
                and proxy["udp-relay-mode"] not in ("native", "quic")):
            raise ProxySourceError("source_invalid") from None
        for field in ("udp-over-stream", "reduce-rtt", "disable-sni", "skip-cert-verify"):
            _copy_bool(proxy, source, field)
        for field in ("heartbeat-interval", "request-timeout", "max-open-streams"):
            if field in source:
                proxy[field] = _integer(source[field], 1, 1 << 31)
    else:  # snell
        _copy_string(proxy, source, "psk")
        if "psk" not in proxy:
            raise ProxySourceError("source_invalid") from None
        proxy["version"] = _integer(source.get("version", 3), 1, 5)
        if udp_allowed and proxy["version"] < 3:
            raise ProxySourceError("source_invalid") from None
        if "obfs-opts" in source:
            options = source["obfs-opts"]
            if (not isinstance(options, dict) or set(options) - {"mode", "host"}
                    or options.get("mode") not in ("http", "tls")
                    or not options.get("host")):
                raise ProxySourceError("source_invalid") from None
            proxy["obfs-opts"] = {"mode": options["mode"],
                                  "host": _string(options["host"], 253)}
    if "alpn" in source:
        alpn = source["alpn"]
        if not isinstance(alpn, list) or not 1 <= len(alpn) <= 8:
            raise ProxySourceError("source_invalid") from None
        proxy["alpn"] = [_string(item, 32) for item in alpn]
    for field in ("idle-session-check-interval", "idle-session-timeout",
                  "min-idle-session"):
        if field in source:
            proxy[field] = _integer(source[field], 1, 86400)
    return proxy


_CLASH_TOP_LEVEL = {
    "proxies", "proxy-providers", "proxy-groups", "rules", "rule-providers",
    "sub-rules", "port", "socks-port", "redir-port", "tproxy-port", "mixed-port",
    "authentication", "allow-lan", "bind-address", "mode", "log-level", "ipv6",
    "external-controller", "external-controller-tls", "external-ui", "external-ui-url",
    "secret", "tun", "dns", "hosts", "profile", "sniffer", "geodata-mode",
    "geodata-loader", "geo-auto-update", "geo-update-interval", "geox-url",
    "global-client-fingerprint", "find-process-mode", "unified-delay",
    "tcp-concurrent", "keep-alive-interval", "keep-alive-idle", "interface-name",
    "routing-mark", "iptables", "listeners", "ntp", "cfw-bypass",
    "cfw-latency-timeout",
}


def _provider_body(result: Any) -> bytes:
    try:
        if isinstance(result, FetchResult):
            body = result.body
        elif isinstance(result, bytes):
            body = result
        elif isinstance(result, str):
            body = result.encode("utf-8")
        elif isinstance(result, dict) and "body" in result:
            value = result["body"]
            body = value if isinstance(value, bytes) else (
                value.encode("utf-8") if isinstance(value, str) else b"")
        else:
            body = b""
    except UnicodeEncodeError:
        raise ProxySourceError("source_fetch_denied") from None
    if not body or len(body) > MAX_SOURCE_BYTES:
        raise ProxySourceError("source_fetch_denied") from None
    return body


def _fetch_provider(fetcher: Callable[..., Any], url: str,
                    allow_insecure_http: bool,
                    headers: Optional[Mapping[str, str]] = None) -> bytes:
    _validate_fetch_url(url, allow_insecure_http)
    try:
        parameters = inspect.signature(fetcher).parameters
        variable_keywords = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values())
    except (TypeError, ValueError):
        parameters = {}
        variable_keywords = False
    kwargs: Dict[str, Any] = {}
    if "allow_insecure_http" in parameters or variable_keywords:
        kwargs["allow_insecure_http"] = allow_insecure_http
    if headers:
        if "headers" not in parameters and not variable_keywords:
            raise ProxySourceError("source_fetch_denied") from None
        kwargs["headers"] = dict(headers)
    try:
        result = fetcher(url, **kwargs)
    except ProxySourceError:
        raise
    except Exception:
        raise ProxySourceError("source_fetch_denied") from None
    return _provider_body(result)



def _validate_cfw_metadata(document: Mapping[str, Any]) -> None:
    if "cfw-bypass" in document:
        bypass = document["cfw-bypass"]
        if not isinstance(bypass, list) or len(bypass) > MAX_YAML_NODES:
            raise ProxySourceError("source_invalid") from None
        for item in bypass:
            _string(item, 2048)
    if "cfw-latency-timeout" in document:
        latency = document["cfw-latency-timeout"]
        if latency is None or isinstance(latency, bool):
            return
        if isinstance(latency, str):
            _string(latency, 128, nonempty=False)
            return
        if (type(latency) not in (int, float) or not math.isfinite(latency)
                or abs(latency) > 86400000):
            raise ProxySourceError("source_invalid") from None

def _clash_proxies(document: Any, udp_allowed: bool,
                   fetcher: Optional[Callable[..., Any]],
                   allow_insecure_http: bool) -> List[Dict[str, Any]]:
    if not isinstance(document, dict) or set(document) - _CLASH_TOP_LEVEL:
        raise ProxySourceError("source_invalid") from None
    _validate_cfw_metadata(document)
    direct = document.get("proxies", [])
    if not isinstance(direct, list):
        raise ProxySourceError("source_invalid") from None
    raw_proxies: List[Any] = list(direct)
    if len(raw_proxies) > MAX_NODES:
        raise ProxySourceError("source_invalid") from None
    providers = document.get("proxy-providers", {})
    if not isinstance(providers, dict) or len(providers) > MAX_NODES:
        raise ProxySourceError("source_invalid") from None
    provider_bytes = 0
    for provider_name in sorted(providers):
        provider = providers[provider_name]
        _name(provider_name, "provider")
        if not isinstance(provider, dict) or not isinstance(provider.get("type"), str):
            raise ProxySourceError("source_invalid") from None
        provider_type = provider["type"].lower()
        if provider_type == "inline":
            if set(provider) - {"type", "payload", "health-check", "override"}:
                raise ProxySourceError("source_invalid") from None
            payload = provider.get("payload")
            if not isinstance(payload, list):
                raise ProxySourceError("source_invalid") from None
            raw_proxies.extend(payload)
        elif provider_type == "http":
            if set(provider) - {
                "type", "url", "interval", "health-check", "override",
                "header", "headers"
            }:
                raise ProxySourceError("source_invalid") from None
            if fetcher is None or not isinstance(provider.get("url"), str):
                raise ProxySourceError("source_fetch_denied") from None
            interval = provider.get("interval")
            if (interval is not None
                    and (type(interval) is not int
                         or not 60 <= interval <= 31_536_000)):
                raise ProxySourceError("source_invalid") from None
            if "header" in provider and "headers" in provider:
                raise ProxySourceError("source_invalid") from None
            provider_headers: Dict[str, str] = {}
            header = provider.get("header", provider.get("headers"))
            if header is not None:
                if not isinstance(header, dict) or len(header) != 1:
                    raise ProxySourceError("source_invalid") from None
                for key, value in header.items():
                    if isinstance(value, list) and len(value) == 1:
                        value = value[0]
                    if (not isinstance(key, str) or key.lower() != "user-agent"
                            or not isinstance(value, str) or not value
                            or len(value) > 256 or _CONTROL.search(value)):
                        raise ProxySourceError("source_invalid") from None
                    provider_headers["User-Agent"] = value
            provider_body = _fetch_provider(
                fetcher, provider["url"], allow_insecure_http,
                provider_headers or None)
            provider_bytes += len(provider_body)
            if provider_bytes > MAX_SOURCE_BYTES:
                raise ProxySourceError("source_invalid") from None
            nested = _structured(provider_body)
            if (not isinstance(nested, dict) or set(nested) - {"proxies"}
                    or not isinstance(nested.get("proxies"), list)):
                raise ProxySourceError("source_invalid") from None
            raw_proxies.extend(nested["proxies"])
        else:
            raise ProxySourceError("source_invalid") from None
        if len(raw_proxies) > MAX_NODES:
            raise ProxySourceError("source_invalid") from None
    if not raw_proxies:
        raise ProxySourceError("provider_empty") from None
    return [_normalize_clash_proxy(item, index + 1, udp_allowed)
            for index, item in enumerate(raw_proxies)]


def _uri_proxies(text: str, udp_allowed: bool) -> List[Dict[str, Any]]:
    candidate = text.strip()
    if "://" not in candidate:
        try:
            candidate = _text(_b64(candidate, whitespace=True))
        except ProxySourceError:
            raise ProxySourceError("source_invalid") from None
    lines = [line.strip() for line in candidate.splitlines() if line.strip()]
    if not lines or len(lines) > MAX_NODES:
        raise ProxySourceError("source_invalid") from None
    return [_parse_uri(line, index + 1, udp_allowed)
            for index, line in enumerate(lines)]


def _final_config(proxies: List[Dict[str, Any]], selected_node: str,
                  udp_allowed: bool) -> Tuple[Dict[str, Any], Tuple[str, ...]]:
    if not proxies or len(proxies) > MAX_NODES:
        raise ProxySourceError("provider_empty") from None
    names: List[str] = []
    seen = set()
    for proxy in proxies:
        name = proxy["name"]
        if name in seen:
            raise ProxySourceError("source_invalid") from None
        seen.add(name)
        names.append(name)
    selected = _name(selected_node, "node") if selected_node else ""
    if selected and selected not in seen:
        raise ProxySourceError("selection_missing") from None
    if selected:
        ordered = [selected] + [name for name in names if name != selected] + ["XENOID-AUTO"]
    else:
        ordered = ["XENOID-AUTO"] + list(names)
    controller_payload = json.dumps(
        proxies, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    controller_secret = hashlib.sha256(
        b"xenoid-mihomo-controller/v1\x00" + controller_payload
    ).hexdigest()
    config: Dict[str, Any] = {
        "mode": "global", "log-level": "info", "allow-lan": True,
        "bind-address": "*", "find-process-mode": "off", "ipv6": True,
        "hosts": {},
        "listeners": [
            {"name": "xenoid-redir-v4", "type": "redir", "port": 7893, "listen": "0.0.0.0"},
            {"name": "xenoid-redir-v6", "type": "redir", "port": 7895, "listen": "::"},
            {"name": "xenoid-tproxy-v4", "type": "tproxy", "port": 7897, "listen": "0.0.0.0", "udp": bool(udp_allowed)},
            {"name": "xenoid-tproxy-v6", "type": "tproxy", "port": 7899, "listen": "::", "udp": bool(udp_allowed)},
        ],
        "external-controller": "127.0.0.1:9091",
        "secret": controller_secret,
        "tun": {"enable": False}, "iptables": {"enable": False},
        "profile": {"store-selected": False, "store-fake-ip": False},
        "geo-auto-update": False,
        "sniffer": {
            "enable": True,
            "force-dns-mapping": True,
            "parse-pure-ip": True,
            "override-destination": True,
            "sniff": {
                "HTTP": {"ports": [80, "8080-8880"]},
                "TLS": {"ports": [443, 8443]},
                "QUIC": {"ports": [443, 8443]},
            },
        },
        "dns": {
            "enable": True, "listen": "[::]:1053", "enhanced-mode": "redir-host",
            "respect-rules": True, "ipv6": True,
            "nameserver": [
                "https://8.8.8.8/dns-query#GLOBAL",
                "https://8.8.4.4/dns-query#GLOBAL",
            ],
            "proxy-server-nameserver": [
                "https://8.8.8.8/dns-query#DIRECT",
                "https://8.8.4.4/dns-query#DIRECT",
            ],
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": "XENOID-AUTO", "type": "url-test", "proxies": list(names),
             "url": "https://cp.cloudflare.com/generate_204", "interval": 300,
             "lazy": True},
            {"name": "GLOBAL", "type": "select", "proxies": ordered},
        ],
        "rules": ["MATCH,GLOBAL"],
    }
    canonical = json.dumps(config, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    return json.loads(canonical), tuple(names)


def compile_source(kind: str, value: Any, selected_node: str = "",
                   udp_allowed: bool = True, allow_insecure_http: bool = False,
                   fetcher: Optional[Callable[..., Any]] = None) -> CompiledSource:
    """Compile one complete candidate; any malformed member rejects it all."""
    if (kind not in ("endpoint", "uri_list", "clash")
            or not isinstance(udp_allowed, bool)
            or not isinstance(allow_insecure_http, bool)):
        raise ProxySourceError("source_invalid") from None
    raw = _source_bytes(value)
    if kind == "endpoint":
        proxies = [_endpoint(_text(raw).strip(), 1, udp_allowed)]
    elif kind == "uri_list":
        proxies = _uri_proxies(_text(raw), udp_allowed)
    else:
        document = value if isinstance(value, (dict, list)) else _structured(raw)
        _validate_tree(document)
        proxies = _clash_proxies(document, udp_allowed, fetcher,
                                  allow_insecure_http)
    config, names = _final_config(proxies, selected_node, udp_allowed)
    return CompiledSource(config, names, hashlib.sha256(raw).hexdigest())

def compile_fetched_subscription(
    body: Any,
    selected_node: str = "",
    udp_allowed: bool = True,
    allow_insecure_http: bool = False,
    fetcher: Optional[Callable[..., Any]] = None,
) -> CompiledSource:
    """Compile an already-fetched subscription body without fetching its URL."""
    raw = _source_bytes(body)
    if isinstance(body, (dict, list)):
        fetched_kind = "clash"
    else:
        text = _text(raw)
        stripped = text.lstrip()
        clash_marker = re.search(
            r"(?m)^[ \t]*(?:proxies|proxy-providers)[ \t]*:", text)
        fetched_kind = "clash" if stripped.startswith(("{", "[")) or clash_marker else "uri_list"
    return compile_source(
        fetched_kind,
        raw,
        selected_node=selected_node,
        udp_allowed=udp_allowed,
        allow_insecure_http=allow_insecure_http,
        fetcher=fetcher,
    )


__all__ = ["CompiledSource", "FetchResult", "PinnedHTTPSFetcher",
           "ProxySourceError", "compile_fetched_subscription", "compile_source",
           "fetch_pinned_url", "fetch_url_cache_key"]
