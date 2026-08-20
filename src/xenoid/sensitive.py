from __future__ import annotations

import re
from collections.abc import Iterable


def _joined(*parts: bytes) -> bytes:
    return b"".join(parts)


_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("macOS user home", re.compile(re.escape(_joined(b"/", b"Users/")) + rb"[^\s\"'<>`]+")),
    ("Linux user home", re.compile(re.escape(_joined(b"/", b"home/")) + rb"[^\s\"'<>`]+")),
    ("Windows user home", re.compile(rb"[A-Za-z]:\\" + _joined(b"Us", b"ers") + rb"\\[^\s\"'<>`]+")),
    ("mounted host volume", re.compile(re.escape(_joined(b"/Vol", b"umes/")) + rb"[^\s\"'<>`]+")),
    ("host temporary path", re.compile(re.escape(_joined(b"/private/var/", b"folders/")) + rb"[^\s\"'<>`]+")),
    ("personal cache or workspace", re.compile(rb"~/(?:Projects|Library|Desktop|Documents|Downloads|\.cursor|\.codex|\.kimi-code)/[^\s\"'<>`]*")),
    ("workstation identity", re.compile(_joined(b"byte", b"dance"), re.IGNORECASE)),
    ("internal user metadata", re.compile(_joined(b"user-", b'id=\"ou_'), re.IGNORECASE)),
    ("internal collaboration URL", re.compile(_joined(rb"https?://[^\s\)\]>]*(?:", b"byte", b"dance|lark", b"office|fei", rb"shu\.cn|byte", rb"d\.org|tiktok-row)[^\s\)\]>]*"), re.IGNORECASE)),
    ("local file URL", re.compile(_joined(b"fi", b"le://"), re.IGNORECASE)),
    ("private key", re.compile(_joined(b"-----BEGIN ", rb"(?:RSA |EC |DSA )?", b"PRIVATE KEY-----"))),
    ("OpenSSH private key", re.compile(_joined(b"-----BEGIN ", b"OPENSSH PRIVATE KEY-----"))),
    ("AWS access key", re.compile(_joined(rb"\bAK", rb"IA[0-9A-Z]{16}\b"))),
    ("keybox XML", re.compile(_joined(b"<", b"Keybox"))),
    ("GitHub token", re.compile(_joined(rb"\bgh", rb"[opusr]_[A-Za-z0-9_]{20,}\b"))),
    ("GitHub token", re.compile(_joined(b"github_", rb"pat_[A-Za-z0-9_]{20,}"))),
    ("Slack credential", re.compile(_joined(rb"\bxox", rb"[aboprs]-[A-Za-z0-9-]{20,}"))),
    ("npm credential", re.compile(_joined(rb"\bnpm_", rb"[A-Za-z0-9]{30,}"))),
    ("Google API credential", re.compile(_joined(rb"\bAI", rb"za[0-9A-Za-z_-]{30,}"))),
    ("Stripe credential", re.compile(rb"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("OpenAI credential", re.compile(_joined(rb"\bsk", rb"-[A-Za-z0-9_-]{20,}"))),
    ("bearer credential", re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/-]{20,}")),
    ("JWT credential", re.compile(_joined(rb"\beyJ", rb"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\."))),
    ("URI userinfo credential", re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^@\s]+@")),
    ("URI query credential", re.compile(rb"[?&](?:password|secret|token|api[_-]?key)=[^&#\s]{8,}", re.IGNORECASE)),
    ("embedded credential assignment", re.compile(rb"\b(?:password|passwd|secret|access[_-]?token|api[_-]?key)\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']", re.IGNORECASE)),
    ("private assessment target", re.compile(_joined(rb"\b(?:mo", b"mo|hun", b"ter|maho", b"shojo|zhen", b"xi|kan", b"xue|her", b"dr|risk", rb"hider)\b"), re.IGNORECASE)),
    ("development analysis disclosure", re.compile(_joined(rb"\b(?:reverse[- ]engineer", b"ing|analysis[- ]only|later ", b"milestone|phase[- ]1|tempor", b"ary workaround|priv", rb"ate research notes)\b"), re.IGNORECASE)),
)

class SensitiveByteScanner:
    def __init__(self, overlap: int = 4096) -> None:
        self._tail = b""
        self._overlap = overlap
        self._labels: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        window = self._tail + chunk
        for label, pattern in _PATTERNS:
            if pattern.search(window):
                self._labels.add(label)
        self._tail = window[-self._overlap:]

    @property
    def findings(self) -> tuple[str, ...]:
        return tuple(sorted(self._labels))


def scan_sensitive_bytes(chunks: bytes | Iterable[bytes]) -> tuple[str, ...]:
    scanner = SensitiveByteScanner()
    if isinstance(chunks, bytes):
        scanner.feed(chunks)
    else:
        for chunk in chunks:
            scanner.feed(chunk)
    return scanner.findings
