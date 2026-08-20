from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any

_TAIL_BYTES = 64 * 1024
_TERM_GRACE_SECONDS = 5.0
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URI = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)"
    r"(?:(?P<userinfo>[^/@\s]+)@)?(?P<host>[^/?#\s]+)"
    r"(?P<path>/[^?#\s]*)?(?:\?(?P<query>[^#\s]*))?"
)
_SECRET_NAME = re.compile(
    r"(?:auth|bearer|cookie|credential|password|passwd|secret|token|api[_-]?key)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BoundedResult:
    state: str
    returncode: int | None
    stdout_tail: str
    stderr_tail: str
    duration_ms: int
    error_code: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == "passed" and self.returncode == 0

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "state": self.state,
            "returncode": self.returncode,
            "durationMs": self.duration_ms,
        }
        if self.stdout_tail:
            result["stdoutTail"] = self.stdout_tail
        if self.stderr_tail:
            result["stderrTail"] = self.stderr_tail
        if self.error_code:
            result["errorCode"] = self.error_code
        return result


class Redactor:
    """One deterministic boundary for child output retained by host tooling."""

    def __init__(
        self,
        *,
        project_root: Path | None = None,
        env: Mapping[str, str] | None = None,
        known_values: Sequence[str] = (),
    ) -> None:
        replacements: list[tuple[str, str]] = []
        if project_root is not None:
            replacements.append((str(project_root.resolve()), "$PROJECT"))
        try:
            replacements.append((str(Path.home().resolve()), "$HOME"))
        except OSError:
            pass
        replacements.append((str(Path(tempfile.gettempdir()).resolve()), "$TMP"))
        source = env if env is not None else os.environ
        secrets = list(known_values)
        secrets.extend(
            value
            for key, value in source.items()
            if _SECRET_NAME.search(key) and isinstance(value, str)
        )
        for value in secrets:
            if len(value) >= 4:
                replacements.append((value, "[REDACTED]"))
        # Longest first prevents a parent path from leaving a private suffix.
        self._replacements = tuple(
            sorted(set(replacements), key=lambda item: len(item[0]), reverse=True)
        )

    def __call__(self, value: str) -> str:
        text = _CONTROL.sub("?", value)
        for private, replacement in self._replacements:
            text = text.replace(private, replacement)

        def redact_uri(match: re.Match[str]) -> str:
            userinfo = "[REDACTED]@" if match.group("userinfo") else ""
            path = match.group("path") or ""
            query = "?[REDACTED]" if match.group("query") is not None else ""
            return f"{match.group('scheme')}{userinfo}{match.group('host')}{path}{query}"

        return _URI.sub(redact_uri, text)


def _append_tail(buffer: bytearray, chunk: bytes) -> None:
    buffer.extend(chunk)
    if len(buffer) > _TAIL_BYTES:
        del buffer[: len(buffer) - _TAIL_BYTES]


def _signal_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    deadline: float,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    max_input_bytes: int = 4096,
    cancelled: Event | Callable[[], bool] | None = None,
    project_root: Path | None = None,
    known_values: Sequence[str] = (),
    progress: Callable[[str, str], None] | None = None,
    stdout_consumer: Callable[[bytes], None] | None = None,
) -> BoundedResult:
    """Run one local child in its own process group under an absolute deadline.

    Output is never accumulated without a bound. On timeout or cancellation the
    complete local process group receives SIGTERM, then SIGKILL after five
    seconds. Callers receive only redacted tails and stable state/error codes.
    """

    started = time.monotonic()
    if not command or any(not isinstance(part, str) or not part for part in command):
        return BoundedResult(
            "failed", None, "", "", 0, "process_command_invalid"
        )
    if not isinstance(deadline, (int, float)) or deadline <= started:
        return BoundedResult(
            "timed_out", None, "", "", 0, "process_timeout"
        )

    if (
        not isinstance(max_input_bytes, int)
        or isinstance(max_input_bytes, bool)
        or not 0 <= max_input_bytes <= 1024 * 1024
    ):
        return BoundedResult(
            "failed", None, "", "", 0, "process_input_bound_invalid"
        )
    if input_bytes is not None and len(input_bytes) > max_input_bytes:
        return BoundedResult(
            "failed", None, "", "", 0, "process_input_too_large"
        )
    child_env = dict(os.environ if env is None else env)
    redactor = Redactor(
        project_root=project_root or cwd,
        env=child_env,
        known_values=known_values,
    )
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=child_env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        return BoundedResult(
            "failed",
            None,
            "",
            "",
            max(0, int((time.monotonic() - started) * 1000)),
            "process_start_failed",
        )

    if input_bytes is not None and process.stdin is not None:
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    for stream_name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, stream_name)
    tails = {"stdout": bytearray(), "stderr": bytearray()}
    state = "passed"
    error_code: str | None = None
    terminating_at: float | None = None
    last_progress = started

    def is_cancelled() -> bool:
        if cancelled is None:
            return False
        if isinstance(cancelled, Event):
            return cancelled.is_set()
        try:
            return bool(cancelled())
        except Exception:
            return True

    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if state == "passed" and (is_cancelled() or now >= deadline):
                state = "cancelled" if is_cancelled() else "timed_out"
                error_code = (
                    "process_cancelled" if state == "cancelled" else "process_timeout"
                )
                _signal_group(process, signal.SIGTERM)
                terminating_at = now
            if (
                terminating_at is not None
                and now - terminating_at >= _TERM_GRACE_SECONDS
            ):
                _signal_group(process, signal.SIGKILL)
                terminating_at = None
            try:
                selected = selector.select(timeout=0.1)
            except InterruptedError:
                continue
            for key, _ in selected:
                try:
                    chunk = os.read(key.fd, 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                _append_tail(tails[str(key.data)], chunk)
                if key.data == "stdout" and stdout_consumer is not None:
                    try:
                        stdout_consumer(chunk)
                    except Exception:
                        if state == "passed":
                            state = "failed"
                            error_code = "process_output_consumer_failed"
                        stdout_consumer = None
                        _signal_group(process, signal.SIGTERM)
                        terminating_at = now
                if progress is not None:
                    try:
                        progress(
                            str(key.data),
                            redactor(chunk.decode("utf-8", "replace")),
                        )
                    except Exception:
                        if state == "passed":
                            state = "failed"
                            error_code = "process_progress_failed"
                        progress = None
                        _signal_group(process, signal.SIGTERM)
                        terminating_at = now
            if progress is not None and now - last_progress >= 5.0:
                try:
                    progress("heartbeat", "running")
                except Exception:
                    if state == "passed":
                        state = "failed"
                        error_code = "process_progress_failed"
                    progress = None
                    _signal_group(process, signal.SIGTERM)
                    terminating_at = now
                last_progress = now
        returncode = process.wait()
    except BaseException:
        _signal_group(process, signal.SIGTERM)
        try:
            grace_deadline = time.monotonic() + _TERM_GRACE_SECONDS
            while process.poll() is None and time.monotonic() < grace_deadline:
                try:
                    time.sleep(0.05)
                except BaseException:
                    break
        finally:
            _signal_group(process, signal.SIGKILL)
            try:
                process.wait(timeout=_TERM_GRACE_SECONDS)
            except BaseException:
                pass
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    if state == "passed" and returncode != 0:
        state = "failed"
        error_code = "process_failed"
    duration = max(0, int((time.monotonic() - started) * 1000))
    stdout = redactor(bytes(tails["stdout"]).decode("utf-8", "replace")).strip()
    stderr = redactor(bytes(tails["stderr"]).decode("utf-8", "replace")).strip()
    return BoundedResult(state, returncode, stdout, stderr, duration, error_code)
