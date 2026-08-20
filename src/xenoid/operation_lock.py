from __future__ import annotations

import fcntl
import os
import stat
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator, Optional

from .config import InstanceError


EXPECTED_INSTANCE_ID_ENV = "XENOID_EXPECT_INSTANCE_ID"
OPERATION_LOCK_TIMEOUT_ENV = "XENOID_OPERATION_LOCK_TIMEOUT"

_HELD_INSTANCE_IDS: ContextVar[frozenset[str]] = ContextVar(
    "xenoid_held_instance_ids",
    default=frozenset(),
)


@contextmanager
def instance_operation_lock(
    state_root: Path,
    *,
    timeout_seconds: Optional[float] = None,
) -> Iterator[None]:
    """Serialize lifecycle/state mutation for one immutable instance.

    A `None` timeout is the trusted-local blocking behavior. Network workers use
    zero so a busy instance cannot consume a global request slot while queued.
    """

    root = Path(state_root)
    instance_id = root.name
    if instance_id in _HELD_INSTANCE_IDS.get():
        yield
        return
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / "operation.lock"
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InstanceError("instance_busy", "instance operation lock unavailable") from exc
    locked = False
    held_token = None
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise InstanceError("instance_busy", "instance operation lock invalid")
        if timeout_seconds is None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
        else:
            deadline = time.monotonic() + max(0.0, timeout_seconds)
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise InstanceError("instance_busy", "instance operation in progress") from exc
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        held = _HELD_INSTANCE_IDS.get()
        held_token = _HELD_INSTANCE_IDS.set(held | {instance_id})
        yield
    finally:
        if held_token is not None:
            _HELD_INSTANCE_IDS.reset(held_token)
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def operation_lock_is_held(instance_id: str) -> bool:
    return (
        isinstance(instance_id, str)
        and bool(instance_id)
        and instance_id in _HELD_INSTANCE_IDS.get()
    )
