#!/usr/bin/env python3
"""Run one protection operation while holding the selected engine-host lock."""

from __future__ import annotations

import os
import platform
import selectors
import re
import shlex
import signal
import subprocess
import sys
import time
from typing import Sequence

CAPABILITY_ENV = "XENOID_SHARED_PROTECTION_CAPABILITY"
LOCK_SCRIPT = r'''
set -eu
p=/run/lock/xenoid-shared-protection.lock
if [ ! -e "$p" ]; then (set -C; umask 077; : > "$p") 2>/dev/null || true; fi
[ ! -L "$p" ]
[ -f "$p" ]
[ "$(stat -c '%u:%g:%a:%h' "$p")" = '0:0:600:1' ]
exec flock -x "$p" sh -c '
set -eu
d=/run/xenoid/shared-protection-capabilities
install -d -o root -g root -m 0700 "$d"
[ ! -L "$d" ] && [ "$(stat -c "%u:%g:%a" "$d")" = "0:0:700" ]
nonce=$(od -An -N32 -tx1 /dev/urandom | tr -d " \n")
case "$nonce" in *[!0-9a-f]*|"") exit 1;; esac
cap="$d/$nonce"
umask 077
(set -C; : >"$cap")
[ ! -L "$cap" ] && [ "$(stat -c "%u:%g:%a:%h" "$cap")" = "0:0:600:1" ]
trap "rm -f -- \"$cap\"" EXIT HUP INT TERM
( printf "XENOID_LOCKED %s\n" "$nonce" )
cat >/dev/null
'
'''


def transport(argv: Sequence[str]) -> list[str]:
    mode = "colima" if platform.system() == "Darwin" else "local"
    target = ""
    port = ""
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == "--colima":
            mode = "colima"
        elif value == "--local":
            mode = "local"
        elif value == "--ssh" and index + 1 < len(argv):
            mode = "ssh"
            target = argv[index + 1]
            index += 1
        elif value == "--ssh-port" and index + 1 < len(argv):
            port = argv[index + 1]
            index += 1
        index += 1
    if mode == "local":
        return ["sudo", "-n", "sh", "-c", LOCK_SCRIPT, "xenoid-shared-protection-lock"]
    if mode == "colima":
        return [
            "colima",
            "ssh",
            "--",
            "sudo",
            "-n",
            "sh",
            "-c",
            LOCK_SCRIPT,
            "xenoid-shared-protection-lock",
        ]
    if not target:
        raise ValueError("shared_protection_engine_unavailable")
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if port:
        ssh.extend(("-p", port))
    ssh.append(target)
    ssh.append(
        shlex.join(
            [
                "sudo",
                "-n",
                "sh",
                "-c",
                LOCK_SCRIPT,
                "xenoid-shared-protection-lock",
            ]
        )
    )
    return ssh


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main() -> int:
    if len(sys.argv) < 2:
        print("shared_protection_command_invalid", file=sys.stderr)
        return 2
    existing = os.environ.get(CAPABILITY_ENV, "")
    if re.fullmatch(r"[0-9a-f]{64}", existing):
        return subprocess.run(sys.argv[1:], check=False).returncode
    try:
        holder_command = transport(sys.argv[2:])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    holder = subprocess.Popen(
        holder_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    acquired = False
    capability = ""
    try:
        if holder.stdout is None or holder.stderr is None:
            return 1
        selector.register(holder.stdout, selectors.EVENT_READ)
        selector.register(holder.stderr, selectors.EVENT_READ)
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline and holder.poll() is None:
            for key, _ in selector.select(min(1.0, deadline - time.monotonic())):
                line = key.fileobj.readline()
                match = re.fullmatch(r"XENOID_LOCKED ([0-9a-f]{64})\n", line)
                if key.fileobj is holder.stdout and match is not None:
                    capability = match.group(1)
                    acquired = True
                    break
            if acquired:
                break
        if not acquired and holder.poll() is not None:
            remainder = holder.stdout.read(4097)
            if len(remainder) <= 4096:
                for line in remainder.splitlines(keepends=True):
                    match = re.fullmatch(
                        r"XENOID_LOCKED ([0-9a-f]{64})\n",
                        line,
                    )
                    if match is not None:
                        capability = match.group(1)
                        acquired = True
                        break
        if not acquired:
            print("shared_protection_lock_unavailable", file=sys.stderr)
            return 1
        environment = os.environ.copy()
        environment[CAPABILITY_ENV] = capability
        child = subprocess.Popen(
            sys.argv[1:],
            env=environment,
            start_new_session=True,
        )
        try:
            return child.wait()
        except BaseException:
            stop_process(child)
            raise
    finally:
        selector.close()
        if holder.stdin is not None:
            try:
                holder.stdin.close()
            except OSError:
                pass
        stop_process(holder)


if __name__ == "__main__":
    raise SystemExit(main())
