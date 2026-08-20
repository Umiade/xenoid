#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile


def _epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SystemExit("source_date_epoch_invalid") from exc
    if value < 0:
        raise SystemExit("source_date_epoch_invalid")
    return value


def _members(source: Path) -> list[Path]:
    members = [source]
    for path in source.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        ):
            raise SystemExit("canonical_archive_unsafe_member")
        members.append(path)
    return sorted(
        members,
        key=lambda path: (
            source.name
            if path == source
            else f"{source.name}/{path.relative_to(source).as_posix()}"
        ).encode("utf-8"),
    )


def create(source: Path, destination: Path) -> None:
    try:
        source_info = source.lstat()
    except OSError as exc:
        raise SystemExit("canonical_archive_source_invalid") from exc
    if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISDIR(source_info.st_mode):
        raise SystemExit("canonical_archive_source_invalid")
    source = source.resolve(strict=True)
    destination_parent = destination.parent.resolve(strict=True)
    if destination_parent == source or source in destination_parent.parents:
        raise SystemExit("canonical_archive_destination_invalid")
    epoch = _epoch()
    members = _members(source)
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination_parent
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw,
                compresslevel=9,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.GNU_FORMAT,
                ) as archive:
                    for path in members:
                        relative = (
                            source.name
                            if path == source
                            else f"{source.name}/{path.relative_to(source).as_posix()}"
                        )
                        if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
                            raise SystemExit("canonical_archive_member_invalid")
                        info = path.lstat()
                        entry = tarfile.TarInfo(relative)
                        entry.uid = 0
                        entry.gid = 0
                        entry.uname = ""
                        entry.gname = ""
                        entry.mtime = epoch
                        entry.pax_headers = {}
                        if stat.S_ISDIR(info.st_mode):
                            entry.type = tarfile.DIRTYPE
                            entry.mode = 0o755
                            entry.size = 0
                            archive.addfile(entry)
                        else:
                            entry.type = tarfile.REGTYPE
                            entry.mode = 0o755 if info.st_mode & 0o111 else 0o644
                            entry.size = info.st_size
                            with path.open("rb") as stream:
                                archive.addfile(entry, stream)
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
        directory = os.open(destination_parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    create(arguments.source, arguments.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
