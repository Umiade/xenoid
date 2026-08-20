#!/usr/bin/env python3
"""Deterministic ZIP/JAR publication and the pinned Xenoid Apktool resolver."""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Sequence
import urllib.error
import urllib.request
import zipfile

APKTOOL_VERSION = "2.10.0"
APKTOOL_URL = (
    "https://github.com/iBotPeaches/Apktool/releases/download/"
    f"v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
)
APKTOOL_SHA256 = "c0350abbab5314248dfe2ee0c907def4edd14f6faef1f5d372d3d4abd28f0431"
APKTOOL_MAX_BYTES = 32 * 1024 * 1024

_DOS_EPOCH = (1980, 1, 1, 0, 0, 0)
_COPY_BUFFER_BYTES = 1024 * 1024


class XenoidArchiveError(RuntimeError):
    """A stable, fail-closed archive or pinned-tool error."""


def _raise(code: str) -> None:
    raise XenoidArchiveError(code)


def _sha256_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise XenoidArchiveError("apktool_cache_unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            _raise("apktool_cache_unsafe")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, _COPY_BUFFER_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        _raise("apktool_cache_unsafe")
    os.chmod(directory, 0o700, follow_symlinks=False)


def _lock_descriptor(lock_path: Path) -> int:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise XenoidArchiveError("apktool_cache_lock_unsafe") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        _raise("apktool_cache_lock_unsafe")
    os.fchmod(descriptor, 0o600)
    return descriptor


def _valid_cached_apktool(cache_path: Path) -> bool:
    try:
        metadata = cache_path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        _raise("apktool_cache_unsafe")
    if _sha256_file(cache_path) != APKTOOL_SHA256:
        return False
    os.chmod(cache_path, 0o600, follow_symlinks=False)
    return True


def resolve_apktool(project_root: os.PathLike[str] | str | None = None) -> Path:
    """Return verified Apktool 2.10.0 bytes from the project-private cache.

    A process-wide filesystem lock serializes validation and publication. Downloads
    are bounded, digest-checked, fsynced, and atomically renamed without disturbing
    a previously valid cache entry.
    """

    root = (
        Path(project_root).resolve()
        if project_root is not None
        else Path(__file__).resolve().parents[1]
    )
    cache_directory = root / ".xenoid" / "cache" / "tooling"
    _private_directory(cache_directory)
    cache_path = cache_directory / f"apktool_{APKTOOL_VERSION}.jar"
    lock_path = cache_directory / f"apktool_{APKTOOL_VERSION}.lock"
    lock_descriptor = _lock_descriptor(lock_path)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if _valid_cached_apktool(cache_path):
            return cache_path

        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".apktool_{APKTOOL_VERSION}.",
            suffix=".download",
            dir=cache_directory,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(temporary_descriptor, 0o600)
            try:
                response = urllib.request.urlopen(APKTOOL_URL, timeout=120)
            except (OSError, urllib.error.URLError) as error:
                raise XenoidArchiveError("apktool_download_failed") from error
            with response, os.fdopen(temporary_descriptor, "wb", closefd=True) as output:
                temporary_descriptor = -1
                length = 0
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > APKTOOL_MAX_BYTES:
                        _raise("apktool_download_too_large")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if _sha256_file(temporary_path) != APKTOOL_SHA256:
                _raise("apktool_sha256_mismatch")
            os.replace(temporary_path, cache_path)
            _fsync_directory(cache_directory)
            if not _valid_cached_apktool(cache_path):
                _raise("apktool_sha256_mismatch")
            return cache_path
        finally:
            if temporary_descriptor >= 0:
                os.close(temporary_descriptor)
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def run_apktool(
    arguments: Sequence[os.PathLike[str] | str],
    *,
    project_root: os.PathLike[str] | str | None = None,
) -> None:
    """Run the shared pinned Apktool JAR through Java."""

    tool = resolve_apktool(project_root)
    subprocess.run(
        ["java", "-jar", str(tool), *(str(argument) for argument in arguments)],
        check=True,
    )


def _validated_entries(
    archive: zipfile.ZipFile,
) -> tuple[dict[str, zipfile.ZipInfo], set[str]]:
    files: dict[str, zipfile.ZipInfo] = {}
    directories: set[str] = set()
    seen: set[str] = set()

    for entry in archive.infolist():
        original_name = entry.orig_filename
        name = entry.filename
        if "\x00" in original_name or "\x00" in name:
            _raise("zip_entry_nul")
        if original_name != name:
            _raise("zip_entry_invalid_name")
        if not name or "\\" in name:
            _raise("zip_entry_invalid_name")
        try:
            name_bytes = name.encode("utf-8")
        except UnicodeEncodeError as error:
            raise XenoidArchiveError("zip_entry_invalid_name") from error
        if not name_bytes or name in seen:
            _raise("zip_entry_duplicate")
        seen.add(name)

        posix_path = PurePosixPath(name)
        windows_path = PureWindowsPath(name)
        components = name[:-1].split("/") if name.endswith("/") else name.split("/")
        if (
            posix_path.is_absolute()
            or windows_path.is_absolute()
            or bool(windows_path.drive)
            or any(component in {"", ".", ".."} for component in components)
        ):
            _raise("zip_entry_unsafe_name")

        unix_mode = entry.external_attr >> 16 if entry.create_system == 3 else 0
        entry_type = stat.S_IFMT(unix_mode)
        if entry_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            _raise("zip_entry_special")
        is_directory = name.endswith("/")
        if (entry_type == stat.S_IFDIR and not is_directory) or (
            entry_type == stat.S_IFREG and is_directory
        ):
            _raise("zip_entry_type_mismatch")
        if (entry.external_attr & 0x10) and not is_directory:
            _raise("zip_entry_type_mismatch")
        if entry.flag_bits & 0x1:
            _raise("zip_entry_encrypted")

        for index in range(1, len(components)):
            directories.add("/".join(components[:index]) + "/")
        if is_directory:
            if entry.file_size != 0:
                _raise("zip_directory_not_empty")
            directories.add(name)
        else:
            files[name] = entry

    if any(directory[:-1] in files for directory in directories):
        _raise("zip_entry_path_conflict")
    return files, directories


def _canonical_info(
    name: str,
    *,
    is_directory: bool,
    size: int = 0,
) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name, date_time=_DOS_EPOCH)
    entry.create_system = 3
    entry.create_version = 20
    entry.extract_version = 20
    entry.flag_bits = 0
    entry.volume = 0
    entry.internal_attr = 0
    entry.external_attr = (
        ((stat.S_IFDIR | 0o755) << 16) | 0x10
        if is_directory
        else (stat.S_IFREG | 0o644) << 16
    )
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry._compresslevel = 9
    entry.file_size = size
    entry.extra = b""
    entry.comment = b""
    return entry


def canonicalize_zip(
    source: os.PathLike[str] | str,
    destination: os.PathLike[str] | str,
) -> None:
    """Atomically rewrite *source* as a canonical ZIP/JAR at *destination*."""

    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=destination_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(temporary_descriptor, 0o600)
        with zipfile.ZipFile(source_path, "r") as input_archive:
            files, directories = _validated_entries(input_archive)
            names = sorted((*directories, *files), key=lambda name: name.encode("utf-8"))
            with os.fdopen(temporary_descriptor, "w+b", closefd=True) as output_file:
                temporary_descriptor = -1
                with zipfile.ZipFile(
                    output_file,
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                    allowZip64=True,
                    strict_timestamps=True,
                ) as output_archive:
                    output_archive.comment = b""
                    for name in names:
                        if name in directories:
                            output_archive.writestr(
                                _canonical_info(name, is_directory=True),
                                b"",
                                compress_type=zipfile.ZIP_DEFLATED,
                                compresslevel=9,
                            )
                            continue
                        source_info = files[name]
                        output_info = _canonical_info(
                            name,
                            is_directory=False,
                            size=source_info.file_size,
                        )
                        with input_archive.open(source_info, "r") as input_entry:
                            with output_archive.open(output_info, "w") as output_entry:
                                shutil.copyfileobj(
                                    input_entry,
                                    output_entry,
                                    length=_COPY_BUFFER_BYTES,
                                )
                output_file.flush()
                os.fchmod(output_file.fileno(), 0o644)
                os.fsync(output_file.fileno())
        os.replace(temporary_path, destination_path)
        _fsync_directory(destination_path.parent)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise XenoidArchiveError("zip_canonicalization_failed") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def publish_file_atomic(
    source: os.PathLike[str] | str,
    destination: os.PathLike[str] | str,
) -> None:
    """Publish a verified regular file without exposing partial destination bytes."""

    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source_path, source_flags)
    except OSError as error:
        raise XenoidArchiveError("archive_publish_source_unsafe") from error
    source_metadata = os.fstat(source_descriptor)
    if not stat.S_ISREG(source_metadata.st_mode):
        os.close(source_descriptor)
        _raise("archive_publish_source_unsafe")

    try:
        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination_path.name}.",
            suffix=".publish",
            dir=destination_path.parent,
        )
    except BaseException:
        os.close(source_descriptor)
        raise
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(temporary_descriptor, 0o600)
        with os.fdopen(source_descriptor, "rb", closefd=True) as input_file:
            source_descriptor = -1
            with os.fdopen(temporary_descriptor, "wb", closefd=True) as output_file:
                temporary_descriptor = -1
                shutil.copyfileobj(input_file, output_file, length=_COPY_BUFFER_BYTES)
                output_file.flush()
                os.fchmod(output_file.fileno(), 0o644)
                os.fsync(output_file.fileno())
        os.replace(temporary_path, destination_path)
        _fsync_directory(destination_path.parent)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
