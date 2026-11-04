"""Private local files and a single POSIX writer; no credential discovery."""
from contextlib import AbstractContextManager
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from .errors import MigrationError


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise MigrationError("Duplicate JSON key.")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _:
                          (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise MigrationError("Invalid JSON file.") from None


def private_dir(path, *, create=False):
    path = Path(path).expanduser().absolute()
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.resolve() != path
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise MigrationError("State directory must be owned by you, mode 0700, and not a symlink.")
    return path


def check_file(fd, path, *, modes=(0o600, 0o400)):
    info, linked = os.fstat(fd), Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
        raise MigrationError("Unsafe private file: require owned, single-link 0600/0400 regular files.")
    return info


def private_read(path, *, limit=64 * 1024 * 1024, modes=(0o600, 0o400)):
    path = Path(path).expanduser().absolute()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = check_file(stream.fileno(), path, modes=modes)
            if info.st_size > limit:
                raise MigrationError("Private input exceeds its size limit.")
            raw = stream.read(limit + 1)
            after = check_file(stream.fileno(), path, modes=modes)
            if len(raw) > limit or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise MigrationError("Private input changed during reading.")
            return raw
    except OSError:
        raise MigrationError("Cannot read private input; check its path and permissions.") from None


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value, *, mode=0o600):
    """Publish once. Failed partial files are retained, never silently replaced."""
    data = encoded(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    fsync_dir(Path(path).parent)
    return sha(data)


class WriterLock(AbstractContextManager):
    def __init__(self, directory):
        self.directory = private_dir(directory)
        self.path = self.directory / "writer.lock"
        self.fd = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            raise MigrationError("This version requires POSIX file locks (macOS/Linux).") from None
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            check_file(self.fd, self.path, modes=(0o600,))
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise MigrationError("Another process owns this state, or the lock is unsafe.") from None
        self.pid = os.getpid()
        return self

    def check(self):
        if self.fd is None or self.pid != os.getpid():
            raise MigrationError("Current-process writer lock required.")
        private_dir(self.directory)
        check_file(self.fd, self.path, modes=(0o600,))

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Deadline:
    def __init__(self, seconds=300, *, clock=time.monotonic):
        if type(seconds) not in (int, float) or not 0 < seconds <= 86400:
            raise MigrationError("Runtime must be between 0 and 86400 seconds.")
        self.clock, self.end, self.stopped = clock, clock() + seconds, False

    def stop(self, *_):
        self.stopped = True  # Cooperative: do not interrupt ACK persistence.

    def check(self):
        if self.stopped or self.clock() >= self.end:
            raise MigrationError("Operation stopped or runtime exhausted.")

    def timeout(self):
        self.check()
        return max(0.01, min(30, self.end - self.clock()))
