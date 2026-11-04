from dataclasses import asdict, dataclass, field
import re

from .errors import MigrationError
from .security import encoded, sha


def text(value, name):
    if (type(value) is not str or not value or len(value) > 1024
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise MigrationError(f"Invalid {name}.")
    return value


@dataclass(frozen=True)
class Endpoint:
    host: str
    user: str
    port: int = 993
    auth: str = "password"
    kind: str = "imap"

    def __post_init__(self):
        text(self.host, "host")
        text(self.user, "account")
        if (self.kind not in ("imap", "gmail") or self.auth not in ("password", "xoauth2", "gmail-oauth")
                or type(self.port) is not int or not 0 < self.port < 65536
                or re.search(r"[\s/@?#]", self.host)):
            raise MigrationError("Invalid account endpoint.")
        if self.kind == "gmail" and (self.host != "gmail.googleapis.com" or self.port != 443 or self.auth != "gmail-oauth"):
            raise MigrationError("Gmail requires its pinned API endpoint and OAuth credentials.")
        if self.kind == "imap" and self.auth == "gmail-oauth":
            raise MigrationError("Use password or XOAUTH2 for IMAP.")


@dataclass(frozen=True)
class JobConfig:
    source: Endpoint
    destination: Endpoint
    folders: tuple = ()
    mapping: dict = field(default_factory=dict)
    max_message_bytes: int = 25 * 1024 * 1024
    create_folders: bool = False

    def __post_init__(self):
        if self.source.kind != "imap":
            raise MigrationError("Source must be IMAP.")
        if (self.source.host.casefold(), self.source.port, self.source.user) == (
                self.destination.host.casefold(), self.destination.port, self.destination.user):
            raise MigrationError("Source and destination must be different mailboxes.")
        if (self.destination.kind == "gmail" and self.source.host.casefold() in ("imap.gmail.com", "imap.googlemail.com")
                and self.source.user.casefold() == self.destination.user.casefold()):
            raise MigrationError("Refusing a Gmail-to-itself migration.")
        if len(set(self.folders)) != len(self.folders) or len(self.folders) > 1000:
            raise MigrationError("Duplicate or excessive folder scope.")
        for name in self.folders:
            text(name, "folder")
        if type(self.mapping) is not dict or len(self.mapping) > 1000:
            raise MigrationError("Invalid folder mapping.")
        for key, value in self.mapping.items():
            text(key, "source folder")
            text(value, "destination folder")
        if type(self.max_message_bytes) is not int or not 0 < self.max_message_bytes <= 150 * 1024 * 1024:
            raise MigrationError("Message limit must be 1 byte through 150 MiB.")
        if type(self.create_folders) is not bool:
            raise MigrationError("Invalid folder-creation policy.")

    def to_dict(self):
        result = asdict(self)
        result["folders"] = list(self.folders)
        return result

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {
                "source", "destination", "folders", "mapping", "max_message_bytes", "create_folders"}:
            raise MigrationError("Invalid job configuration shape.")
        return cls(Endpoint(**value["source"]), Endpoint(**value["destination"]),
                   tuple(value["folders"]), value["mapping"], value["max_message_bytes"], value["create_folders"])

    @property
    def digest(self):
        return sha(encoded(self.to_dict()))

    def target(self, folder):
        return self.mapping.get(folder, "INBOX" if folder.casefold() == "inbox" else folder)


@dataclass(frozen=True)
class Occurrence:
    folder: str
    uidvalidity: int
    uid: int
    bytes: int
    flags: tuple
    internal_date: str

    def __post_init__(self):
        text(self.folder, "folder")
        if any(type(v) is not int or v <= 0 for v in (self.uidvalidity, self.uid, self.bytes)):
            raise MigrationError("Invalid source occurrence identity or size.")
        if (type(self.flags) is not tuple
                or any(type(f) is not str or not f or re.search(r'[\s(){}%*"\x00-\x1f\x7f]', f) for f in self.flags)
                or len({f.casefold() for f in self.flags}) != len(self.flags)):
            raise MigrationError("Invalid IMAP flags.")
        text(self.internal_date, "INTERNALDATE")

    @property
    def key(self):
        return encoded([self.folder, self.uidvalidity, self.uid]).decode()

    def to_dict(self):
        value = asdict(self)
        value["flags"] = list(self.flags)
        return value

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"folder", "uidvalidity", "uid", "bytes", "flags", "internal_date"}:
            raise MigrationError("Invalid occurrence shape.")
        return cls(**{**value, "flags": tuple(value["flags"])})


@dataclass(frozen=True)
class Ack:
    key: str
    selector: dict
