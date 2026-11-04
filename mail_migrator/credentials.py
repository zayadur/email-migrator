"""Caller-selected credentials; no ambient account or keychain discovery."""
from dataclasses import dataclass, field
import os
import re
from types import MappingProxyType

from .errors import MigrationError
from .security import private_read, strict_json


@dataclass(frozen=True)
class Credentials:
    values: dict = field(repr=False)

    def __post_init__(self):
        if type(self.values) is not dict:
            raise MigrationError("Credentials must be an explicitly supplied JSON object.")
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))

    def get(self, key):
        value = self.values.get(key)
        if type(value) is not str or not value or len(value) > 65536 or "\x00" in value:
            raise MigrationError(f"Credentials require a nonempty {key} field.")
        return value


def load_credentials(*, path=None, env=None, auth="password"):
    if bool(path) == bool(env):
        raise MigrationError("Select exactly one credential file or named environment variable.")
    key = "password" if auth == "password" else "access_token"
    if path:
        values = strict_json(private_read(path, limit=65536))
        if type(values) is not dict:
            raise MigrationError("Credential file must contain a JSON object.")
    else:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env):
            raise MigrationError("Invalid credential environment-variable name.")
        secret = os.environ.get(env)
        if auth == "gmail-oauth":
            values = strict_json(secret or "")
        else:
            values = {key: secret}
    credentials = Credentials(values)
    for name in (("client_id", "client_secret", "refresh_token") if auth == "gmail-oauth" else (key,)):
        credentials.get(name)
    return credentials
