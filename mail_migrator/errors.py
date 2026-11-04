class MigrationError(Exception):
    """Safe operator-facing error: never include provider bodies or secrets."""


class Hold(MigrationError):
    """A source occurrence cannot be copied under the strict policy."""


class UncertainWrite(MigrationError):
    """A write might have completed. Never automatically repeat it."""
