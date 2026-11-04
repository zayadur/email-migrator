"""Portable mailbox migration with explicit accounts and durable receipts."""

__version__ = "0.1.0"

from .credentials import Credentials
from .engine import Migration
from .gmail import GmailDestination
from .imap import IMAPDestination, IMAPSource
from .models import Endpoint, JobConfig
from .security import Deadline
from .state import State

__all__ = ["Credentials", "Deadline", "Endpoint", "GmailDestination", "IMAPDestination",
           "IMAPSource", "JobConfig", "Migration", "State"]
