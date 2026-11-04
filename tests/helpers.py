import copy
from email import policy
from email.message import EmailMessage
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mail_migrator.message import internal_timestamp
from mail_migrator.models import Ack, Endpoint, JobConfig, Occurrence
from mail_migrator.security import encoded

DATE = "04-Nov-2026 12:00:00 +0000"


def raw_message(*, attachment=False):
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Synthetic fixture"
    message["Date"] = "Wed, 04 Nov 2026 12:00:00 +0000"
    message["Message-ID"] = "<fixture@example.test>"
    message.set_content("Only synthetic test content.\n")
    if attachment:
        message.add_attachment(bytes(range(256)), maintype="application", subtype="octet-stream", filename="fixture.bin")
        message.set_boundary("synthetic-stable-boundary")
    return message.as_bytes(policy=policy.SMTP)


def occurrence(uid=1, *, folder="INBOX", flags=(), raw=None):
    return Occurrence(folder, 11, uid, len(raw or raw_message()), tuple(flags), DATE)


def job(kind="imap", **kwargs):
    destination = (Endpoint("dest.example.test", "destination@example.test") if kind == "imap" else
                   Endpoint("gmail.googleapis.com", "destination@example.test", 443, "gmail-oauth", "gmail"))
    return JobConfig(Endpoint("source.example.test", "source@example.test"), destination, **kwargs)


class OfflineTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.connect = patch("socket.socket.connect", side_effect=AssertionError("Actual network disabled"))
        self.connect.start()
        self.addCleanup(self.connect.stop)
        root_setting = os.environ.get("EMAIL_MIGRATOR_TEST_CASE")
        if not root_setting:
            raise RuntimeError("Set EMAIL_MIGRATOR_TEST_CASE to the owning session's private case directory.")
        root = Path(root_setting).expanduser().absolute()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(prefix="fixture-", dir=root)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.state_dir = self.root / "job"


class FakeSource:
    def __init__(self, items=None):
        self.endpoint = job().source
        items = items if items is not None else [(occurrence(), raw_message())]
        self.items = {spec.key: (spec, raw) for spec, raw in items}
        self.reads = []
        self.missing, self.protocol_error = set(), False

    def inventory(self, config, emit):
        specs = [x[0] for x in self.items.values() if x[0].key not in self.missing]
        folders = sorted({s.folder for s in specs} | {"INBOX"})
        emit({"stage": "synthetic_metadata_only"})
        return {"observed_at": "synthetic-" + str(len(specs)) + "-" + str(len(emit.__self__.rows())),
                "folders": [{"name": f, "uidvalidity": next((s.uidvalidity for s in specs if s.folder == f), 11), "messages": sum(s.folder == f for s in specs),
                             "bytes": sum(s.bytes for s in specs if s.folder == f)} for f in folders],
                "entries": [s.to_dict() for s in specs]}

    def read(self, spec, **kwargs):
        self.reads.append(spec.key)
        if self.protocol_error:
            from mail_migrator.errors import MigrationError
            raise MigrationError("Synthetic protocol error, not absence.")
        if spec.key in self.missing:
            return None
        return self.items[spec.key]

    def close(self):
        pass


class FakeDestination:
    kind = "imap"

    def __init__(self, kind="imap"):
        self.kind = kind
        self.endpoint = job(kind).destination
        self.messages, self.posts, self.gets = {}, [], []
        self.lost_ack = self.bad_readback = self.fail_readback = False
        self.after_insert = self.forced_ack = None
        self.user_flag_edit = False
        self.prepare_error = False

    def preflight(self, targets, *, create=False):
        return []

    def ensure(self, target, *, create=False):
        return target

    def prepare(self):
        if self.prepare_error:
            raise RuntimeError("Synthetic refresh failure")

    def insert(self, raw, target, spec, baseline):
        self.posts.append(spec.key)
        if self.lost_ack:
            raise OSError("synthetic lost ACK")
        number = len(self.posts)
        ack = (Ack("gmail:id" + str(number), {"id": "id" + str(number)}) if self.kind == "gmail" else
               Ack("imap:" + encoded([target, 91, number]).decode(), {"folder": target, "uidvalidity": 91, "uid": number}))
        ack = self.forced_ack or ack
        self.messages[ack.key] = (raw, copy.deepcopy(baseline))
        if self.after_insert:
            self.after_insert()
        return ack

    def get(self, ack, baseline):
        self.gets.append(ack.key)
        if self.fail_readback:
            raise OSError("Synthetic GET failure")
        raw, copied = self.messages[ack.key]
        if self.bad_readback:
            raw = raw.replace(b"Only synthetic", b"Changed synthetic")
        flags = list(copied["copied_flags"])
        state = dict(copied["copied_read_star"])
        if self.user_flag_edit:
            state["read"] = not state["read"]
            flags = [x for x in flags if x.casefold() != r"\seen"]
            if state["read"]:
                flags.append(r"\Seen")
        return {"raw": raw, "date_ms": copied["destination_date_ms"], "read_star": state,
                "flags": flags, "placement": copied["destination_target"], "labels": [copied["destination_target"]]}

    def close(self):
        pass
