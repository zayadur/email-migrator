"""One compact ledger per account pair; delta plans never embed their ancestors."""
from collections import Counter
from contextlib import AbstractContextManager
import datetime as dt
import os
from pathlib import Path
import re
import sqlite3
import uuid

from .errors import MigrationError, UncertainWrite
from .models import JobConfig, Occurrence
from .message import internal_timestamp
from .security import (WriterLock, check_file, encoded, fsync_dir, private_dir,
                       private_read, sha, strict_json, write_new)

SCHEMA = {
    "meta": "CREATE TABLE meta(name TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "folders": "CREATE TABLE folders(name TEXT PRIMARY KEY,uidvalidity INTEGER NOT NULL)",
    "plans": "CREATE TABLE plans(digest TEXT PRIMARY KEY,body TEXT NOT NULL)",
    "occurrences": ("CREATE TABLE occurrences(key TEXT PRIMARY KEY,spec TEXT NOT NULL,state TEXT NOT NULL,"
                    "receipt TEXT,baseline TEXT,error TEXT,first_plan TEXT NOT NULL,last_seen TEXT NOT NULL)"),
    "observations": ("CREATE TABLE observations(plan TEXT NOT NULL,key TEXT NOT NULL,present INTEGER NOT NULL,"
                     "spec TEXT,PRIMARY KEY(plan,key))"),
}
STATES = {"pending", "held", "posting", "uncertain", "created", "verified"}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class State(AbstractContextManager):
    def __init__(self, directory, config=None, *, create=False):
        self.directory = private_dir(directory, create=create)
        self.path = self.directory / "ledger.sqlite3"
        self.config_path = self.directory / "job.json"
        self.requested_config, self.create = config, create
        self.db = self.lock = None

    def __enter__(self):
        self.lock = WriterLock(self.directory).__enter__()
        try:
            fresh = not os.path.lexists(self.path)
            if fresh:
                if not self.create or self.requested_config is None:
                    raise MigrationError("No existing job. Create an explicit plan first.")
                if any(p.name != "writer.lock" for p in self.directory.iterdir()):
                    raise MigrationError("Incomplete/nonempty state directory; never initialize over it.")
                write_new(self.config_path, self.requested_config.to_dict(), mode=0o400)
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            else:
                self._check_database_file()
            for name in ("plans", "reports"):
                private_dir(self.directory / name, create=fresh)
            info = self.path.lstat()
            self.database_identity = (info.st_dev, info.st_ino)
            if not fresh:
                # Inspect existing evidence read-only before opening a writer or
                # setting any journal pragma. Never repair an unfamiliar DB.
                self.db = sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True)
                self.db.row_factory = sqlite3.Row
                self.db.execute("PRAGMA query_only=ON")
                self._validate()
                self.db.close()
                self.db = None
                after = self.path.lstat()
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                    raise MigrationError("Ledger changed between read-only validation and writer admission.")
            self.db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA busy_timeout=0")
            if fresh:
                with self.db:
                    for ddl in SCHEMA.values():
                        self.db.execute(ddl)
                    self.db.executemany("INSERT INTO meta VALUES (?,?)", [
                        ("schema", "1"), ("config_sha256", self.requested_config.digest)])
                fsync_dir(self.directory)
            self._validate()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _check_database_file(self):
        for suffix in ("-journal", "-wal", "-shm"):
            if os.path.lexists(str(self.path) + suffix):
                raise MigrationError("Unreconciled database sidecar; no automatic recovery/reseed.")
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = check_file(stream.fileno(), self.path, modes=(0o600,))
            raw = stream.read(100)
        if info.st_size > 1024 * 1024 * 1024 or len(raw) < 100 or raw[:16] != b"SQLite format 3\x00" or raw[18:20] != b"\x01\x01":
            raise MigrationError("Existing ledger is empty, malformed or not rollback-journal SQLite.")

    def _validate(self):
        actual = {r["name"]: r["sql"] for r in self.db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table'")}
        if actual != SCHEMA or self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise MigrationError("Ledger schema/integrity mismatch; no automatic repair.")
        meta = dict(self.db.execute("SELECT name,value FROM meta"))
        self.config = JobConfig.from_dict(strict_json(private_read(self.config_path, modes=(0o400,))))
        if meta != {"schema": "1", "config_sha256": self.config.digest}:
            raise MigrationError("Job configuration and ledger identity differ.")
        if self.requested_config is not None and self.config.to_dict() != self.requested_config.to_dict():
            raise MigrationError("Account pair, mapping, scope or policy changed; use a different state directory.")
        self.config_hash = meta["config_sha256"]
        enrolled = {r[0] for r in self.db.execute("SELECT digest FROM plans")}
        actual_plans = {p.name for p in (self.directory / "plans").iterdir()}
        if actual_plans != {f"plan-{digest}.json" for digest in enrolled}:
            raise MigrationError("Unenrolled/missing plan artifact; retain evidence and reconcile manually.")
        rows = self.rows()
        if len(rows) > 1000000:
            raise MigrationError("Ledger row limit exceeded.")
        ids = []
        for row in rows:
            spec = Occurrence.from_dict(strict_json(row["spec"]))
            if row["key"] != spec.key or row["state"] not in STATES:
                raise MigrationError("Ledger occurrence identity/state mismatch.")
            if row["first_plan"] not in enrolled or row["last_seen"] not in enrolled:
                raise MigrationError("Occurrence lost its original plan provenance.")
            saved = row["state"] in ("created", "verified")
            if saved != (row["receipt"] is not None) or (row["state"] in ("posting", "uncertain", "created", "verified")) != (row["baseline"] is not None):
                raise MigrationError("Ledger receipt/baseline combination is invalid.")
            if saved:
                receipt = strict_json(row["receipt"])
                if type(receipt) is not dict or set(receipt) != {"key", "selector"} or type(receipt["key"]) is not str or not receipt["key"].strip():
                    raise MigrationError("Saved receipt is malformed; retain it, never repost.")
                ids.append(receipt["key"])
                selector = receipt["selector"]
                if self.config.destination.kind == "gmail":
                    if (type(selector) is not dict or set(selector) != {"id"}
                            or type(selector["id"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", selector["id"])
                            or receipt["key"] != "gmail:" + selector["id"]):
                        raise MigrationError("Malformed saved Gmail receipt; no provider access or replay.")
                else:
                    if (type(selector) is not dict or set(selector) != {"folder", "uidvalidity", "uid"}
                            or type(selector["folder"]) is not str
                            or any(type(selector[n]) is not int or selector[n] <= 0 for n in ("uidvalidity", "uid"))
                            or receipt["key"] != "imap:" + encoded([selector["folder"], selector["uidvalidity"], selector["uid"]]).decode()):
                        raise MigrationError("Malformed saved IMAP receipt; no provider access or replay.")
                baseline = strict_json(row["baseline"])
                if type(baseline) is not dict or set(baseline) != {
                        "raw_sha256", "content_sha256", "destination_date_ms", "copied_read_star", "copied_flags",
                        "destination_target", "source_bytes", "source_internal_date", "source_internal_date_ms", "snapshot_flags"}:
                    raise MigrationError("Saved copy baseline is malformed.")
                if (any(type(baseline[n]) is not str or not re.fullmatch(r"[0-9a-f]{64}", baseline[n]) for n in ("raw_sha256", "content_sha256"))
                        or baseline["source_bytes"] != spec.bytes
                        or type(baseline["destination_date_ms"]) is not int
                        or type(baseline["copied_read_star"]) is not dict
                        or set(baseline["copied_read_star"]) != {"read", "starred"}
                        or any(type(v) is not bool for v in baseline["copied_read_star"].values())
                        or type(baseline["destination_target"]) is not str or not baseline["destination_target"]):
                    raise MigrationError("Saved fingerprint/flags/chronology evidence is invalid.")
                if (internal_timestamp(baseline["source_internal_date"]) != internal_timestamp(spec.internal_date)
                        or baseline["source_internal_date_ms"] != internal_timestamp(spec.internal_date)):
                    raise MigrationError("Saved source chronology changed.")
                if self.config.destination.kind == "imap" and (
                        selector["folder"] != baseline["destination_target"]
                        or baseline["destination_target"] != self.config.target(spec.folder)
                        or baseline["destination_date_ms"] != internal_timestamp(spec.internal_date)):
                    raise MigrationError("Saved destination placement/date no longer matches its job.")
            if row["state"] == "held" and not row["error"]:
                raise MigrationError("Held occurrence lacks its reason.")
        if len(set(ids)) != len(ids):
            raise MigrationError("Saved destination receipt aliases another occurrence; no provider writes.")
        self.check()

    def check(self):
        self.lock.check()
        if self.config.digest != self.config_hash:
            raise MigrationError("In-memory account configuration changed.")
        if JobConfig.from_dict(strict_json(private_read(self.config_path, modes=(0o400,)))).digest != self.config.digest:
            raise MigrationError("Frozen job file changed.")
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = check_file(fd, self.path, modes=(0o600,))
            if (info.st_dev, info.st_ino) != self.database_identity:
                raise MigrationError("Ledger file was replaced while open; no further work.")
        finally:
            os.close(fd)

    def rows(self, states=None):
        if states:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM occurrences WHERE state IN (" + ",".join("?" for _ in states) + ") ORDER BY key", tuple(states))]
        return [dict(r) for r in self.db.execute("SELECT * FROM occurrences ORDER BY key")]

    def refuse_uncertain(self, *, include_created=False):
        states = ("posting", "uncertain", "created") if include_created else ("posting", "uncertain")
        if self.rows(states) or list(self.directory.glob("emergency-ack-*.json")):
            raise UncertainWrite("Unresolved/uncertain writes exist. Retain the ledger; do not retry or reseed.")

    def accept_inventory(self, inventory):
        self.check()
        self.refuse_uncertain(include_created=True)
        entries = [Occurrence.from_dict(s) for s in inventory["entries"]]
        by_key = {e.key: e for e in entries}
        if len(by_key) != len(entries) or len(entries) > 1000000:
            raise MigrationError("Duplicate/excessive source inventory.")
        folders = inventory["folders"]
        if not 1 <= len(folders) <= 1000 or len(folders) != len({f["name"] for f in folders}):
            raise MigrationError("Duplicate source folder.")
        folder_map = {f["name"]: f for f in folders}
        for folder in folders:
            if (set(folder) != {"name", "uidvalidity", "messages", "bytes"}
                    or type(folder["name"]) is not str or not folder["name"]
                    or type(folder["uidvalidity"]) is not int or folder["uidvalidity"] <= 0
                    or any(type(folder[n]) is not int or folder[n] < 0 for n in ("messages", "bytes"))):
                raise MigrationError("Malformed source folder metadata.")
            matching = [s for s in entries if s.folder == folder["name"]]
            if (len(matching) != folder["messages"] or sum(s.bytes for s in matching) != folder["bytes"]
                    or any(s.uidvalidity != folder["uidvalidity"] for s in matching)):
                raise MigrationError("Source folder/entry accounting or UIDVALIDITY differs.")
        if any(s.folder not in folder_map for s in entries):
            raise MigrationError("Source entry is outside the observed folder set.")
        for spec in entries:
            internal_timestamp(spec.internal_date)
        old = {r["key"]: r for r in self.rows()}
        known_folders = dict(self.db.execute("SELECT name,uidvalidity FROM folders"))
        if any(f["name"] in known_folders and known_folders[f["name"]] != f["uidvalidity"] for f in folders):
            raise MigrationError("Source UIDVALIDITY changed; no UID reuse or automatic remapping.")
        if set(known_folders) - {f["name"] for f in folders}:
            raise MigrationError("A previously scoped source folder vanished.")
        for key, item in by_key.items():
            if key in old:
                previous = Occurrence.from_dict(strict_json(old[key]["spec"]))
                if (item.bytes, internal_timestamp(item.internal_date)) != (previous.bytes, internal_timestamp(previous.internal_date)):
                    raise MigrationError("An existing source identity changed size or INTERNALDATE.")
        candidates = sorted(k for k in by_key if k not in old or old[k]["state"] == "pending")
        payload = {"schema": 1, "config_sha256": self.config.digest,
                   "observed_at": inventory["observed_at"], "folders": folders,
                   "entries": [by_key[k].to_dict() for k in candidates], "candidates": candidates,
                   "source_inventory_sha256": sha(encoded(inventory)),
                   "known_owner_count": len(old), "known_identity_sha256": sha(encoded(sorted(old)))}
        digest = sha(encoded(payload))
        if len(encoded(payload)) > 256 * 1024 * 1024:
            raise MigrationError("Plan exceeds the explicit 256-MiB metadata limit; no plan published.")
        path = self.directory / "plans" / f"plan-{digest}.json"
        # A new observation must not overwrite a previous generation.
        file_hash = write_new(path, payload, mode=0o400)
        with self.db:
            self.db.execute("INSERT INTO plans VALUES (?,?)", (digest, encoded(payload).decode()))
            for f in folders:
                self.db.execute("INSERT OR IGNORE INTO folders VALUES (?,?)", (f["name"], f["uidvalidity"]))
            for key, spec in by_key.items():
                if key not in old:
                    self.db.execute("INSERT INTO occurrences VALUES (?,?, 'pending',NULL,NULL,NULL,?,?)",
                                    (key, encoded(spec.to_dict()).decode(), digest, digest))
                else:
                    self.db.execute("UPDATE occurrences SET last_seen=? WHERE key=?", (digest, key))
                self.db.execute("INSERT INTO observations VALUES (?,?,1,?)", (digest, key, encoded(spec.to_dict()).decode()))
            for key, row in old.items():
                if key not in by_key:
                    self.db.execute("INSERT INTO observations VALUES (?,?,0,NULL)", (digest, key))
                    if row["state"] == "pending":
                        self.db.execute("UPDATE occurrences SET state='held',error='source_absent_during_plan' WHERE key=?", (key,))
        return path, file_hash, payload

    def load_plan(self, path, file_hash):
        self.check()
        path = Path(path).expanduser().absolute()
        if path.parent != self.directory / "plans" or not file_hash or len(file_hash) != 64:
            raise MigrationError("Provide the exact job plan and --plan-sha256 printed during planning.")
        raw = private_read(path, limit=256 * 1024 * 1024, modes=(0o400,))
        if sha(raw) != file_hash:
            raise MigrationError("Immutable plan byte hash differs.")
        plan = strict_json(raw)
        digest = sha(encoded(plan))
        row = self.db.execute("SELECT body FROM plans WHERE digest=?", (digest,)).fetchone()
        if (path.name != f"plan-{digest}.json" or row is None or row[0] != encoded(plan).decode()
                or plan.get("config_sha256") != self.config.digest):
            raise MigrationError("Plan is not an enrolled generation for this account pair.")
        return plan

    def hold(self, key, reason):
        self.check()
        with self.db:
            changed = self.db.execute("UPDATE occurrences SET state='held',error=? WHERE key=? AND state='pending'", (reason, key)).rowcount
            if changed != 1:
                raise MigrationError("Only a pending source occurrence may become a hold.")

    def posting(self, key, baseline):
        self.check()
        with self.db:
            if self.db.execute("UPDATE occurrences SET state='posting',baseline=? WHERE key=? AND state='pending'",
                               (encoded(baseline).decode(), key)).rowcount != 1:
                raise MigrationError("Occurrence is no longer pending; never repost.")

    def acknowledge(self, key, ack):
        # Intentionally NO lock/clock/alias/callback/readback check before commit.
        receipt = {"key": ack.key, "selector": ack.selector}
        try:
            with self.db:
                if self.db.execute("UPDATE occurrences SET state='created',receipt=? WHERE key=? AND state='posting'",
                                   (encoded(receipt).decode(), key)).rowcount != 1:
                    raise MigrationError("ACK row changed unexpectedly.")
            # Only AFTER the first durable commit: detect an accidental file
            # replacement and retain an independent receipt before stopping.
            info = self.path.lstat()
            if (info.st_dev, info.st_ino) != self.database_identity:
                raise MigrationError("ACK committed to a detached ledger.")
        except BaseException:
            write_new(self.directory / f"emergency-ack-{uuid.uuid4().hex}.json",
                      {"source_key": key, "receipt": receipt, "config_sha256": self.config.digest,
                       "manual_reconciliation_required": True})
            raise UncertainWrite("Returned ACK saved in an emergency receipt; no automatic retry.") from None

    def uncertain(self, key):
        with self.db:
            self.db.execute("UPDATE occurrences SET state='uncertain',error='unacknowledged_write' WHERE key=? AND state='posting'", (key,))

    def verified(self, key):
        self.check()
        with self.db:
            if self.db.execute("UPDATE occurrences SET state='verified' WHERE key=? AND state='created'", (key,)).rowcount != 1:
                raise MigrationError("Readback must refer to a saved created receipt.")

    def receipt_unique(self, key, ack):
        if not isinstance(ack.key, str) or not ack.key.strip():
            raise MigrationError("Malformed ACK retained; no subsequent writes.")
        for row in self.rows(("created", "verified")):
            if row["key"] != key and strict_json(row["receipt"])["key"] == ack.key:
                raise MigrationError("Returned ACK aliases another copy; both receipts retained.")

    def report(self, value):
        self.check()
        path = self.directory / "reports" / f"report-{uuid.uuid4().hex}.json"
        write_new(path, value)
        return path

    def status(self):
        rows = self.rows()
        counts = Counter(r["state"] for r in rows)
        emergency = len(list(self.directory.glob("emergency-ack-*.json")))
        return {"states": dict(counts), "total_occurrences": len(rows),
                "held": [{"key": r["key"], "reason": r["error"], "spec": strict_json(r["spec"])} for r in rows if r["state"] == "held"],
                "unresolved_writes": counts["posting"] + counts["uncertain"] + counts["created"] + emergency,
                "emergency_receipts_requiring_review": emergency,
                "plan_generations": self.db.execute("SELECT COUNT(*) FROM plans").fetchone()[0]}

    def __exit__(self, *args):
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            if self.lock is not None:
                self.lock.__exit__(*args)
                self.lock = None
