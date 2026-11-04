"""Provider-independent orchestration; all copying is an explicit library call."""
from .errors import Hold, MigrationError, UncertainWrite
from .message import fingerprint, internal_timestamp, verify_content
from .models import Ack, Occurrence
from .security import strict_json


class Migration:
    def __init__(self, state, source, destination, deadline):
        if source is not None and getattr(source, "endpoint", None) != state.config.source:
            raise MigrationError("Source transport does not match the frozen job account.")
        if (getattr(destination, "endpoint", None) != state.config.destination
                or destination.kind != state.config.destination.kind):
            raise MigrationError("Destination transport does not match the frozen job account/backend.")
        self.state, self.source, self.destination, self.deadline = state, source, destination, deadline

    def gate(self):
        self.deadline.check()
        self.state.check()

    def plan(self):
        """Read both accounts, preserve observation evidence, accept one generation."""
        self.gate()
        self.state.refuse_uncertain(include_created=True)
        if self.source is None:
            raise MigrationError("Planning requires the selected source transport.")
        inventory = self.source.inventory(self.state.config, self.state.report)
        targets = [self.state.config.target(f["name"]) for f in inventory["folders"]]
        grouped = {}
        for folder, target in zip(inventory["folders"], targets):
            grouped.setdefault(target, []).append(folder["name"])
        # Native Gmail Sent/etc can be shared by legacy special folders. Other
        # merges would flatten organization, so they are not silently accepted.
        shared_native = {"INBOX", "SENT", "TRASH", "SPAM", "IMPORTANT"}
        if any(len(folders) > 1 and not (self.destination.kind == "gmail" and target in shared_native)
               for target, folders in grouped.items()):
            raise MigrationError("Multiple source folders would merge into a non-native target.")
        missing = self.destination.preflight(targets, create=self.state.config.create_folders)
        self.gate()
        path, digest, plan = self.state.accept_inventory(inventory)
        return {"mode": "plan", "destination_writes": 0, "plan": str(path), "plan_sha256": digest,
                "candidate_occurrences": len(plan["candidates"]),
                "candidate_bytes": sum(e["bytes"] for e in plan["entries"]),
                "source_occurrences": len(inventory["entries"]), "missing_destination_folders": missing,
                "status": self.state.status()}

    def verify_row(self, row, *, newly_created=False):
        self.gate()
        receipt, baseline = strict_json(row["receipt"]), strict_json(row["baseline"])
        ack = Ack(receipt["key"], receipt["selector"])
        self.state.receipt_unique(row["key"], ack)
        value = self.destination.get(ack, baseline)
        self.gate()  # Late reads do not establish fresh verification.
        verify_content(value["raw"], baseline, self.destination.kind)
        if value["date_ms"] != baseline["destination_date_ms"]:
            raise MigrationError("Destination chronology differs from the immutable copied baseline.")
        if self.destination.kind == "gmail":
            if baseline["destination_target"] not in value["labels"]:
                raise MigrationError("Destination Gmail folder label missing.")
        elif value["placement"] != baseline["destination_target"]:
            raise MigrationError("Destination IMAP placement differs.")
        conflict = value["read_star"] != baseline["copied_read_star"]
        if self.destination.kind == "imap":
            original_flags = {f.casefold() for f in baseline["copied_flags"]}
            current_flags = {f.casefold() for f in value["flags"] if f.casefold() != r"\recent"}
            extra_drift = original_flags - {r"\seen", r"\flagged"} != current_flags - {r"\seen", r"\flagged"}
            if extra_drift:
                raise MigrationError("Destination IMAP flags differ beyond read/star user changes.")
        if conflict and newly_created:
            raise MigrationError("Created copy has a read/star conflict; retain its ID for review, never repost.")
        if row["state"] == "created":
            self.state.verified(row["key"])
        return {"key": row["key"], "receipt": receipt, "content_and_chronology_verified": True,
                "destination_user_flag_conflict_preserved": conflict}

    def migrate(self, plan_path, plan_sha256, *, apply=False, limit=None):
        if not apply:
            raise MigrationError("Copying requires explicit --apply.")
        if limit is not None and (type(limit) is not int or limit <= 0):
            raise MigrationError("Limit must be a positive pending-attempt count.")
        self.gate()
        self.state.refuse_uncertain()
        plan = self.state.load_plan(plan_path, plan_sha256)
        members = set(plan["candidates"])
        rows = self.state.rows()
        first_proof = not any(r["state"] == "verified" for r in rows)
        selected = [r for r in rows if r["state"] == "created"]
        selected += [r for r in rows if r["state"] == "pending" and r["key"] in members]
        maximum = limit or len(selected)
        result = {"mode": "migrate", "new_copies": 0, "verified": [], "new_holds": [],
                  "first_proof_limited_to_one": first_proof, "source_writes": 0, "sends": 0}
        try:
            if self.state.config.create_folders:
                for folder in plan["folders"]:
                    if folder["messages"] == 0:
                        self.gate()
                        self.destination.ensure(self.state.config.target(folder["name"]), create=True)
            for row in selected[:maximum]:
                self.gate()
                self.state.load_plan(plan_path, plan_sha256)
                if row["state"] == "created":
                    result["verified"].append(self.verify_row(row, newly_created=True))
                    if first_proof:
                        break
                    continue
                spec = Occurrence.from_dict(strict_json(row["spec"]))
                try:
                    if spec.bytes > self.state.config.max_message_bytes:
                        raise Hold("message_exceeds_selected_size_limit")
                    if spec.bytes > getattr(self.destination, "max_message_bytes", self.state.config.max_message_bytes):
                        raise Hold("message_exceeds_destination_size_limit")
                    fetched = self.source.read(spec, confirm_absence=True, max_bytes=spec.bytes)
                    if fetched is None:
                        raise Hold("source_absent_before_copy")
                    actual, raw = fetched
                    if ((actual.folder, actual.uidvalidity, actual.uid, actual.bytes) !=
                            (spec.folder, spec.uidvalidity, spec.uid, spec.bytes)
                            or type(raw) is not bytes or len(raw) != spec.bytes
                            or internal_timestamp(actual.internal_date) != internal_timestamp(spec.internal_date)):
                        raise MigrationError("Transport returned a different source identity, size or date.")
                    baseline = fingerprint(raw, actual, self.destination.kind)
                    if hasattr(self.destination, "validate_source"):
                        self.destination.validate_source(raw, actual)
                except Hold as error:
                    self.state.hold(row["key"], str(error))
                    result["new_holds"].append({"key": row["key"], "reason": str(error)})
                    continue
                target = self.destination.ensure(self.state.config.target(spec.folder), create=self.state.config.create_folders)
                baseline.update(destination_target=target, source_bytes=len(raw),
                                source_internal_date=actual.internal_date, snapshot_flags=list(spec.flags))
                self.destination.prepare()  # Refresh/preflight BEFORE marking a POST attempt.
                self.gate()
                self.state.posting(row["key"], baseline)
                try:
                    ack = self.destination.insert(raw, target, actual, baseline)
                except BaseException:
                    self.state.uncertain(row["key"])
                    raise UncertainWrite("Write was not acknowledged. No automatic retry; retain the state.") from None
                # Nothing may check time, lease, aliases, hooks or GET before this.
                self.state.acknowledge(row["key"], ack)
                result["new_copies"] += 1
                self.gate()
                self.state.receipt_unique(row["key"], ack)
                saved = next(r for r in self.state.rows(("created",)) if r["key"] == row["key"])
                result["verified"].append(self.verify_row(saved, newly_created=True))
                if first_proof:
                    break  # At most one real copy before a subsequent invocation.
            result["status"] = "bounded_pass_finished_not_complete" if self.state.status()["held"] else "bounded_pass_finished"
            return result
        except BaseException as error:
            result["status"] = "stopped_retain_receipts_no_retry"
            result["error_type"] = type(error).__name__
            raise
        finally:
            result["checkpoint"] = self.state.status()
            self.state.report(result)

    def verify(self, *, limit=None):
        if limit is not None and (type(limit) is not int or limit <= 0):
            raise MigrationError("Limit must be positive.")
        self.gate()
        self.state.refuse_uncertain()
        rows = self.state.rows(("created",)) + self.state.rows(("verified",))
        result = {"mode": "verify", "destination_writes": 0, "verified": []}
        try:
            for row in rows[:limit]:
                result["verified"].append(self.verify_row(row, newly_created=row["state"] == "created"))
            return result
        finally:
            self.state.report(result)
