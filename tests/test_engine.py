import copy
import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import patch

from mail_migrator.engine import Migration
from mail_migrator.errors import Hold, MigrationError, UncertainWrite
from mail_migrator.models import Ack, Occurrence
from mail_migrator.security import Deadline, encoded, private_read, sha, strict_json
from mail_migrator.state import State
from tests.helpers import (DATE, FakeDestination, FakeSource, OfflineTest, job,
                           occurrence, raw_message)


class EngineTests(OfflineTest):
    def prepare(self, state, source=None, destination=None, deadline=None):
        source, destination = source or FakeSource(), destination or FakeDestination()
        runner = Migration(state, source, destination, deadline or Deadline())
        plan = runner.plan()
        return runner, source, destination, plan

    def apply(self, runner, plan, **kwargs):
        return runner.migrate(plan["plan"], plan["plan_sha256"], apply=True, **kwargs)

    def test_plan_has_no_destination_writes_or_raw_mail(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, destination, plan = self.prepare(state)
            self.assertEqual(destination.posts, [])
            self.assertEqual(source.reads, [])
            raw = Path(plan["plan"]).read_bytes()
            self.assertNotIn(b"Synthetic fixture", raw)
            self.assertNotIn(b"sender@example.test", raw)
            self.assertEqual(plan["candidate_occurrences"], 1)

    def test_apply_flag_required(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            with self.assertRaises(MigrationError):
                runner.migrate(plan["plan"], plan["plan_sha256"])
            self.assertFalse(dest.posts)

    def test_first_real_proof_is_one_even_with_larger_limit(self):
        items = [(occurrence(i), raw_message()) for i in range(1, 4)]
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state, FakeSource(items))
            result = self.apply(runner, plan, limit=99)
            self.assertTrue(result["first_proof_limited_to_one"])
            self.assertEqual(len(dest.posts), 1)
            self.assertEqual(state.status()["states"], {"verified": 1, "pending": 2})
            self.apply(runner, plan)
            self.assertEqual(len(dest.posts), 3)
            self.assertEqual(state.status()["states"], {"verified": 3})

    def test_rerun_never_reposts_verified(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            self.apply(runner, plan)
            self.apply(runner, plan)
            self.assertEqual(len(dest.posts), 1)

    def test_resume_after_closing_reuses_original_id(self):
        dest = FakeDestination()
        with State(self.state_dir, job(), create=True) as state:
            runner, _, _, plan = self.prepare(state, destination=dest)
            self.apply(runner, plan)
            row = state.rows()[0]
        with State(self.state_dir) as state:
            runner = Migration(state, FakeSource(), dest, Deadline())
            self.apply(runner, plan)
            self.assertEqual(row, state.rows()[0])
            self.assertEqual(len(dest.posts), 1)

    def test_wrong_plan_hash_refused_before_fetch_or_post(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            with self.assertRaises(MigrationError):
                runner.migrate(plan["plan"], "0" * 64, apply=True)
            self.assertEqual((source.reads, dest.posts), ([], []))

    def test_changed_configuration_refused(self):
        with State(self.state_dir, job(), create=True):
            pass
        with self.assertRaises(MigrationError):
            with State(self.state_dir, job(mapping={"INBOX": "Other"}), create=True):
                pass

    def test_library_transports_must_match_frozen_accounts(self):
        from mail_migrator.models import Endpoint
        with State(self.state_dir, job(), create=True) as state:
            source, destination = FakeSource(), FakeDestination()
            source.endpoint = Endpoint("wrong.example.test", "source@example.test")
            with self.assertRaises(MigrationError):
                Migration(state, source, destination, Deadline())
            source = FakeSource()
            destination.endpoint = Endpoint("wrong.example.test", "destination@example.test")
            with self.assertRaises(MigrationError):
                Migration(state, source, destination, Deadline())
            self.assertFalse(source.reads or destination.posts)

    def test_corrupt_saved_baseline_refused_readonly_before_provider(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, _, plan = self.prepare(state)
            self.apply(runner, plan)
            baseline = strict_json(state.rows()[0]["baseline"])
            baseline["raw_sha256"] = "not-a-fingerprint"
            with state.db:
                state.db.execute("UPDATE occurrences SET baseline=?", (encoded(baseline).decode(),))
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass

    def test_late_ack_is_created_before_deadline_check(self):
        clock = [0]
        deadline = Deadline(10, clock=lambda: clock[0])
        dest = FakeDestination()
        dest.after_insert = lambda: clock.__setitem__(0, 11)
        with State(self.state_dir, job(), create=True) as state:
            runner, _, _, plan = self.prepare(state, destination=dest, deadline=deadline)
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            row = state.rows()[0]
            self.assertEqual(row["state"], "created")
            self.assertIsNotNone(row["receipt"])
            self.assertEqual(dest.gets, [])

    def test_cooperative_stop_after_ack_preserves_id(self):
        deadline = Deadline()
        dest = FakeDestination()
        dest.after_insert = deadline.stop
        with State(self.state_dir, job(), create=True) as state:
            runner, _, _, plan = self.prepare(state, destination=dest, deadline=deadline)
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "created")

    def test_ack_alias_saved_before_refusal(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state, FakeSource([(occurrence(i), raw_message()) for i in (1, 2)]))
            self.apply(runner, plan)
            receipt = strict_json(state.rows()[0]["receipt"])
            dest.forced_ack = Ack(**receipt)
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(CounterStates(state), {"created": 1, "verified": 1})
            self.assertEqual(len({r["receipt"] for r in state.rows()}), 1)
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass

    def test_whitespace_ack_saved_before_refusal(self):
        with State(self.state_dir, job(), create=True) as state:
            dest = FakeDestination()
            dest.forced_ack = Ack(" ", {})
            runner, _, _, plan = self.prepare(state, destination=dest)
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(strict_json(state.rows()[0]["receipt"])["key"], " ")
            self.assertEqual(state.rows()[0]["state"], "created")

    def test_lost_ack_blocks_all_retries_and_planning(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            dest.lost_ack = True
            with self.assertRaises(UncertainWrite):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "uncertain")
            with self.assertRaises(UncertainWrite):
                self.apply(runner, plan)
            with self.assertRaises(UncertainWrite):
                runner.plan()
            self.assertEqual(len(dest.posts), 1)

    def test_failed_get_resumes_only_known_id(self):
        dest = FakeDestination()
        with State(self.state_dir, job(), create=True) as state:
            runner, source, _, plan = self.prepare(state, destination=dest)
            dest.fail_readback = True
            with self.assertRaises(OSError):
                self.apply(runner, plan)
            baseline = state.rows()[0]["baseline"]
            self.assertEqual(state.rows()[0]["state"], "created")
            dest.fail_readback = False
            self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["baseline"], baseline)
            self.assertEqual(len(dest.posts), 1)
            self.assertEqual(len(source.reads), 1)

    def test_wrong_body_retains_created_receipt(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            dest.bad_readback = True
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "created")

    def test_invalid_mime_held_before_post(self):
        invalid = raw_message().replace(b"Content-Transfer-Encoding: 7bit", b"Content-Transfer-Encoding: base64").replace(
            b"Only synthetic test content.\r\n", b"YQ\r\n")
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state, FakeSource([(occurrence(raw=invalid), invalid)]))
            self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "held")
            self.assertFalse(dest.posts)

    def test_hold_skipped_not_cleared_on_rerun(self):
        with State(self.state_dir, job(max_message_bytes=1), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            self.apply(runner, plan)
            hold = state.rows()[0]
            self.apply(runner, plan)
            self.assertEqual(state.rows()[0], hold)
            self.assertFalse(source.reads or dest.posts)

    def test_exact_confirmed_source_absence_is_held(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            source.missing.add(occurrence().key)
            self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["error"], "source_absent_before_copy")
            self.assertFalse(dest.posts)

    def test_protocol_failure_not_absence(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, _, plan = self.prepare(state)
            source.protocol_error = True
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "pending")

    def test_refresh_failure_before_posting_is_not_uncertain(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            dest.prepare_error = True
            with self.assertRaises(RuntimeError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "pending")
            self.assertFalse(dest.posts)

    def test_source_flags_snapshot_and_actual_copy_baseline_both_retained(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, _, plan = self.prepare(state)
            updated = occurrence(flags=(r"\Seen", r"\Flagged"))
            source.items[updated.key] = (updated, raw_message())
            self.apply(runner, plan)
            row = state.rows()[0]
            baseline = strict_json(row["baseline"])
            self.assertEqual(baseline["snapshot_flags"], [])
            self.assertEqual(baseline["copied_read_star"], {"read": True, "starred": True})
            self.assertEqual(strict_json(row["spec"])["flags"], [])

    def test_destination_user_flag_conflict_reported_never_modified(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            self.apply(runner, plan)
            before = copy.deepcopy(state.rows()[0])
            dest.user_flag_edit = True
            result = runner.verify()
            self.assertTrue(result["verified"][0]["destination_user_flag_conflict_preserved"])
            self.assertEqual(before, state.rows()[0])

    def test_delta_compact_and_prior_receipt_bytes_preserved(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, first = self.prepare(state)
            self.apply(runner, first)
            before = copy.deepcopy(state.rows()[0])
            second = occurrence(2)
            source.items[second.key] = (second, raw_message())
            plan = runner.plan()
            payload = strict_json(private_read(plan["plan"]))
            self.assertEqual(len(payload["entries"]), 1)
            self.assertEqual(payload["entries"][0]["uid"], 2)
            self.assertNotIn("ancestors", payload)
            self.assertNotIn("receipt", encoded(payload).decode())
            self.apply(runner, plan)
            self.assertEqual(before, {**state.rows()[0], "last_seen": before["last_seen"]})
            self.assertEqual(len(dest.posts), 2)

    def test_new_plan_preserves_absent_pending_as_recovery_hold(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, _, first = self.prepare(state)
            source.missing.add(occurrence().key)
            runner.plan()
            self.assertEqual(state.rows()[0]["state"], "held")
            self.assertEqual(state.rows()[0]["error"], "source_absent_during_plan")
            self.assertEqual(state.db.execute("SELECT COUNT(*) FROM observations WHERE present=0").fetchone()[0], 1)

    def test_identical_content_in_two_folders_is_two_occurrences(self):
        source = FakeSource([(occurrence(folder=f), raw_message()) for f in ("INBOX", "Archive")])
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state, source)
            self.apply(runner, plan)
            self.apply(runner, plan)
            self.assertEqual(len(dest.posts), 2)
            self.assertEqual(len({r["receipt"] for r in state.rows()}), 2)

    def test_native_sent_aliases_allowed_custom_merges_refused(self):
        source = FakeSource([(occurrence(folder=f), raw_message()) for f in ("Sent", "Sent Messages")])
        with State(self.state_dir, job("gmail", mapping={"Sent": "SENT", "Sent Messages": "SENT"}), create=True) as state:
            _, _, _, plan = self.prepare(state, source, FakeDestination("gmail"))
            self.assertEqual(plan["candidate_occurrences"], 2)
        with State(self.root / "different", job(mapping={"Sent": "Archive", "Sent Messages": "Archive"}), create=True) as state:
            with self.assertRaises(MigrationError):
                self.prepare(state, source)

    def test_empty_or_malformed_existing_ledger_never_reseeded(self):
        with State(self.state_dir, job(), create=True):
            pass
        path = self.state_dir / "ledger.sqlite3"
        for body in (b"", b"not a database"):
            path.write_bytes(body)
            with self.assertRaises(MigrationError):
                with State(self.state_dir, job(), create=True):
                    pass
            self.assertEqual(path.read_bytes(), body)

    def test_unknown_existing_state_refused(self):
        with State(self.state_dir, job(), create=True) as state:
            self.prepare(state)
            with state.db:
                state.db.execute("UPDATE occurrences SET state='mystery'")
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass

    def test_wal_sidecar_refused(self):
        with State(self.state_dir, job(), create=True):
            pass
        (self.state_dir / "ledger.sqlite3-wal").write_bytes(b"synthetic")
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass

    def test_orphan_plan_not_silently_forgotten(self):
        with State(self.state_dir, job(), create=True):
            pass
        (self.state_dir / "plans" / "unregistered.json").write_text("{}")
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass

    def test_emergency_receipt_fences_provider_work_even_if_rows_look_safe(self):
        from mail_migrator.security import write_new
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            write_new(self.state_dir / "emergency-ack-synthetic.json", {"review_required": True})
            with self.assertRaises(UncertainWrite):
                self.apply(runner, plan)
            with self.assertRaises(UncertainWrite):
                runner.plan()
            self.assertEqual(state.status()["emergency_receipts_requiring_review"], 1)
            self.assertFalse(source.reads or dest.posts)

    def test_replaced_ledger_detected_before_provider_work(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            original = state.path.read_bytes()
            state.path.rename(self.state_dir / "old-ledger-evidence.sqlite3")
            state.path.write_bytes(original)
            state.path.chmod(0o600)
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertFalse(source.reads or dest.posts)

    def test_unknown_existing_schema_refused_without_changing_bytes(self):
        with State(self.state_dir, job(), create=True) as state:
            with state.db:
                state.db.execute("CREATE TABLE unexpected(value TEXT)")
        path = self.state_dir / "ledger.sqlite3"
        before = path.read_bytes()
        with self.assertRaises(MigrationError):
            with State(self.state_dir):
                pass
        self.assertEqual(path.read_bytes(), before)

    def test_sqlite_full_sync_and_one_writer(self):
        with State(self.state_dir, job(), create=True) as state:
            self.assertEqual(state.db.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(state.db.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            with self.assertRaises(MigrationError):
                with State(self.state_dir):
                    pass

    def test_changed_uidvalidity_refused_without_rewriting_old_spec(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, _, _ = self.prepare(state)
            before = copy.deepcopy(state.rows())
            spec = occurrence()
            moved = Occurrence(spec.folder, 99, spec.uid, spec.bytes, spec.flags, spec.internal_date)
            source.items = {moved.key: (moved, raw_message())}
            with self.assertRaises(MigrationError):
                runner.plan()
            self.assertEqual(before, state.rows())

    def test_plan_private_modes(self):
        with State(self.state_dir, job(), create=True) as state:
            _, _, _, plan = self.prepare(state)
            self.assertEqual(self.state_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(plan["plan"]).stat().st_mode & 0o777, 0o400)
            self.assertEqual(state.path.stat().st_mode & 0o777, 0o600)

    def test_inconsistent_folder_metadata_refused_before_enrollment(self):
        with State(self.state_dir, job(), create=True) as state:
            inventory = FakeSource().inventory(job(), state.report)
            inventory["folders"][0]["uidvalidity"] = 99
            with self.assertRaises(MigrationError):
                state.accept_inventory(inventory)
            self.assertEqual(state.rows(), [])
            self.assertEqual(list((self.state_dir / "plans").iterdir()), [])

    def test_transport_identity_rechecked_before_posting(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, source, dest, plan = self.prepare(state)
            source.items[occurrence().key] = (occurrence(99), raw_message())
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "pending")
            self.assertFalse(dest.posts)

    def test_first_proof_can_advance_past_prewrite_holds_but_only_one_post(self):
        draft = occurrence(1, flags=(r"\Draft",))
        items = [(draft, raw_message()), (occurrence(2), raw_message()), (occurrence(3), raw_message())]
        with State(self.state_dir, job("gmail"), create=True) as state:
            runner, _, dest, plan = self.prepare(state, FakeSource(items), FakeDestination("gmail"))
            result = self.apply(runner, plan)
            self.assertEqual(len(result["new_holds"]), 1)
            self.assertEqual(len(dest.posts), 1)
            self.assertEqual(CounterStates(state), {"held": 1, "pending": 1, "verified": 1})

    def test_empty_folders_created_only_during_explicit_apply(self):
        source = FakeSource([])
        with State(self.state_dir, job(create_folders=True), create=True) as state:
            runner, _, dest, plan = self.prepare(state, source)
            created = []
            dest.ensure = lambda target, **kwargs: created.append(target) or target
            self.assertEqual(created, [])
            self.apply(runner, plan)
            self.assertEqual(created, ["INBOX"])
            self.assertFalse(dest.posts)

    def test_gmail_engine_full_copy_and_resume(self):
        with State(self.state_dir, job("gmail"), create=True) as state:
            runner, _, dest, plan = self.prepare(state, destination=FakeDestination("gmail"))
            self.apply(runner, plan)
            baseline = state.rows()[0]["baseline"]
            self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "verified")
            self.assertEqual(state.rows()[0]["baseline"], baseline)
            self.assertEqual(len(dest.posts), 1)

    def test_created_user_flag_conflict_cannot_claim_first_proof(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            dest.user_flag_edit = True
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "created")
            self.assertEqual(len(dest.posts), 1)

    def test_late_readback_not_verified(self):
        clock = [0]
        deadline = Deadline(10, clock=lambda: clock[0])
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state, deadline=deadline)
            original_get = dest.get
            def late_get(*args):
                value = original_get(*args)
                clock[0] = 11
                return value
            dest.get = late_get
            with self.assertRaises(MigrationError):
                self.apply(runner, plan)
            self.assertEqual(state.rows()[0]["state"], "created")

    def test_ack_database_failure_creates_emergency_receipt(self):
        with State(self.state_dir, job(), create=True) as state:
            runner, _, dest, plan = self.prepare(state)
            original_db = state.db
            class FailAckCommit:
                def __getattr__(self, name):
                    return getattr(original_db, name)
                def __enter__(self):
                    original_db.__enter__()
                    return self
                def __exit__(self, *args):
                    return original_db.__exit__(*args)
                def execute(self, sql, *args):
                    if "SET state='created'" in sql:
                        raise sqlite3.OperationalError("Synthetic ACK persistence failure")
                    return original_db.execute(sql, *args)
            state.db = FailAckCommit()
            with self.assertRaises(UncertainWrite):
                self.apply(runner, plan)
            emergency = list(self.state_dir.glob("emergency-ack-*.json"))
            self.assertEqual(len(emergency), 1)
            self.assertTrue(strict_json(private_read(emergency[0]))["receipt"]["key"].startswith("imap:"))
            self.assertEqual(state.rows()[0]["state"], "posting")
            self.assertEqual(len(dest.posts), 1)
            state.db = original_db


def CounterStates(state):
    from collections import Counter
    return dict(Counter(r["state"] for r in state.rows()))
