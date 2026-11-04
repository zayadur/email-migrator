import contextlib
import copy
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

from mail_migrator.cli import main
from mail_migrator.credentials import Credentials, load_credentials
from mail_migrator.errors import Hold, MigrationError
from mail_migrator.message import fingerprint, internal_timestamp, parse, verify_content
from mail_migrator.models import Endpoint, Occurrence
from mail_migrator.security import Deadline, private_read, strict_json, write_new
from tests.helpers import OfflineTest, occurrence, raw_message


class MessageTests(OfflineTest):
    def test_imap_exact_raw_and_attachment_fingerprints(self):
        raw = raw_message(attachment=True)
        baseline = fingerprint(raw, occurrence(raw=raw), "imap")
        verify_content(raw, baseline, "imap")
        self.assertNotIn("content", baseline)
        self.assertNotIn("Synthetic fixture", json.dumps(baseline))
        self.assertNotIn("fixture.bin", json.dumps(baseline))
        with self.assertRaises(MigrationError):
            verify_content(raw.replace(b"fixture.bin", b"changed.bin"), baseline, "imap")

    def test_gmail_hash_survives_json_baseline_roundtrip(self):
        raw = raw_message(attachment=True)
        baseline = strict_json(json.dumps(fingerprint(raw, occurrence(raw=raw), "gmail")))
        verify_content(raw, baseline, "gmail")

    def test_exact_one_gmail_received_prefix_accepted(self):
        raw = raw_message()
        prefix = b"Received: by gmailapi.google.com with HTTPREST; Wed, 04 Nov 2026 12:01:00 +0000\r\n"
        baseline = fingerprint(raw, occurrence(), "gmail")
        verify_content(prefix + raw, baseline, "gmail")
        for invalid in (prefix + prefix + raw, prefix.replace(b"gmailapi.google.com", b"other.example.test") + raw):
            with self.assertRaises(MigrationError):
                verify_content(invalid, baseline, "gmail")

    def test_new_nonreceived_header_refused(self):
        raw = raw_message()
        baseline = fingerprint(raw, occurrence(), "gmail")
        with self.assertRaises(MigrationError):
            verify_content(b"X-Added: changed\r\n" + raw, baseline, "gmail")

    def test_gmail_payload_change_not_hidden_by_trace(self):
        raw = raw_message()
        baseline = fingerprint(raw, occurrence(), "gmail")
        prefix = b"Received: by gmailapi.google.com with HTTPREST; Wed, 04 Nov 2026 12:01:00 +0000\r\n"
        with self.assertRaises(MigrationError):
            verify_content(prefix + raw.replace(b"Only synthetic", b"Different data"), baseline, "gmail")

    def test_nested_mime_headers_are_part_of_fingerprint(self):
        raw = raw_message(attachment=True)
        source = raw.replace(b'Content-Disposition: attachment;', b'Content-Description: Original\r\nContent-Disposition: attachment;')
        baseline = fingerprint(source, occurrence(raw=source), "gmail")
        with self.assertRaises(MigrationError):
            verify_content(source.replace(b"Content-Description: Original", b"Content-Description: Altered!"), baseline, "gmail")

    def test_nested_encoding_change_not_allowed_even_for_same_decoded_body(self):
        raw = raw_message(attachment=True)
        baseline = fingerprint(raw, occurrence(raw=raw), "gmail")
        # The text part's payload is ASCII, so 7bit -> 8bit changes no decoded
        # bytes. It is still a MIME-header rewrite and must be refused.
        with self.assertRaises(MigrationError):
            verify_content(raw.replace(b"Content-Transfer-Encoding: 7bit", b"Content-Transfer-Encoding: 8bit", 1), baseline, "gmail")

    def test_base64_deferred_defects_held(self):
        source = raw_message().replace(b"Content-Transfer-Encoding: 7bit", b"Content-Transfer-Encoding: base64")
        for payload in (b"YQ", b"Y#Q==", b"Y"):
            raw = source.replace(b"Only synthetic test content.", payload)
            with self.subTest(payload=payload), self.assertRaises(Hold):
                parse(raw)

    def test_bare_lf_not_implicitly_normalized(self):
        with self.assertRaises(Hold):
            parse(raw_message().replace(b"\r\n", b"\n"))

    def test_gmail_missing_date_held_imap_can_preserve(self):
        raw = raw_message().replace(b"Date: Wed, 04 Nov 2026 12:00:00 +0000\r\n", b"")
        fingerprint(raw, occurrence(raw=raw), "imap")
        with self.assertRaises(Hold):
            fingerprint(raw, occurrence(raw=raw), "gmail")

    def test_gmail_missing_and_duplicate_id_held(self):
        raw = raw_message()
        for value in (raw.replace(b"Message-ID: <fixture@example.test>\r\n", b""),
                      b"Message-ID: <second@example.test>\r\n" + raw):
            with self.assertRaises(Hold):
                fingerprint(value, occurrence(raw=value), "gmail")

    def test_deleted_held_and_drafts_not_downgraded_in_gmail(self):
        with self.assertRaises(Hold):
            fingerprint(raw_message(), occurrence(flags=(r"\Deleted",)), "imap")
        with self.assertRaises(Hold):
            fingerprint(raw_message(), occurrence(flags=(r"\Draft",)), "gmail")
        fingerprint(raw_message(), occurrence(flags=(r"\Draft",)), "imap")

    def test_recent_not_appended(self):
        baseline = fingerprint(raw_message(), occurrence(flags=(r"\Recent", r"\Seen", r"\Flagged")), "imap")
        self.assertEqual(baseline["copied_flags"], [r"\Flagged", r"\Seen"])

    def test_explicit_minus0000_is_utc_not_machine_local_time(self):
        raw = raw_message().replace(b"12:00:00 +0000", b"12:00:00 -0000")
        self.assertEqual(fingerprint(raw, occurrence(raw=raw), "gmail")["destination_date_ms"],
                         internal_timestamp("04-Nov-2026 12:00:00 +0000"))

    def test_timezone_less_date_held(self):
        raw = raw_message().replace(b"12:00:00 +0000", b"12:00:00")
        with self.assertRaises(Hold):
            fingerprint(raw, occurrence(raw=raw), "gmail")

    def test_internaldate_locale_independent_and_offset_equivalent(self):
        self.assertEqual(internal_timestamp("04-Nov-2026 12:00:00 +0000"), internal_timestamp(" 4-Nov-2026 17:30:00 +0530"))
        for invalid in ("04-Nope-2026 12:00:00 +0000", "04-Nov-2026 12:00:00 +9999", "32-Nov-2026 12:00:00 +0000"):
            with self.assertRaises(MigrationError):
                internal_timestamp(invalid)

    def test_invalid_flags_are_safe_errors(self):
        for flags in ((1,), (r"\Seen", r"\seen"), ("two flags",), ("bad)",)):
            with self.subTest(flags=flags), self.assertRaises(MigrationError):
                occurrence(flags=flags)


class SecurityAndCLITests(OfflineTest):
    def test_private_credentials_file_no_repr_leak(self):
        path = self.root / "credentials.json"
        write_new(path, {"password": "synthetic-private-password"})
        credentials = load_credentials(path=path)
        self.assertEqual(credentials.get("password"), "synthetic-private-password")
        self.assertNotIn("synthetic-private-password", repr(credentials))

    def test_only_explicit_env_name_is_used(self):
        with patch.dict(os.environ, {"SELECTED_SECRET": "synthetic", "PASSWORD": "ambient"}):
            self.assertEqual(load_credentials(env="SELECTED_SECRET").get("password"), "synthetic")
            with self.assertRaises(MigrationError):
                load_credentials()

    def test_missing_or_conflicting_credential_sources_refused(self):
        for kwargs in ({}, {"path": "a", "env": "b"}, {"env": "not a name"}):
            with self.assertRaises(MigrationError):
                load_credentials(**kwargs)

    def test_oauth_combined_json_is_explicit(self):
        value = {"client_id": "synthetic-client", "client_secret": "synthetic-secret", "refresh_token": "synthetic-refresh"}
        with patch.dict(os.environ, {"SELECTED_OAUTH": json.dumps(value)}):
            self.assertEqual(load_credentials(env="SELECTED_OAUTH", auth="gmail-oauth").get("refresh_token"), "synthetic-refresh")

    def test_nonobject_oauth_json_refused_and_values_immutable(self):
        with patch.dict(os.environ, {"SELECTED_OAUTH": "[]"}), self.assertRaises(MigrationError):
            load_credentials(env="SELECTED_OAUTH", auth="gmail-oauth")
        credentials = Credentials({"password": "synthetic"})
        with self.assertRaises(TypeError):
            credentials.values["password"] = "changed"

    def test_public_secret_file_refused(self):
        path = self.root / "public.json"
        path.write_text('{"password":"synthetic"}')
        path.chmod(0o644)
        with self.assertRaises(MigrationError):
            load_credentials(path=path)

    def test_symlink_and_hardlinked_files_refused(self):
        path = self.root / "private.json"
        write_new(path, {"password": "synthetic"})
        link = self.root / "link.json"
        link.symlink_to(path)
        with self.assertRaises(MigrationError):
            load_credentials(path=link)
        os.link(path, self.root / "hardlink.json")
        with self.assertRaises(MigrationError):
            load_credentials(path=path)

    def test_duplicate_json_and_nonfinite_values_refused(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(MigrationError):
                strict_json(value)

    def test_runtime_rejects_nan_infinite_negative(self):
        for value in (float("nan"), float("inf"), 0, -1, 86401, True):
            with self.assertRaises(MigrationError):
                Deadline(value)

    def test_cli_never_echoes_unsupported_password_flag_values(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = main(["--state", str(self.state_dir), "--source-password", "synthetic-never-echo"])
        self.assertEqual(code, 2)
        self.assertNotIn("synthetic-never-echo", output.getvalue())

    def test_cli_missing_apply_refused_without_state_or_network(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["migrate", "--state", str(self.state_dir)]), 2)
        self.assertFalse(self.state_dir.exists())

    def test_cli_default_plan_requires_explicit_endpoints(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--state", str(self.state_dir), "--dry-run"]), 2)
        self.assertFalse(self.state_dir.exists())

    def test_cli_help_and_version_require_no_credentials(self):
        for args in (["--help"], ["--version"]):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stop:
                main(args)
            self.assertEqual(stop.exception.code, 0)

    def test_gmail_endpoint_and_self_copy_are_restricted(self):
        with self.assertRaises(MigrationError):
            Endpoint("evil.example.test", "user@example.test", 443, "gmail-oauth", "gmail")
