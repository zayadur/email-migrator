import contextlib
import io
import json
from unittest.mock import patch

from mail_migrator.cli import main
from mail_migrator.errors import MigrationError
from mail_migrator.security import WriterLock, write_new
from tests.helpers import FakeDestination, FakeSource, OfflineTest


class CLITests(OfflineTest):
    def setUp(self):
        super().setUp()
        self.source, self.destination = FakeSource(), FakeDestination()
        self.credentials = self.root / "private.json"
        write_new(self.credentials, {"password": "synthetic-secret-not-for-output"})

    def run_cli(self, args):
        out, error = io.StringIO(), io.StringIO()
        with patch("mail_migrator.cli.IMAPSource", return_value=self.source), \
                patch("mail_migrator.cli.IMAPDestination", return_value=self.destination), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
            code = main(args)
        self.assertNotIn("synthetic-secret-not-for-output", out.getvalue() + error.getvalue())
        return code, out.getvalue(), error.getvalue()

    def plan_args(self):
        return ["plan", "--state", str(self.state_dir),
                "--source-host", "source.example.test", "--source-user", "source@example.test",
                "--destination-type", "imap", "--destination-host", "dest.example.test",
                "--destination-user", "destination@example.test", "--source-credentials", str(self.credentials),
                "--destination-credentials", str(self.credentials)]

    def test_cli_plan_apply_verify_status_with_explicit_credential_files(self):
        code, output, error = self.run_cli(self.plan_args())
        self.assertEqual((code, error), (0, ""))
        plan = json.loads(output)
        self.assertEqual(self.destination.posts, [])
        code, output, error = self.run_cli(["migrate", "--apply", "--state", str(self.state_dir),
                "--plan", plan["plan"], "--plan-sha256", plan["plan_sha256"],
                "--source-credentials", str(self.credentials), "--destination-credentials", str(self.credentials)])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["new_copies"], 1)
        code, output, error = self.run_cli(["verify", "--state", str(self.state_dir),
                                          "--destination-credentials", str(self.credentials)])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["verified_this_run"], 1)
        code, output, error = self.run_cli(["status", "--state", str(self.state_dir)])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["states"], {"verified": 1})
        self.assertEqual(len(self.destination.posts), 1)
        for path in self.state_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"synthetic-secret-not-for-output", path.read_bytes())

    def test_cli_frozen_policy_not_overridden_during_resume(self):
        code, _, _ = self.run_cli(self.plan_args())
        self.assertEqual(code, 0)
        code, _, _ = self.run_cli(["migrate", "--apply", "--state", str(self.state_dir), "--create-folders"])
        self.assertEqual(code, 2)
        self.assertFalse(self.destination.posts)

    def test_client_cleanup_on_constructor_failure_still_holds_job_lock(self):
        observed = []
        def close_source():
            try:
                with WriterLock(self.state_dir):
                    observed.append("unlocked-too-soon")
            except MigrationError:
                observed.append("locked")
        self.source.close = close_source
        with patch("mail_migrator.cli.IMAPSource", return_value=self.source), \
                patch("mail_migrator.cli.IMAPDestination", side_effect=RuntimeError("Synthetic constructor failure")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(self.plan_args()), 1)
        self.assertEqual(observed, ["locked"])
