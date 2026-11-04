import base64
import copy
import json
from types import SimpleNamespace

from mail_migrator.credentials import Credentials
from mail_migrator.errors import MigrationError, UncertainWrite
from mail_migrator.gmail import BASE, GmailDestination, NoRedirect
from mail_migrator.imap import (IMAPDestination, IMAPSource, decode_folder,
                                encode_folder, metadata, parse_list, quote_folder)
from mail_migrator.message import fingerprint, internal_timestamp
from mail_migrator.models import Ack, Endpoint
from mail_migrator.security import Deadline, encoded
from tests.helpers import DATE, OfflineTest, occurrence, raw_message


class FakeIMAP:
    def __init__(self):
        self.capabilities = (b"IMAP4rev1", b"UIDPLUS")
        self.calls = []
        self.items = {"INBOX": {1: (occurrence(), raw_message())}, "Empty": {}}
        self.folder = "INBOX"
        self.validity = 11
        self.append_response = [b"91 42"]
        self.fetch_failure = False
        self.search_failure = False
        self.drift = False
        self.nonsticky = False
        self.all_searches = 0

    def login(self, user, password):
        self.calls.append(("LOGIN", user))
        return "OK", [b"authenticated"]

    def authenticate(self, mechanism, callback):
        self.calls.append((mechanism, callback(None)))
        return "OK", [b"authenticated"]

    def logout(self):
        self.calls.append(("LOGOUT",))

    def capability(self):
        self.calls.append(("CAPABILITY",))
        return "OK", [b" ".join(self.capabilities)]

    def list(self):
        self.calls.append(("LIST",))
        return "OK", [b'(\\HasNoChildren) "/" ' + quote_folder(f) for f in self.items]

    def select(self, mailbox, readonly=False):
        if readonly is not True:
            raise AssertionError("Mutable SELECT is forbidden")
        self.folder = parse_list(b'() "/" ' + mailbox)["name"]
        self.calls.append(("EXAMINE", self.folder))
        return "OK", [str(len(self.items.get(self.folder, {}))).encode()]

    def response(self, name):
        if name == "UIDVALIDITY":
            return name, [str(self.validity).encode()]
        if name == "APPENDUID":
            return name, self.append_response
        if name == "UIDNOTSTICKY":
            return name, [b""] if self.nonsticky else [None]
        raise AssertionError("Unreviewed response code")

    def uid(self, command, *args):
        self.calls.append((command,) + args)
        items = self.items[self.folder]
        if command == "SEARCH":
            if self.search_failure:
                return "NO", [b"synthetic denied"]
            if args == (None, "ALL"):
                self.all_searches += 1
                uids = sorted(items)
                if self.drift and self.all_searches >= 3 and self.folder == "INBOX":
                    uids += [2]
                return "OK", [b" ".join(str(i).encode() for i in uids)]
            if args[:2] == (None, "UID"):
                return "OK", [str(args[2]).encode() if int(args[2]) in items else b""]
            raise AssertionError("Unexpected SEARCH")
        if command != "FETCH":
            raise AssertionError("Source mutation attempted")
        if self.fetch_failure:
            return "NO", [b"synthetic failure"]
        result = []
        for uid in [int(i) for i in args[0].split(",")]:
            if uid not in items:
                continue
            spec, raw = items[uid]
            flags = " ".join(spec.flags)
            prefix = f'1 (UID {uid} RFC822.SIZE {len(raw)} FLAGS ({flags}) INTERNALDATE "{spec.internal_date}"'.encode()
            if "BODY.PEEK[]" in args[1]:
                result.extend([(prefix + b" BODY[]<0> {" + str(len(raw)).encode() + b"}", raw), b")"])
            else:
                result.append(prefix + b")")
        return "OK", result or [None]

    def append(self, folder, flags, date, raw):
        self.calls.append(("APPEND", folder, flags, date, raw))
        return "OK", [b"APPEND completed"]

    def create(self, mailbox):
        folder = parse_list(b'() "/" ' + mailbox)["name"]
        self.calls.append(("CREATE", folder))
        self.items[folder] = {}
        return "OK", [b"created"]


class IMAPTests(OfflineTest):
    def source(self, client=None, auth="password"):
        client = client or FakeIMAP()
        endpoint = Endpoint("imap.example.test", "user@example.test", auth=auth)
        credentials = Credentials({"password": "synthetic", "access_token": "synthetic-token"})
        return IMAPSource(endpoint, credentials, Deadline(), connector=lambda *args, **kwargs: client), client

    def test_modified_utf7_roundtrip_and_quoting(self):
        for name in ("INBOX", "Sent Messages", 'a"b\\c', "A&B", "日本語/é 😀"):
            self.assertEqual(decode_folder(encode_folder(name)), name)
            self.assertEqual(parse_list(b'() "/" ' + quote_folder(name))["name"], name)

    def test_list_literal(self):
        self.assertEqual(parse_list((b'(\\HasNoChildren) "/" {3}', b"Foo"))["name"], "Foo")

    def test_invalid_list_encoding_and_literals_refused(self):
        for row in (b"nonsense", b'() "/" "unterminated', (b'() "/" {2}', b"Foo")):
            with self.assertRaises(MigrationError):
                parse_list(row)

    def test_inventory_includes_empty_folder_and_never_fetches_bodies(self):
        source, client = self.source()
        events = []
        from tests.helpers import job
        inventory = source.inventory(job(), events.append)
        self.assertEqual(len(inventory["entries"]), 1)
        self.assertIn({"name": "Empty", "uidvalidity": 11, "messages": 0, "bytes": 0}, inventory["folders"])
        self.assertTrue(events[-1]["stable"])
        self.assertFalse(any("BODY" in str(call) for call in client.calls))
        source.close()
        self.assertEqual(client.calls[-1], ("LOGOUT",))

    def test_unstable_inventory_retains_all_maps_before_refusal(self):
        source, client = self.source()
        client.drift = True
        events = []
        from tests.helpers import job
        with self.assertRaises(MigrationError):
            source.inventory(job(), events.append)
        comparison = events[-1]
        self.assertEqual(comparison["stage"], "UID_comparison")
        self.assertFalse(comparison["stable"])
        self.assertNotEqual(comparison["start"], comparison["end"])
        self.assertTrue(any(e["stage"] == "collected_folder" for e in events))

    def test_read_body_peek_is_bounded_and_uid_addressed(self):
        source, client = self.source()
        spec, raw = source.read(occurrence(), confirm_absence=True)
        self.assertEqual(raw, raw_message())
        fetch = [c for c in client.calls if c[0] == "FETCH"][-1]
        self.assertEqual(fetch[1], "1")
        self.assertIn(f"BODY.PEEK[]<0.{spec.bytes + 1}>", fetch[2])

    def test_empty_fetch_requires_successful_exact_uid_search(self):
        source, client = self.source()
        missing = occurrence(99)
        self.assertIsNone(source.read(missing, confirm_absence=True))
        self.assertIn(("SEARCH", None, "UID", "99"), client.calls)
        client.search_failure = True
        with self.assertRaises(MigrationError):
            source.read(missing, confirm_absence=True)

    def test_fetch_protocol_failure_is_not_absence(self):
        source, client = self.source()
        client.fetch_failure = True
        with self.assertRaises(MigrationError):
            source.read(occurrence(), confirm_absence=True)

    def test_uidvalidity_change_stops_before_fetch(self):
        source, client = self.source()
        client.validity = 99
        with self.assertRaises(MigrationError):
            source.read(occurrence(), confirm_absence=True)
        self.assertFalse(any(c[0] == "FETCH" for c in client.calls))

    def test_xoauth2_authorization_identity_explicit(self):
        source, client = self.source(auth="xoauth2")
        mechanism = client.calls[0]
        self.assertEqual(mechanism[0], "XOAUTH2")
        self.assertIn(b"user=user@example.test\x01auth=Bearer ", mechanism[1])

    def test_authentication_failure_no_retry(self):
        client = FakeIMAP()
        client.login = lambda *args: ("NO", [b"private provider body"])
        with self.assertRaises(MigrationError) as error:
            self.source(client)
        self.assertNotIn("private provider body", str(error.exception))
        self.assertEqual(client.calls, [("LOGOUT",)])

    def test_destination_requires_uidplus_before_append(self):
        client = FakeIMAP()
        destination = IMAPDestination(Endpoint("dest.example.test", "user@example.test"), Credentials({"password": "synthetic"}),
                                      Deadline(), connector=lambda *args, **kwargs: client)
        client.capabilities = (b"IMAP4rev1",)
        with self.assertRaises(MigrationError):
            destination.preflight(["INBOX"])
        self.assertFalse(any(c[0] == "APPEND" for c in client.calls))

    def test_destination_uses_current_authenticated_capabilities(self):
        client = FakeIMAP()
        client.capabilities = (b"IMAP4rev1",)
        client.capability = lambda: ("OK", [b"IMAP4rev1 UIDPLUS"])
        destination = IMAPDestination(Endpoint("dest.example.test", "user@example.test"), Credentials({"password": "synthetic"}),
                                      Deadline(), connector=lambda *args, **kwargs: client)
        self.assertEqual(destination.preflight(["INBOX"]), [])

    def test_nonsticky_mailbox_refused_before_body_or_append(self):
        source, client = self.source()
        client.nonsticky = True
        with self.assertRaises(MigrationError):
            source.read(occurrence())
        self.assertFalse(any(c[0] in ("FETCH", "APPEND") for c in client.calls))

    def test_append_receipt_and_original_flags_date_bytes(self):
        client = FakeIMAP()
        destination = IMAPDestination(Endpoint("dest.example.test", "user@example.test"), Credentials({"password": "synthetic"}),
                                      Deadline(), connector=lambda *args, **kwargs: client)
        spec = occurrence(flags=(r"\Seen", r"\Flagged"))
        baseline = fingerprint(raw_message(), spec, "imap")
        ack = destination.insert(raw_message(), "INBOX", spec, baseline)
        self.assertEqual(ack.selector, {"folder": "INBOX", "uidvalidity": 91, "uid": 42})
        call = client.calls[-1]
        self.assertEqual(call[2], r"(\Flagged \Seen)")
        self.assertEqual(call[3], '"' + DATE + '"')
        self.assertEqual(call[4], raw_message())

    def test_full_engine_uses_real_imap_transport_with_synthetic_server(self):
        from mail_migrator.engine import Migration
        from mail_migrator.models import Occurrence
        from mail_migrator.state import State
        from tests.helpers import job
        class RoundTripIMAP(FakeIMAP):
            def append(self, folder, flags, date, raw):
                result = super().append(folder, flags, date, raw)
                name = parse_list(b'() "/" ' + folder)["name"]
                self.items[name][42] = (Occurrence(name, 91, 42, len(raw),
                                                   tuple(flags.strip("()").split()), date.strip('"')), raw)
                return result
        config = job()
        source_client, target_client = FakeIMAP(), RoundTripIMAP()
        target_client.validity = 91
        target_client.items = {"INBOX": {}, "Empty": {}}
        credentials, deadline = Credentials({"password": "synthetic"}), Deadline()
        with State(self.state_dir, config, create=True) as state:
            source = IMAPSource(config.source, credentials, deadline, connector=lambda *a, **k: source_client)
            destination = IMAPDestination(config.destination, credentials, deadline, connector=lambda *a, **k: target_client)
            runner = Migration(state, source, destination, deadline)
            plan = runner.plan()
            self.assertFalse(any(c[0] == "APPEND" for c in target_client.calls))
            result = runner.migrate(plan["plan"], plan["plan_sha256"], apply=True)
            self.assertEqual(result["new_copies"], 1)
            self.assertEqual(state.status()["states"], {"verified": 1})
            self.assertFalse(any(c[0] in ("APPEND", "STORE", "CLOSE", "EXPUNGE") for c in source_client.calls))
            source.close()
            destination.close()

    def test_successful_append_without_receipt_is_uncertain(self):
        client = FakeIMAP()
        client.append_response = [None]
        destination = IMAPDestination(Endpoint("dest.example.test", "user@example.test"), Credentials({"password": "synthetic"}),
                                      Deadline(), connector=lambda *args, **kwargs: client)
        with self.assertRaises(UncertainWrite):
            destination.insert(raw_message(), "INBOX", occurrence(), fingerprint(raw_message(), occurrence(), "imap"))

    def test_plan_preflight_missing_folder_does_not_create(self):
        client = FakeIMAP()
        destination = IMAPDestination(Endpoint("dest.example.test", "user@example.test"), Credentials({"password": "synthetic"}),
                                      Deadline(), connector=lambda *args, **kwargs: client)
        self.assertEqual(destination.preflight(["Archive"], create=True), ["Archive"])
        self.assertFalse(any(c[0] == "CREATE" for c in client.calls))
        self.assertEqual(destination.ensure("Archive", create=True), "Archive")
        self.assertTrue(any(c[0] == "CREATE" for c in client.calls))

    def test_duplicate_metadata_field_refused(self):
        row = b'1 (UID 1 UID 2 RFC822.SIZE 5 FLAGS () INTERNALDATE "04-Nov-2026 12:00:00 +0000")'
        with self.assertRaises(MigrationError):
            metadata(row, "INBOX", 11)


class Response:
    def __init__(self, value, *, fail_close=False):
        self.raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.fail_close = fail_close

    def read(self, maximum):
        return self.raw[:maximum]

    def close(self):
        if self.fail_close:
            raise OSError("Synthetic cleanup failure")


class Opener:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def open(self, request, timeout):
        self.calls.append((request.full_url, request.data, dict(request.header_items())))
        if not self.replies:
            raise AssertionError("Unexpected HTTP request")
        value = self.replies.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value if isinstance(value, Response) else Response(value)


class GmailTests(OfflineTest):
    def destination(self, replies=(), profile="user@example.test"):
        opener = Opener([{"access_token": "synthetic-access", "expires_in": 3600}, {"emailAddress": profile}, *replies])
        endpoint = Endpoint("gmail.googleapis.com", "user@example.test", 443, "gmail-oauth", "gmail")
        credentials = Credentials({"client_id": "synthetic-client", "client_secret": "synthetic-secret", "refresh_token": "synthetic-refresh"})
        return GmailDestination(endpoint, credentials, Deadline(), opener=opener), opener

    def labels(self):
        return {"labels": [{"id": "INBOX", "name": "INBOX", "type": "system"},
                           {"id": "SENT", "name": "SENT", "type": "system"},
                           {"id": "Label_a", "name": "Archive", "type": "user"}]}

    def test_profile_mismatch_refuses_destination(self):
        with self.assertRaises(MigrationError):
            self.destination(profile="other@example.test")

    def test_insert_not_send_preserves_read_star_and_date_header_mode(self):
        destination, opener = self.destination([{"id": "message123"}])
        spec = occurrence(flags=(r"\Flagged",))
        baseline = fingerprint(raw_message(), spec, "gmail")
        ack = destination.insert(raw_message(), "INBOX", spec, baseline)
        url, body, _ = opener.calls[-1]
        self.assertEqual(url, BASE + "/messages?internalDateSource=dateHeader")
        self.assertNotIn("send", url)
        self.assertEqual(json.loads(body)["labelIds"], ["INBOX", "STARRED", "UNREAD"])
        self.assertEqual(base64.urlsafe_b64decode(json.loads(body)["raw"]), raw_message())
        self.assertEqual(ack.key, "gmail:message123")

    def test_response_close_failure_cannot_discard_returned_ack(self):
        destination, _ = self.destination([Response({"id": "saved123"}, fail_close=True)])
        baseline = fingerprint(raw_message(), occurrence(), "gmail")
        self.assertEqual(destination.insert(raw_message(), "INBOX", occurrence(), baseline).selector, {"id": "saved123"})

    def test_empty_ack_no_insert_retry(self):
        destination, opener = self.destination([{}])
        with self.assertRaises(UncertainWrite):
            destination.insert(raw_message(), "INBOX", occurrence(), fingerprint(raw_message(), occurrence(), "gmail"))
        self.assertEqual(len(opener.calls), 3)

    def test_raw_readback_date_labels_and_id(self):
        date = internal_timestamp(DATE)
        destination, opener = self.destination([{"id": "saved123", "raw": base64.urlsafe_b64encode(raw_message()).decode(),
                                               "internalDate": str(date), "labelIds": ["INBOX", "UNREAD"]}])
        result = destination.get(Ack("gmail:saved123", {"id": "saved123"}), {"destination_target": "INBOX"})
        self.assertEqual(result["raw"], raw_message())
        self.assertEqual(result["date_ms"], date)
        self.assertEqual(result["read_star"], {"read": False, "starred": False})
        self.assertIn("format=raw", opener.calls[-1][0])

    def test_saved_id_validation_before_network(self):
        destination, opener = self.destination()
        before = len(opener.calls)
        with self.assertRaises(MigrationError):
            destination.get(Ack("gmail: ", {"id": " "}), {})
        self.assertEqual(len(opener.calls), before)

    def test_missing_label_permission_is_plan_only(self):
        destination, opener = self.destination([self.labels()])
        self.assertEqual(destination.preflight(["Missing"], create=True), ["Missing"])
        self.assertTrue(all(body is None for url, body, _ in opener.calls if "/labels" in url))

    def test_custom_and_native_labels_identity_checked(self):
        destination, _ = self.destination([self.labels()])
        self.assertEqual(destination.preflight(["INBOX", "SENT", "Archive"]), [])
        bad = self.labels()
        bad["labels"][0]["id"] = "WrongINBOX"
        destination, _ = self.destination([bad])
        with self.assertRaises(MigrationError):
            destination.preflight(["INBOX"])

    def test_native_draft_mapping_not_silently_flattened(self):
        destination, _ = self.destination([self.labels()])
        with self.assertRaises(MigrationError):
            destination.preflight(["DRAFT"], create=True)

    def test_http_redirects_do_not_forward_credentials(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 307, "redirect", {}, "https://other.example.test"))
