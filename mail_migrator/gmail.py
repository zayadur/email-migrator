"""Gmail insert/read/labels only. No send/delete/modify endpoint exists here."""
import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .errors import Hold, MigrationError, UncertainWrite
from .models import Ack
from .security import encoded

BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
SYSTEM = {"INBOX", "SENT", "TRASH", "SPAM", "IMPORTANT", "STARRED", "UNREAD", "DRAFT"}
MAX_BYTES = 25 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class GmailDestination:
    kind = "gmail"
    max_message_bytes = MAX_BYTES

    def __init__(self, endpoint, credentials, deadline, *, opener=None):
        self.endpoint, self.credentials, self.deadline = endpoint, credentials, deadline
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.token, self.expires = None, 0
        self.labels = {}
        self.prepare()
        profile = self._request(BASE + "/profile")
        if profile.get("emailAddress", "").casefold() != endpoint.user.casefold():
            raise MigrationError("Gmail authenticated profile does not match the selected destination.")

    def _request(self, url, data=None, *, form=False, write_ack=False):
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        if not form:
            headers["Authorization"] = f"Bearer {self.token}"
        body = urllib.parse.urlencode(data).encode() if form else (encoded(data) if data is not None else None)
        request = urllib.request.Request(url, data=body, headers=headers)
        response = None
        try:
            # A returned ACK is parsed without a subsequent clock check.
            timeout = self.deadline.timeout()
            response = self.opener.open(request, timeout=timeout)
            limit = 128 * 1024 if write_ack else (MAX_BYTES * 2 + 1024 * 1024)
            raw = response.read(limit + 1)
            if type(raw) is not bytes or len(raw) > limit:
                raise ValueError()
            result = json.loads(raw)
            if type(result) is not dict:
                raise ValueError()
            return result
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            raise MigrationError(f"Gmail/OAuth HTTP {code}; no automatic retry.") from None
        except (ValueError, UnicodeError):
            raise MigrationError("Invalid bounded Gmail/OAuth response; no retry.") from None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass  # Cleanup must not discard a returned message ACK.

    def prepare(self):
        self.deadline.check()
        if self.token is None or time.monotonic() >= self.expires:
            result = self._request("https://oauth2.googleapis.com/token", {
                "grant_type": "refresh_token", "client_id": self.credentials.get("client_id"),
                "client_secret": self.credentials.get("client_secret"),
                "refresh_token": self.credentials.get("refresh_token")}, form=True)
            token = result.get("access_token")
            if type(token) is not str or not token or type(result.get("expires_in")) is not int or result["expires_in"] <= 0:
                raise MigrationError("OAuth refresh did not return a usable token.")
            if "scope" in result and "https://www.googleapis.com/auth/gmail.modify" not in result["scope"].split():
                raise MigrationError("OAuth grant requires gmail.modify for insert/read/labels.")
            self.token = token
            self.expires = time.monotonic() + max(1, result["expires_in"] - 60)
        self.deadline.check()  # Actual POST admission still occurs after refresh.

    def _labels(self):
        self.prepare()
        values = self._request(BASE + "/labels").get("labels")
        if type(values) is not list or any(type(v) is not dict or type(v.get("name")) is not str
                or type(v.get("id")) is not str or not v["id"].strip()
                or v.get("type") not in ("system", "user") for v in values):
            raise MigrationError("Malformed Gmail label listing.")
        if len({v["name"] for v in values}) != len(values) or len({v["id"] for v in values}) != len(values):
            raise MigrationError("Ambiguous Gmail labels.")
        self.labels = {v["name"]: v for v in values}
        return self.labels

    def preflight(self, targets, *, create=False):
        labels = self._labels()
        missing = []
        for target in set(targets):
            if target in SYSTEM:
                if target in ("DRAFT", "UNREAD", "STARRED"):
                    raise MigrationError("Map folders to an organizational label, not DRAFT/UNREAD/STARRED.")
                if labels.get(target, {}).get("id") != target or labels[target]["type"] != "system":
                    raise MigrationError("Required native Gmail label missing.")
            elif target not in labels:
                missing.append(target)
            elif labels[target]["type"] != "user":
                raise MigrationError("Custom folder collides with a native Gmail label.")
        if missing and not create:
            raise MigrationError("Destination labels are missing; explicitly plan --create-folders or create them first.")
        return sorted(missing)

    def ensure(self, target, *, create=False):
        missing = self.preflight([target], create=create)
        if missing:
            self.prepare()
            self._request(BASE + "/labels", {"name": target, "labelListVisibility": "labelShow", "messageListVisibility": "show"})
            self._labels()  # Read back by name; a lost label ACK is never a message retry.
            if target not in self.labels or self.labels[target]["type"] != "user":
                raise MigrationError("Created Gmail label not confirmed.")
        return self.labels[target]["id"]

    def validate_source(self, raw, occurrence):
        if len(raw) > MAX_BYTES:
            raise Hold("gmail_message_exceeds_25MiB_nonresumable_limit")

    def insert(self, raw, target, occurrence, baseline):
        labels = [target]
        if not baseline["copied_read_star"]["read"]:
            labels.append("UNREAD")
        if baseline["copied_read_star"]["starred"]:
            labels.append("STARRED")
        result = self._request(BASE + "/messages?internalDateSource=dateHeader",
            {"raw": base64.urlsafe_b64encode(raw).decode("ascii"), "labelIds": sorted(set(labels))}, write_ack=True)
        identity = result.get("id")
        if type(identity) is not str or not identity:
            raise UncertainWrite("Gmail insert returned no message ID; never retry.")
        return Ack("gmail:" + identity, {"id": identity})

    def get(self, ack, baseline):
        identity = ack.selector.get("id")
        if type(identity) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", identity):
            raise MigrationError("Malformed saved Gmail ID; no replay.")
        self.prepare()
        result = self._request(BASE + "/messages/" + urllib.parse.quote(identity, safe="")
                               + "?format=raw&fields=id,labelIds,internalDate,raw")
        if result.get("id") != identity or type(result.get("raw")) is not str or type(result.get("labelIds")) is not list:
            raise MigrationError("Incomplete Gmail readback.")
        try:
            wire = result["raw"].encode("ascii")
            raw = base64.b64decode(wire + b"=" * (-len(wire) % 4), altchars=b"-_", validate=True)
            date = int(result["internalDate"])
        except (ValueError, UnicodeError, KeyError):
            raise MigrationError("Invalid Gmail raw/date readback.") from None
        labels = result["labelIds"]
        return {"raw": raw, "date_ms": date, "labels": labels,
                "placement": baseline["destination_target"],
                "read_star": {"read": "UNREAD" not in labels, "starred": "STARRED" in labels}}

    def close(self):
        self.token = None
