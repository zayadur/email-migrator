"""Conservative MIME fingerprints. No rewriting, normalization, or raw archive."""
import datetime as dt
from email import policy
from email.errors import MessageError
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
import re

from .errors import Hold, MigrationError
from .security import encoded, sha


def internal_timestamp(value):
    try:
        # IMAP month names are English regardless of the machine's locale.
        m = re.fullmatch(r" ?(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)", value)
        if not m:
            raise ValueError()
        day, month, year, hour, minute, second, sign, zh, zm = m.groups()
        months = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
        offset = (int(zh) * 60 + int(zm)) * (1 if sign == "+" else -1)
        if int(zh) > 23 or int(zm) > 59:
            raise ValueError()
        date = dt.datetime(int(year), months[month.lower()], int(day), int(hour), int(minute),
                           int(second), tzinfo=dt.timezone(dt.timedelta(minutes=offset)))
        return int(date.timestamp()) * 1000
    except (ValueError, KeyError, OverflowError):
        raise MigrationError("Invalid source INTERNALDATE.") from None


def header_items(message):
    return [(name.casefold(), re.sub(r"\r?\n[ \t]+", " ", value).strip())
            for name, value in message.raw_items()]


def parse(raw):
    try:
        if (type(raw) is not bytes or b"\r\n\r\n" not in raw
                or re.search(rb"(?<!\r)\n|\r(?!\n)", raw)):
            raise ValueError()
        message = BytesParser(policy=policy.default).parsebytes(raw)
        parts = list(message.walk())
        headers = [tuple(part.items()) for part in parts]  # Materialize lazy defects.
        leaves, layout = [], []
        for part in parts:
            payload = part.get_payload(decode=True)
            layout.append([part.is_multipart(), part.get_content_type(), part.get_content_charset(),
                           part.get_content_disposition(), part.get_filename(),
                           [str(x) for x in part.get_all("Content-ID", [])],
                           header_items(part) if part is not message else None])
            if not part.is_multipart():
                if payload is None:
                    value = part.get_payload()
                    if type(value) is not str:
                        raise ValueError()
                    payload = value.encode("utf-8", errors="surrogateescape")
                if part.get_content_maintype() == "text":
                    payload = payload.replace(b"\r\n", b"\n")
                leaves.append([part.get_content_type(), part.get_content_disposition(),
                               part.get_filename(), len(payload), sha(payload)])
        if any(part.defects for part in parts) or any(getattr(v, "defects", ()) for group in headers for _, v in group):
            raise ValueError()
        return message, {"headers": header_items(message), "leaves": leaves, "layout": layout}
    except (ValueError, TypeError, UnicodeError, IndexError, MessageError):
        raise Hold("unsupported_headers_or_MIME") from None


def gmail_date(message):
    try:
        fields = [v for n, v in message.raw_items() if n.casefold() == "date"]
        if len(fields) != 1:
            raise ValueError()
        date = parsedate_to_datetime(fields[0])
        if date.tzinfo is None:
            # Accept explicit RFC -0000 as UTC, never an invented local timezone.
            if not re.search(r"\s-0000\s*$", fields[0]):
                raise ValueError()
            date = date.replace(tzinfo=dt.timezone.utc)
        milliseconds = int(date.timestamp()) * 1000
        if not 0 <= milliseconds <= int(dt.datetime.now(dt.timezone.utc).timestamp() + 86400) * 1000:
            raise ValueError()
        return milliseconds
    except (ValueError, TypeError, OverflowError):
        raise Hold("unsupported_gmail_Date") from None


def fingerprint(raw, occurrence, kind):
    message, content = parse(raw)
    flags = {x.casefold() for x in occurrence.flags}
    if r"\deleted" in flags:
        raise Hold("source_marked_deleted")
    if kind == "gmail":
        if r"\draft" in flags:
            raise Hold("native_gmail_draft_requires_separate_review")
        ids = message.get_all("Message-ID", [])
        if len(ids) != 1 or not re.fullmatch(r"<[^<>\s@]+@[^<>\s@]+>", str(ids[0])) or len(message.get_all("From", [])) != 1:
            raise Hold("unsupported_gmail_identity_headers")
        timestamp = gmail_date(message)
    else:
        timestamp = internal_timestamp(occurrence.internal_date)
    return {"raw_sha256": sha(raw), "content_sha256": sha(encoded(content)),
            "destination_date_ms": timestamp, "source_internal_date_ms": internal_timestamp(occurrence.internal_date),
            "copied_read_star": {"read": r"\seen" in flags, "starred": r"\flagged" in flags},
            "copied_flags": sorted(x for x in occurrence.flags if x.casefold() not in (r"\recent", r"\deleted"))}


def verify_content(raw, baseline, kind):
    if kind == "imap":
        if sha(raw) != baseline["raw_sha256"]:
            raise MigrationError("Destination raw message differs from the saved source fingerprint.")
        return
    _, current = parse(raw)
    if sha(encoded(current)) == baseline["content_sha256"]:
        return
    # Gmail can prepend exactly one service-generated Received trace. Nothing
    # else may be added, removed, reordered, or rewritten under this policy.
    target_received = [v for n, v in current["headers"] if n == "received"]
    if not target_received:
        raise MigrationError("Gmail headers or Received chain changed.")
    trace = target_received[0]
    if not re.search(r"\bby gmailapi\.google\.com with HTTPREST\s*;", trace, re.I):
        raise MigrationError("Unexpected added Gmail trace.")
    try:
        date = parsedate_to_datetime(trace.rsplit(";", 1)[1].strip())
        if date.tzinfo is None:
            raise ValueError()
    except (ValueError, IndexError, TypeError):
        raise MigrationError("Invalid added Gmail trace date.") from None
    headers = list(current["headers"])
    headers.remove(["received", trace] if ["received", trace] in headers else ("received", trace))
    current["headers"] = headers
    # JSON baselines use lists; runtime parsers use tuples.
    if sha(encoded(current)) != baseline["content_sha256"]:
        raise MigrationError("Destination headers, attachments, or MIME structure changed.")
