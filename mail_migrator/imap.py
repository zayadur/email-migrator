"""TLS IMAP only. Source commands are EXAMINE/SEARCH/FETCH BODY.PEEK, never STORE."""
import base64
import imaplib
import re
import ssl

from .errors import MigrationError, UncertainWrite
from .message import internal_timestamp
from .models import Ack, Occurrence, text
from .security import encoded
from .state import now


def encode_folder(value):
    text(value, "folder")
    result, non_ascii = [], []
    def flush():
        if non_ascii:
            raw = "".join(non_ascii).encode("utf-16-be")
            result.append(b"&" + base64.b64encode(raw).rstrip(b"=").replace(b"/", b",") + b"-")
            non_ascii.clear()
    for char in value:
        if 32 <= ord(char) <= 126:
            flush()
            result.append(b"&-" if char == "&" else char.encode("ascii"))
        else:
            non_ascii.append(char)
    flush()
    return b"".join(result)


def decode_folder(value):
    try:
        ascii_name = value.decode("ascii")
        result, offset = [], 0
        while offset < len(ascii_name):
            if ascii_name[offset] != "&":
                result.append(ascii_name[offset])
                offset += 1
                continue
            end = ascii_name.index("-", offset)
            token = ascii_name[offset + 1:end]
            if not token:
                result.append("&")
            else:
                token = token.replace(",", "/")
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
                result.append(decoded.decode("utf-16-be"))
            offset = end + 1
        name = "".join(result)
        if encode_folder(name) != value:
            raise ValueError()
        return name
    except (ValueError, UnicodeError):
        raise MigrationError("Unsupported IMAP mailbox encoding.") from None


def quote_folder(name):
    return b'"' + encode_folder(name).replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def parse_list(row):
    literal = None
    if type(row) is tuple and len(row) == 2:
        row, literal = row
    if type(row) is not bytes:
        raise MigrationError("Invalid IMAP LIST response.")
    match = re.fullmatch(rb'\(([^)]*)\) (NIL|"(?:[^"\\]|\\.)*") (.+)', row)
    if not match:
        raise MigrationError("Unsupported IMAP LIST response.")
    flags, delimiter, wire = match.groups()
    if literal is not None:
        if type(literal) is not bytes or wire != b"{" + str(len(literal)).encode() + b"}":
            raise MigrationError("Invalid LIST literal.")
        wire = literal
    elif wire.startswith(b'"'):
        if not re.fullmatch(rb'"(?:[^"\\]|\\["\\])*"', wire):
            raise MigrationError("Malformed quoted mailbox.")
        wire = re.sub(rb"\\([\"\\])", rb"\1", wire[1:-1])
    elif re.search(rb'[\s(){}"\\\x00-\x1f\x7f]', wire):
        raise MigrationError("Unsupported mailbox atom.")
    return {"name": decode_folder(wire), "flags": flags.decode("ascii").split(),
            "delimiter": None if delimiter == b"NIL" else delimiter[1:-1].decode("ascii")}


def metadata(row, folder, validity):
    if type(row) is tuple:
        row = row[0]
    if type(row) is not bytes:
        raise MigrationError("Invalid IMAP metadata response.")
    def one(pattern):
        values = re.findall(pattern, row)
        if len(values) != 1:
            raise MigrationError("Missing/duplicate IMAP message metadata.")
        return values[0]
    try:
        uid = int(one(rb"\bUID (\d+)\b"))
        size = int(one(rb"\bRFC822\.SIZE (\d+)\b"))
        flags = tuple(sorted(one(rb"\bFLAGS \(([^)]*)\)").decode("ascii").split()))
        date = one(rb'\bINTERNALDATE "([^"\r\n]+)"').decode("ascii")
        internal_timestamp(date)
        return Occurrence(folder, validity, uid, size, flags, date)
    except (ValueError, UnicodeError):
        raise MigrationError("Invalid numeric or ASCII source metadata.") from None


class IMAPSession:
    def __init__(self, endpoint, credentials, deadline, *, connector=None):
        self.endpoint, self.deadline = endpoint, deadline
        self.client = None
        try:
            self.client = (connector or imaplib.IMAP4_SSL)(endpoint.host, endpoint.port,
                ssl_context=ssl.create_default_context(), timeout=deadline.timeout())
            self.client.debug = 0
            deadline.check()
            if endpoint.auth == "password":
                status, _ = self.client.login(endpoint.user, credentials.get("password"))
            else:
                token = credentials.get("access_token")
                payload = f"user={endpoint.user}\x01auth=Bearer {token}\x01\x01".encode()
                status, _ = self.client.authenticate("XOAUTH2", lambda _: payload)
            if status != "OK":
                raise MigrationError("IMAP authentication rejected; no retry.")
        except BaseException as error:
            self.close()
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise MigrationError("IMAP TLS connection/authentication failed; no retry.") from None

    def check(self):
        self.deadline.check()
        # imaplib's initial timeout also governs later reads; bound each admission.
        sock = getattr(self.client, "sock", None)
        if sock is not None:
            sock.settimeout(self.deadline.timeout())

    def folders(self):
        self.check()
        status, rows = self.client.list()
        if status != "OK" or type(rows) is not list:
            raise MigrationError("IMAP LIST failed.")
        result = [parse_list(row) for row in rows if row is not None]
        result = [r for r in result if not {f.casefold() for f in r["flags"]} & {r"\noselect", r"\nonexistent"}]
        names = [r["name"] for r in result]
        if len(result) > 1000 or len(names) != len(set(names)):
            raise MigrationError("Duplicate or excessive IMAP folder list.")
        return result

    def examine(self, folder):
        self.check()
        status, counts = self.client.select(quote_folder(folder), readonly=True)
        if status != "OK" or len(counts) != 1 or not isinstance(counts[0], bytes) or not counts[0].isdigit():
            raise MigrationError("Read-only EXAMINE failed.")
        _, values = self.client.response("UIDVALIDITY")
        if not values or len(values) != 1 or type(values[0]) is not bytes or not values[0].isdigit() or int(values[0]) <= 0:
            raise MigrationError("Missing/invalid UIDVALIDITY.")
        _, nonsticky = self.client.response("UIDNOTSTICKY")
        if nonsticky and any(value is not None for value in nonsticky):
            raise MigrationError("Nonpersistent mailbox UIDs cannot be migrated safely.")
        return int(values[0])

    def uid_set(self):
        self.check()
        status, rows = self.client.uid("SEARCH", None, "ALL")
        if status != "OK" or type(rows) is not list or any(type(x) is not bytes for x in rows):
            raise MigrationError("UID SEARCH failed.")
        tokens = b" ".join(rows).split()
        if any(not t.isdigit() or int(t) <= 0 for t in tokens):
            raise MigrationError("Malformed source UID set.")
        uids = sorted(int(t) for t in tokens)
        if len(uids) != len(set(uids)) or len(uids) > 1000000:
            raise MigrationError("Duplicate/excessive UID set.")
        return uids

    def read(self, spec, *, confirm_absence=False, max_bytes=None):
        if self.examine(spec.folder) != spec.uidvalidity:
            raise MigrationError("UIDVALIDITY changed; no UID reuse.")
        self.check()
        maximum = spec.bytes if max_bytes is None else max_bytes
        query = f"(UID RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[]<0.{maximum + 1}>)"
        status, rows = self.client.uid("FETCH", str(spec.uid), query)
        if status != "OK" or type(rows) is not list:
            raise MigrationError("Source FETCH failed; not an absence.")
        if rows == [None] and confirm_absence:
            if self.examine(spec.folder) != spec.uidvalidity:
                raise MigrationError("UIDVALIDITY changed while confirming absence.")
            self.check()
            status, found = self.client.uid("SEARCH", None, "UID", str(spec.uid))
            self.deadline.check()
            if status == "OK" and found == [b""]:
                return None
            raise MigrationError("Empty FETCH did not establish exact UID absence.")
        literals = [row for row in rows if type(row) is tuple]
        if len(literals) != 1 or len(literals[0]) != 2 or any(type(row) is not tuple and row not in (b")", b"", None) for row in rows):
            raise MigrationError("Malformed body FETCH response.")
        prefix, raw = literals[0]
        current = metadata(prefix, spec.folder, spec.uidvalidity)
        if (type(raw) is not bytes or current.uid != spec.uid or current.bytes != spec.bytes
                or len(raw) != spec.bytes or len(raw) > maximum
                or internal_timestamp(current.internal_date) != internal_timestamp(spec.internal_date)):
            raise MigrationError("Fetched source identity/size/date changed.")
        self.deadline.check()
        return current, raw

    def close(self):
        if self.client is not None:
            try:
                self.client.logout()  # LOGOUT, never CLOSE or EXPUNGE.
            except Exception:
                pass
            self.client = None


class IMAPSource(IMAPSession):
    def inventory(self, config, emit):
        available = self.folders()
        names = sorted(config.folders or [f["name"] for f in available])
        if not names or not set(names) <= {f["name"] for f in available}:
            raise MigrationError("Requested source folders are missing or empty in scope.")
        def sets():
            result = {}
            for name in names:
                validity = self.examine(name)
                result[name] = {"uidvalidity": validity, "uids": self.uid_set()}
            return result
        start = sets()
        emit({"stage": "UID_start", "sets": start, "observed_at": now()})
        entries, folders = [], []
        for folder in names:
            validity = self.examine(folder)
            if validity != start[folder]["uidvalidity"]:
                raise MigrationError("UIDVALIDITY changed during inventory.")
            uids = start[folder]["uids"]
            observed = {}
            for offset in range(0, len(uids), 500):
                self.check()
                batch = uids[offset:offset + 500]
                status, rows = self.client.uid("FETCH", ",".join(map(str, batch)), "(UID RFC822.SIZE FLAGS INTERNALDATE)")
                if status != "OK" or type(rows) is not list:
                    raise MigrationError("Source metadata FETCH failed.")
                for row in rows:
                    if row is None:
                        continue
                    item = metadata(row, folder, validity)
                    if item.uid not in batch or item.uid in observed:
                        raise MigrationError("Unexpected/duplicate fetched UID.")
                    observed[item.uid] = item
                if len(entries) + len(observed) > 1000000:
                    raise MigrationError("Source inventory exceeds one million occurrences.")
            items = [v.to_dict() for _, v in sorted(observed.items())]
            emit({"stage": "collected_folder", "folder": folder, "uidvalidity": validity, "entries": items})
            entries.extend(items)
            folders.append({"name": folder, "uidvalidity": validity, "messages": len(items),
                            "bytes": sum(e["bytes"] for e in items)})
        end = sets()
        collected = {f["name"]: {"uidvalidity": f["uidvalidity"],
                     "uids": sorted(e["uid"] for e in entries if e["folder"] == f["name"])} for f in folders}
        emit({"stage": "UID_comparison", "start": start, "collected": collected, "end": end,
              "stable": start == collected == end})
        if start != collected or collected != end:
            raise MigrationError("Source changed during inventory; evidence retained, no plan accepted.")
        if not config.folders and {f["name"] for f in self.folders()} != set(names):
            raise MigrationError("Source folder list changed during inventory.")
        return {"observed_at": now(), "folders": folders, "entries": entries}


class IMAPDestination(IMAPSession):
    kind = "imap"

    def preflight(self, targets, *, create=False):
        self.check()
        status, rows = self.client.capability()
        if status != "OK" or type(rows) is not list or any(type(row) is not bytes for row in rows):
            raise MigrationError("Destination capability check failed.")
        capabilities = {token.upper() for token in b" ".join(rows).split()}
        if not capabilities & {b"UIDPLUS", b"IMAP4REV2"}:
            raise MigrationError("Destination must support UIDPLUS/APPENDUID for safe receipts.")
        present = {f["name"] for f in self.folders()}
        missing = sorted(set(targets) - present)
        if missing and not create:
            raise MigrationError("Destination folders are missing. Create them first or explicitly plan --create-folders.")
        return missing

    def ensure(self, target, *, create=False):
        missing = self.preflight([target], create=create)
        if missing:
            self.check()
            status, _ = self.client.create(quote_folder(target))
            if status != "OK":
                raise MigrationError("Destination folder creation failed; inspect before rerunning.")
            if target not in {f["name"] for f in self.folders()}:
                raise MigrationError("Created destination folder not confirmed.")
        self.examine(target)
        return target

    def prepare(self):
        self.check()

    def insert(self, raw, target, occurrence, baseline):
        # Engine already performed admission; no callbacks after the APPEND ACK.
        flags = "(" + " ".join(baseline["copied_flags"]) + ")"
        status, rows = self.client.append(quote_folder(target), flags, f'"{occurrence.internal_date}"', raw)
        if status != "OK":
            raise UncertainWrite("APPEND did not return a usable receipt; no retry.")
        _, response = self.client.response("APPENDUID")
        values = []
        for row in (response or []):
            if isinstance(row, bytes):
                m = re.fullmatch(rb"(\d+) (\d+)", row.strip())
                if m:
                    values.append((int(m[1]), int(m[2])))
        if not values:
            for row in rows or []:
                if isinstance(row, bytes):
                    values.extend((int(v), int(u)) for v, u in re.findall(rb"\[APPENDUID (\d+) (\d+)\]", row))
        if len(values) != 1 or min(values[0]) <= 0:
            raise UncertainWrite("APPEND succeeded without one exact APPENDUID; reconcile manually.")
        validity, uid = values[0]
        selector = {"folder": target, "uidvalidity": validity, "uid": uid}
        return Ack("imap:" + encoded([target, validity, uid]).decode(), selector)

    def get(self, ack, baseline):
        selector = ack.selector
        spec = Occurrence(selector["folder"], selector["uidvalidity"], selector["uid"],
                          baseline["source_bytes"], (), baseline["source_internal_date"])
        value = self.read(spec)
        occurrence, raw = value
        return {"raw": raw, "date_ms": internal_timestamp(occurrence.internal_date),
                "read_star": {"read": r"\seen" in {f.casefold() for f in occurrence.flags},
                              "starred": r"\flagged" in {f.casefold() for f in occurrence.flags}},
                "flags": list(occurrence.flags), "placement": selector["folder"]}
