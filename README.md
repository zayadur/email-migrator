# Email Migrator

Independent Python CLI **and importable library** for IMAP → IMAP and
IMAP → Gmail/Google Workspace migrations. Accounts and credentials are selected
per job, not inherited from a laptop, organization, vault or earlier client.

Python **3.11+**, macOS/Linux, standard library only. No dependency installation
is needed for the local script:

```sh
python3 migrate_mail.py --help
# Equivalent module entry point:
python3 -m mail_migrator --help
```

Optionally install in your own virtual environment with `python -m pip install .`
to get the `mail-migrator` command. No global installation is required.

## Credentials

Keep credentials outside this project and its state directories. Each side
accepts **one** of `--source-credentials FILE` / `--source-secret-env NAME`, and
the corresponding `--destination-*` flags. Environment flags take the **variable
name**, not the secret value. Passwords/tokens are never accepted directly as
command-line values or written into a checkpoint.

For password/app-password IMAP authentication, the private JSON file contains:

```json
{"password": "<provider-approved password or app password>"}
```

Set the file to mode `0600` (or `0400`). Host and username are separate explicit
flags. Password authentication must be allowed by the provider; the script does
not bypass MFA or obtain an app password.

For IMAP XOAUTH2, select `--source-auth xoauth2` or
`--destination-auth xoauth2` and supply `{"access_token": "<token>"}`. A selected
environment variable can instead contain just that password/access token.
Generic IMAP access tokens are not automatically refreshed.

For the **Gmail API destination**, supply an already authorized OAuth grant:

```json
{
  "client_id": "<OAuth client ID>",
  "client_secret": "<OAuth client secret>",
  "refresh_token": "<authorized user's refresh token>"
}
```

The grant needs `https://www.googleapis.com/auth/gmail.modify`. A Gmail-selected
environment variable contains this JSON object, not a bare token. The API
profile must match `--destination-user`. Token refresh is pinned to Google's
OAuth endpoint; no ambient Google credentials, service-account impersonation,
browser authorization or credential discovery occurs. Obtain/authorize the
grant through your approved process before running this tool.

## 1. Plan without changing mail

```sh
python3 migrate_mail.py plan \
  --state /private/jobs/mail-job-a \
  --source-host imap.old.example \
  --source-user alice@old.example \
  --source-credentials /private/credentials/source.json \
  --destination-type imap \
  --destination-host imap.new.example \
  --destination-user alice@new.example \
  --destination-credentials /private/credentials/destination.json \
  --create-folders
```

Omitting `plan` or adding `--dry-run` has the same planning-only behavior. It
authenticates to both selected accounts, reads source metadata and destination
folder availability, and writes private local evidence/ledger/plan files. **No
message bodies are downloaded and no destination folders or mail are written.**

The output prints an exact `plan` path and `plan_sha256` for the apply command.
`--create-folders` enrolls permission to create missing destination folders
**later during apply**, not during planning. Omit it to require existing folders.

All selectable source folders, including empty folders, are inventoried by
default. Restrict scope explicitly with repeated `--folder` flags. Every folder
occurrence is independent; identical bodies/Message-IDs in two folders are not
deduplicated. Start/collected/end UID sets must agree; evidence is retained
before rejecting an unstable snapshot. There is no automatic inventory retry.

### Gmail instead of IMAP

Use these destination flags in the planning command (omit destination host/port):

```sh
--destination-type gmail \
--destination-user alice@new.example \
--destination-credentials /private/credentials/gmail-oauth.json
```

By default `INBOX` maps to native Inbox. Other source folder names are preserved
as custom labels, **not guessed as native Sent/Trash**. Use a nonsecret JSON
mapping with `--mapping /path/to/folders.json`, for example:

```json
{
  "INBOX": "INBOX",
  "INBOX.Sent": "SENT",
  "INBOX.Sent Messages": "SENT",
  "INBOX.Trash": "TRASH",
  "INBOX.Junk": "SPAM"
}
```

Uppercase native organizational labels (`INBOX`, `SENT`, `TRASH`, `SPAM`,
`IMPORTANT`) use Google's system IDs. Two legacy folders may explicitly share
the same native label, but merges into custom labels/IMAP folders are refused
rather than silently flattening organization. There is no automatic account
label. A different mapping/scope/policy requires a different state directory.

## 2. Apply the exact plan

Replace the plan path/hash below with the values printed by planning:

```sh
python3 migrate_mail.py migrate --apply \
  --state /private/jobs/mail-job-a \
  --plan /private/jobs/mail-job-a/plans/plan-<digest>.json \
  --plan-sha256 <printed-file-sha256> \
  --source-credentials /private/credentials/source.json \
  --destination-credentials /private/credentials/destination.json \
  --limit 1
```

The state fixes both account identities. Resume commands supply credentials,
**not different account/mapping flags**. `--apply` is mandatory. The first
successful real copy is limited to one, including its immediate readback. It
stops after that proof even if a larger limit was requested. Strict pre-write
holds may be recorded while looking for the first eligible copy.

Rerun the same apply command with `--limit 100`, or omit `--limit` to process the
remaining pending occurrences within `--runtime` (default **300 seconds per
invocation**). The limit counts pending attempts/known-ID readbacks, not just
successful copies. There is no new per-account normalization budget: **this
version performs no header normalization or exception archiving at all**.

Known verified copies are skipped. A returned destination ID is durably saved
before alias, deadline, callback or readback checks. Interrupted known-created
copies resume by **GET only**, not another APPEND/insert. Both IMAP and Gmail
readbacks check content, attachments/MIME, placement, chronology and initial
read/star state before marking a new copy verified.

## 3. Delta runs and verification

Run the **same plan command with the same state/configuration** again to inventory
arrivals. One normalized SQLite ledger owns all generations. Each immutable plan
contains only new/still-pending specifications, a source inventory hash and compact
provenance—not embedded ancestor plans. Old receipts, held work and source-absence
observations remain retained. Applying the new printed plan cannot recreate a
known copied occurrence.

```sh
# Local inspection, no credentials or network:
python3 migrate_mail.py status --state /private/jobs/mail-job-a

# Read known destination IDs without reading/writing source mail:
python3 migrate_mail.py verify --state /private/jobs/mail-job-a \
  --destination-credentials /private/credentials/destination.json
```

Verified copies with later destination-user read/star edits are reported as
conflicts and left alone; their immutable copy-time baseline is not rewritten.
Initial created copies with a flag conflict remain created for review. This
version does not synchronize later source flag changes automatically.

## Safety and supported limits

- **Copy only.** Source uses TLS-validated IMAPS, read-only EXAMINE and UID
  SEARCH/FETCH/BODY.PEEK. No SMTP/send, source STORE/CLOSE/EXPUNGE, deletion,
  DNS, account changes or mailbox moves exist.
- **One process per state directory.** State is private (`0700` directory,
  `0600` ledger/reports, `0400` job/plan files), locked with POSIX `flock`, using
  rollback-journal SQLite with `synchronous=FULL`. Symlink/hardlinked private
  files, malformed databases, unregistered plans and UIDVALIDITY changes stop
  the operation; there is no reset/reseed/repair command.
- **No blind retries.** A timeout, lost/missing acknowledgment or interrupted
  POST/APPEND becomes unresolved. Further planning/copying stops. An emergency
  ACK file is attempted if saving a returned receipt in SQLite fails. Retain
  everything and reconcile the existing destination copy manually; deleting
  state and rerunning can duplicate mail. Folder-creation failures also require
  inspection; there is no automatic request loop.
- IMAP destinations require **UIDPLUS/APPENDUID** (or IMAP4rev2) and readable
  destination folders. APPEND preserves raw CRLF mail, original INTERNALDATE
  and supported flags. Servers stripping/reformatting raw content or flags
  fail readback rather than triggering another copy.
- Gmail uses **messages.insert**, never send. Gmail's internal date comes from
  the original **Date header**, which can differ from source IMAP arrival time.
  Missing/invalid Date, missing/invalid Message-ID/From, malformed MIME, draft
  flags, deleted flags and messages over the nonresumable **25-MiB** raw ceiling
  become durable pre-write holds. Native editable Gmail drafts, resumable large
  uploads and generated/replacement headers are deliberately unsupported.
- Gmail comparison permits only one valid `gmailapi.google.com` HTTPREST
  Received prefix in addition to the original MIME/header fingerprint. Other
  rewriting stops at the saved created ID. Gmail preserves read/star flags;
  nonportable flags such as `\Answered` remain source metadata, not a claim of
  Gmail flag equivalence.
- Non-CRLF raw mail is held rather than silently normalized by `imaplib`.
  Default selected message bound is **25 MiB**; an explicit IMAP planning policy
  can raise it through **150 MiB**. Inventory is bounded to 1,000 folders /
  1,000,000 occurrences; a single plan is bounded to **256 MiB**. No full-size
  performance/acceptance claim is implied by these limits.
- Runtime is cooperative: no new work after its bound, but an admitted write's
  one bounded response is allowed to finish and its ACK is saved first. Socket
  timeouts are not a hard wall-clock kill against a trickling/malicious server.
- Ledger/reports store account identities, folder/UID/size/flag/date metadata,
  content hashes and destination receipts. Passwords/tokens, raw bodies, subjects
  and attachment contents are not archived. Protect state as client data.
- Existing mail copied by another tool is **not automatically recognized** by
  Message-ID/body. There is no safe import of the earlier client-specific ledger
  format in this version. **Do not point a fresh state at an already migrated
  mailbox and expect deduplication.** The original migration's state, approvals
  and unresolved work are unchanged by this extraction.

Exit codes: `0` successful bounded operation/status (not a full-migration
certificate), `3` held/unresolved work remains, `2` usage/safety refusal,
`1` unexpected runtime/transport failure, `130` interruption.

## Python library

```python
from mail_migrator import (
    Credentials, Deadline, Endpoint, IMAPDestination, IMAPSource,
    JobConfig, Migration, State,
)

config = JobConfig(
    source=Endpoint("imap.old.example", "alice@old.example"),
    destination=Endpoint("imap.new.example", "alice@new.example"),
)
# Obtain these objects from your job's approved secret source, not literals.
source_credentials = Credentials({"password": source_password})
destination_credentials = Credentials({"password": destination_password})
deadline = Deadline(300)
with State("/private/jobs/mail-job-a", config, create=True) as state:
    source = IMAPSource(config.source, source_credentials, deadline)
    try:
        destination = IMAPDestination(config.destination, destination_credentials, deadline)
        try:
            plan = Migration(state, source, destination, deadline).plan()
            # Inspect plan; a later migrate(..., apply=True) is a separate choice.
        finally:
            destination.close()
    finally:
        source.close()
```

The CLI is a thin wrapper over the same `Migration.plan`, `migrate`, `verify`
and `State.status` API. Transports can be injected for offline testing; their
`endpoint` must match the frozen job identity, and the destination declares its
`kind` (`imap` or `gmail`).

## Development

```sh
EMAIL_MIGRATOR_TEST_CASE="$PWD/.cases/<your-session-id>" \
  python3 -B -m unittest discover -s tests -t . -v
```

Tests use synthetic MIME, private disposable state and fake IMAP/HTTP transports.
Network connections are blocked; no live credentials, uploads or mail are used.
The initial portable version has **not** been validated against live accounts.
Source is version-controlled in the private
[`zayadur/email-migrator`](https://github.com/zayadur/email-migrator) repository.
Case artifacts, build output, credentials and migration state are Git-ignored.

Protocol references: [Python imaplib](https://docs.python.org/3/library/imaplib.html),
[UIDPLUS](https://www.rfc-editor.org/rfc/rfc4315),
[Gmail insert](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/insert),
[Gmail raw readback](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get).
