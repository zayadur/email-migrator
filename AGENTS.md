# Email Migrator — independent utility

This is an organization-neutral Python CLI/library, like `../pdf-translator`.
It is not an M3-owned project. A migration job, not this directory, determines
the owning organization and permitted accounts.

- Require explicit source/destination identities and credential-file or named
  environment-variable flags. Never default to a laptop account, vault profile,
  cloud project, or a previous client's credentials.
- `migrate_mail.py` is the local CLI; `mail_migrator/` is the importable package.
  Keep operator instructions and supported limitations in `README.md`.
- Development is offline. Tests use synthetic MIME and fake transports, never
  real mailbox credentials. Retain test artifacts under `.cases/<session-id>/`.
- State directories contain private client metadata. Ignore state, credentials,
  raw mail and case artifacts. Never import a previous migration's checkpoints
  or client data as fixtures, and never publish them.
- Source access is read-only. No sending, deletion, expunge, DNS, account changes
  or automatic header normalization belongs in this tool.
- Destination copies require explicit apply mode and a hash-bound immutable
  plan. Preserve returned acknowledgments before alias/deadline/readback checks.
  Never retry an uncertain write or reset/reseed an existing checkpoint.
- Creating this library does not authorize a live migration, replacement of a
  prior client's tooling, or modification of its ledgers and approval records.
- Do not initialize Git, connect a remote or publish without a separate request.
