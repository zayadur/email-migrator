"""Small CLI facade; endpoint identities are frozen per state directory."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import signal
import sys

from . import __version__
from .credentials import load_credentials
from .engine import Migration
from .errors import MigrationError
from .gmail import GmailDestination
from .imap import IMAPDestination, IMAPSource
from .models import Endpoint, JobConfig
from .security import Deadline, strict_json
from .state import State


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unrecognized values, which can be secrets
        # accidentally supplied as unsupported password flags.
        raise MigrationError("Invalid command-line arguments. Use --help; passwords must be in files or named environment variables.")


def parser():
    cli = Parser(description="Read-only-source, resumable IMAP/Gmail migration. Defaults to planning; never sends mail.")
    cli.add_argument("command", nargs="?", default="plan", choices=("plan", "migrate", "verify", "status"))
    cli.add_argument("--version", action="version", version=__version__)
    cli.add_argument("--state", type=Path, required=True, help="Private directory for this exact account pair and policy.")
    cli.add_argument("--source-host")
    cli.add_argument("--source-user")
    cli.add_argument("--source-port", type=int)
    cli.add_argument("--source-auth", choices=("password", "xoauth2"))
    cli.add_argument("--destination-type", choices=("imap", "gmail"))
    cli.add_argument("--destination-host")
    cli.add_argument("--destination-user")
    cli.add_argument("--destination-port", type=int)
    cli.add_argument("--destination-auth", choices=("password", "xoauth2"))
    for side in ("source", "destination"):
        group = cli.add_mutually_exclusive_group()
        group.add_argument(f"--{side}-credentials", type=Path, help="Private credential JSON file (0600/0400); never copied to state.")
        group.add_argument(f"--{side}-secret-env", help="Explicit environment-variable NAME, not its value; Gmail uses a JSON OAuth object.")
    cli.add_argument("--folder", action="append", help="Scope to a source folder; repeat. Default: every selectable folder.")
    cli.add_argument("--mapping", type=Path, help="Nonsecret JSON object: source folder -> destination folder/label.")
    cli.add_argument("--create-folders", action="store_true", help="Enroll permission to create missing destination folders/labels during --apply only.")
    cli.add_argument("--max-message-bytes", type=int, help="Planning policy; default 25 MiB (Gmail's nonresumable ceiling stays 25 MiB).")
    cli.add_argument("--runtime", type=int, default=300, help="Cooperative invocation bound in seconds; returned ACKs are saved even after expiry.")
    cli.add_argument("--limit", type=int, help="Pending attempts/readbacks this run. First real proof is always limited to one.")
    cli.add_argument("--dry-run", action="store_true", help="Explicit planning-only synonym for the default plan command.")
    cli.add_argument("--apply", action="store_true", help="Required with migrate; authorizes the enrolled destination copies only.")
    cli.add_argument("--plan", type=Path)
    cli.add_argument("--plan-sha256")
    return cli


def config_from_args(args):
    if not args.source_host or not args.source_user or not args.destination_user or not args.destination_type:
        raise MigrationError("Planning requires explicit --source-host, --source-user, --destination-type and --destination-user.")
    mapping = {}
    if args.mapping:
        # Mapping is not a credential; normal readable files are permitted.
        mapping_path = args.mapping.expanduser()
        if mapping_path.stat().st_size > 65536:
            raise MigrationError("Folder mapping file exceeds 64 KiB.")
        mapping = strict_json(mapping_path.read_bytes())
    source = Endpoint(args.source_host, args.source_user, args.source_port if args.source_port is not None else 993, args.source_auth or "password")
    if args.destination_type == "gmail":
        if args.destination_host or args.destination_port or args.destination_auth:
            raise MigrationError("Gmail uses its pinned API endpoint and OAuth, not destination IMAP flags.")
        destination = Endpoint("gmail.googleapis.com", args.destination_user, 443, "gmail-oauth", "gmail")
    else:
        if not args.destination_host:
            raise MigrationError("IMAP destination requires --destination-host.")
        destination = Endpoint(args.destination_host, args.destination_user, args.destination_port if args.destination_port is not None else 993,
                               args.destination_auth or "password")
    return JobConfig(source, destination, tuple(args.folder or ()), mapping,
                     args.max_message_bytes if args.max_message_bytes is not None else 25 * 1024 * 1024, args.create_folders)


def main(argv=None):
    handlers = {}
    try:
        args = parser().parse_args(argv)
        if args.command != "plan" and args.dry_run:
            raise MigrationError("--dry-run is planning-only; it cannot be combined with migrate/verify/status.")
        if args.apply != (args.command == "migrate"):
            raise MigrationError("Only migrate uses --apply, and migrate requires it explicitly.")
        if args.limit is not None and args.limit <= 0:
            raise MigrationError("--limit must be positive.")
        config = config_from_args(args) if args.command == "plan" else None
        if args.command != "plan" and any(v is not None for v in (
                args.source_host, args.source_user, args.source_port, args.source_auth,
                args.destination_type, args.destination_host, args.destination_user,
                args.destination_port, args.destination_auth, args.folder, args.mapping)):
            raise MigrationError("Existing jobs use frozen job.json identities; pass credentials, not new endpoint/scope flags.")
        if args.command != "plan" and (args.create_folders or args.max_message_bytes is not None):
            raise MigrationError("Folder-creation and size policies must be enrolled during planning, not changed on resume.")
        if args.command != "migrate" and (args.plan is not None or args.plan_sha256 is not None):
            raise MigrationError("Plan selection is only used with migrate --apply.")
        deadline = Deadline(args.runtime)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, deadline.stop)
        with State(args.state, config, create=args.command == "plan") as state:
            if args.command == "status":
                print(json.dumps(state.status(), indent=2))
                return 0
            state.refuse_uncertain(include_created=args.command == "plan")
            with ExitStack() as clients:
                config = state.config
                source = None
                dest_credentials = load_credentials(path=args.destination_credentials,
                    env=args.destination_secret_env, auth=config.destination.auth)
                if args.command != "verify":
                    credentials = load_credentials(path=args.source_credentials,
                        env=args.source_secret_env, auth=config.source.auth)
                    source = IMAPSource(config.source, credentials, deadline)
                    clients.callback(source.close)
                destination_type = GmailDestination if config.destination.kind == "gmail" else IMAPDestination
                destination = destination_type(config.destination, dest_credentials, deadline)
                clients.callback(destination.close)
                runner = Migration(state, source, destination, deadline)
                if args.command == "plan":
                    result = runner.plan()
                elif args.command == "migrate":
                    if args.plan is None or args.plan_sha256 is None:
                        raise MigrationError("migrate requires --plan and --plan-sha256 from its planning output.")
                    result = runner.migrate(args.plan, args.plan_sha256, apply=True, limit=args.limit)
                else:
                    result = runner.verify(limit=args.limit)
            status = state.status()
            summary = {k: v for k, v in result.items() if k not in ("verified", "new_holds", "checkpoint", "status")}
            summary.update(verified_this_run=len(result.get("verified", [])),
                           held_this_run=len(result.get("new_holds", [])), states=status["states"],
                           all_holds_remain_unfinished=bool(status["held"]))
            print(json.dumps(summary, indent=2))
            return 3 if status["held"] or status["unresolved_writes"] else 0
    except MigrationError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Stopped. Retain state and saved receipts; do not reset or blindly repeat a write.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Stopped ({type(error).__name__}). Provider details withheld; retain state for inspection.", file=sys.stderr)
        return 1
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
