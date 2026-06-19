"""The `deadline-room` command line: serve, replay, and demo the governance spine.

This is the pip-installable entry point (pyproject `[project.scripts]` ->
`deadline-room`). It is a thin command surface over the same sealed/signed spine
the rest of the project verifies; it adds no new source of truth.

  deadline-room serve [--data-dir DIR] [--host H] [--port P]
        Start the long-running governance API (FastAPI under uvicorn) over a
        sealed-artifact corpus directory. Read endpoints serve the signed
        portfolio, insights, SLA, and queue; the write endpoint seals a posted
        incident offline. This is the standing daemon a CISO office runs.

  deadline-room replay RUN_LOG.jsonl
        Replay a captured run log byte-for-byte and verify its detached signature
        against the committed public key. Prints whether the replay is
        byte-identical and whether the signature is VALID, and exits nonzero on any
        mismatch. Read-only; it seals nothing.

  deadline-room demo [--mode MODE] [--incident-id ID] [--data-dir DIR]
        Run one incident OFFLINE through the floor and seal it into a corpus, then
        print the refreshed queue and portfolio root. With no --data-dir it seals
        into a throwaway temporary corpus so the committed captures are untouched.
        `deadline-room --demo` is accepted as an alias.

Every command is offline by default: no live Band room, no API keys.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_DATA_DIR = REPO_ROOT / "web" / "data"


def _cmd_serve(args: argparse.Namespace) -> int:
    """Start the governance API under uvicorn over a corpus directory."""
    import uvicorn

    from service.app import create_app

    data_dir = Path(args.data_dir).resolve()
    app = create_app(data_dir)
    print(f"deadline-room: serving the governance API over {data_dir}")
    print(f"  read:  GET  http://{args.host}:{args.port}/portfolio | /queue | "
          "/sla | /insights")
    print(f"  write: POST http://{args.host}:{args.port}/incidents")
    print(f"  health: GET http://{args.host}:{args.port}/healthz | /readyz")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    """Replay a captured run log byte-for-byte and verify its signature."""
    from warden.replay import RunLog, replay
    from warden.signing import (
        DEMO_KEY_CAVEAT,
        fingerprint,
        load_public_key_hex,
        verify_run_log_jsonl,
    )

    log_path = Path(args.run_log).resolve()
    if not log_path.exists():
        print(f"deadline-room: no run log at {log_path}", file=sys.stderr)
        return 2
    log = RunLog.load(log_path)
    replayed = replay(log)
    byte_identical = replayed.to_jsonl() == log.to_jsonl()

    sig_path = log_path.with_suffix(log_path.suffix + ".sig.json")
    signature: dict | None = None
    if sig_path.exists():
        signature = json.loads(sig_path.read_text(encoding="utf-8"))

    print(f"Run log         : {log_path}")
    print(f"Run-log sha256  : {log.sha256()}")
    print(f"Byte-identical  : {'YES' if byte_identical else 'NO'}")
    sig_ok = False
    if signature is not None:
        sig_ok = verify_run_log_jsonl(log.to_jsonl(), signature)
        print(f"Signature       : {'VALID' if sig_ok else 'INVALID'}")
        print(f"Signer fp       : {fingerprint(load_public_key_hex())}")
    else:
        print("Signature       : (no sidecar found beside the run log)")
    print(f"Note: {DEMO_KEY_CAVEAT}")

    if not byte_identical:
        return 1
    if signature is not None and not sig_ok:
        return 1
    return 0


def _run_demo(mode: str, incident_id: str, data_dir: Path) -> int:
    """Run one incident offline, seal it, and print the refreshed queue."""
    from service.corpus import Corpus
    from service.worker import IncidentRequest, run_incident_offline

    data_dir.mkdir(parents=True, exist_ok=True)
    request = IncidentRequest(incident_id=incident_id, mode=mode)
    sealed = run_incident_offline(request, data_dir)
    corpus = Corpus(data_dir)
    att = corpus.attestation()
    queue = corpus.queue()

    print("=" * 78)
    print("DEADLINE ROOM DEMO: posted incident run offline, sealed, and queued")
    print("=" * 78)
    print(f"Corpus directory : {data_dir}")
    print(f"Sealed run log   : {sealed.run_log_name}")
    print(f"Run-log sha256   : {sealed.sha256}")
    print(f"Chain head       : {sealed.chain_head}")
    print(f"Signature valid  : {'YES' if sealed.signature_valid else 'NO'}")
    print(f"Portfolio root   : {att.root}  ({att.run_count} attested runs)")
    print("Queue (nearest statutory deadline first):")
    for item in queue["items"]:
        deadline = item["nearest_deadline_utc"] or "(no deadline)"
        print(f"  [{item['status']:<10}] {item['key']}  due {deadline}")
    print("=" * 78)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    """Seal a posted incident into a corpus and print the queue (offline)."""
    if args.data_dir is None:
        with tempfile.TemporaryDirectory(prefix="deadline-room-demo-") as tmp:
            return _run_demo(args.mode, args.incident_id, Path(tmp))
    return _run_demo(args.mode, args.incident_id, Path(args.data_dir).resolve())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deadline-room",
        description=(
            "Standing governance service over the sealed/signed Deadline Room "
            "corpus: serve the API, replay a run, or seal a demo incident."))
    # `deadline-room --demo` alias for `deadline-room demo`.
    parser.add_argument(
        "--demo", action="store_true",
        help="alias for the demo subcommand (run one incident offline + queue it)")
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="start the governance API (uvicorn)")
    p_serve.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                         help="sealed-artifact corpus directory to serve")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=_cmd_serve)

    p_replay = sub.add_parser(
        "replay", help="replay a run log byte-for-byte and verify its signature")
    p_replay.add_argument("run_log", help="path to a captured run-*.jsonl")
    p_replay.set_defaults(func=_cmd_replay)

    p_demo = sub.add_parser(
        "demo", help="run one incident offline, seal it, and print the queue")
    p_demo.add_argument("--mode", default="normal",
                        help="offline floor beat (normal, inject_contradiction, "
                             "chaos, amendment)")
    p_demo.add_argument("--incident-id", default="inc-demo",
                        help="incident id for the sealed run")
    p_demo.add_argument("--data-dir", default=None,
                        help="corpus directory to seal into (default: a throwaway "
                             "temp dir so committed captures are untouched)")
    p_demo.set_defaults(func=_cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # `deadline-room --demo` with no subcommand runs the demo with defaults.
    if getattr(args, "command", None) is None:
        if getattr(args, "demo", False):
            return _run_demo("normal", "inc-demo", _demo_temp_dir())
        parser.print_help()
        return 0
    return args.func(args)


def _demo_temp_dir() -> Path:
    """A throwaway corpus directory for `deadline-room --demo` (no --data-dir), so
    the committed captures are never touched. The directory persists for the life
    of the process so the printed queue refers to a real sealed file."""
    return Path(tempfile.mkdtemp(prefix="deadline-room-demo-"))


if __name__ == "__main__":
    raise SystemExit(main())
