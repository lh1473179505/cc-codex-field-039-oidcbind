"""CLI. inspect already works; redeem is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from oidcbind.load import LoadError, load_json
from oidcbind.b64 import at_hash, s256, split_jwt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oidcbind")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show session, callback, and unvalidated id_token claims")
    ins.add_argument("--client", required=True)
    ins.add_argument("--session", required=True)
    ins.add_argument("--callback", required=True)
    ins.add_argument("--token", required=False)
    red = sub.add_parser("redeem", help="bind the callback and token response to the pending session")
    red.add_argument("--client", required=True)
    red.add_argument("--session", required=True)
    red.add_argument("--callback", required=True)
    red.add_argument("--token", required=True)
    red.add_argument("--now", type=int, default=1763000000)
    red.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        client = load_json(args.client)
        session = load_json(args.session)
        callback = load_json(args.callback)
    except LoadError as exc:
        print(f"failed to load inputs: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "inspect":
        payload = {
            "client_id": client.get("client_id"),
            "session": {
                "state": session.get("state"),
                "nonce": session.get("nonce"),
                "issuer": session.get("issuer"),
                "redirect_uri": session.get("redirect_uri"),
                "code_challenge": s256(session["code_verifier"]) if session.get("code_verifier") else None,
            },
            "callback": callback,
        }
        token = None
        if getattr(args, "token", None):
            try:
                token = load_json(args.token)
            except LoadError as exc:
                print(f"failed to load token: {exc}", file=sys.stderr)
                return 2
            idt = token.get("id_token")
            if idt:
                try:
                    header, claims, _, _ = split_jwt(idt)
                    payload["id_token_unverified"] = {"header": header, "claims": claims}
                    if token.get("access_token"):
                        payload["expected_at_hash"] = at_hash(token["access_token"])
                except ValueError as exc:
                    payload["id_token_error"] = str(exc)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "redeem":
        try:
            token = load_json(args.token)
        except LoadError as exc:
            print(f"failed to load token: {exc}", file=sys.stderr)
            return 2
        from oidcbind.engine import redeem
        try:
            report = redeem(client, session, callback, token, args.now)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
