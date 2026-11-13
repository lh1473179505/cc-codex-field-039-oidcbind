"""URL-safe base64 and PKCE helpers. Token redemption logic is not implemented here."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def s256(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def at_hash(access_token: str, alg: str = "HS256") -> str:
    if alg != "HS256":
        raise ValueError("only HS256 is used in this lab")
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return b64url(digest[:16])


def split_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    try:
        h, p, s = token.split(".")
    except ValueError as exc:
        raise ValueError("bad_jwt") from exc
    header = json.loads(b64url_decode(h).decode("utf-8"))
    payload = json.loads(b64url_decode(p).decode("utf-8"))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = b64url_decode(s)
    return header, payload, signing_input, sig


def hs256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
