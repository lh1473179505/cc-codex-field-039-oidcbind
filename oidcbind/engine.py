"""Bind a pending session, a callback, and a captured token response."""

from __future__ import annotations

import hmac
from typing import Any

from oidcbind.b64 import at_hash, hs256, s256, split_jwt


def _normalize_issuer(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if value.endswith("/"):
        return value[:-1]
    return value


def _same_string(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _deny(reason_codes: list[str]) -> dict[str, Any]:
    return {
        "decision": "deny",
        "reason_codes": reason_codes,
        "subject": None,
        "issuer": None,
        "access_token_ok": False,
    }


def redeem(
    client: dict[str, Any],
    session: dict[str, Any],
    callback: dict[str, Any],
    token: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    reasons: list[str] = []

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    expected_issuer = _normalize_issuer(session.get("issuer"))

    # Callback: an authorization error short-circuits before token inspection.
    if callback.get("error"):
        return _deny(["authorization_error"])

    if not callback.get("code"):
        add("missing_code")
    if not _same_string(callback.get("state"), session.get("state")):
        add("state_mismatch")

    callback_iss = callback.get("iss")
    if callback_iss is None:
        if client.get("require_iss"):
            add("missing_iss")
    elif _normalize_issuer(callback_iss) != expected_issuer:
        add("iss_mismatch")

    if session.get("spent"):
        add("replay")

    # Token body checks.
    if str(token.get("token_type", "")).lower() != "bearer":
        add("bad_token_type")

    access_token = token.get("access_token")
    id_token = token.get("id_token")
    if not access_token or not id_token:
        add("missing_token")

    token_issuer = token.get("iss", token.get("issuer"))
    if token_issuer is not None and _normalize_issuer(token_issuer) != expected_issuer:
        add("iss_mismatch")

    if token.get("source_endpoint") != session.get("token_endpoint"):
        add("token_endpoint_mismatch")

    redirect_uri = session.get("redirect_uri")
    if redirect_uri not in client.get("redirect_uris", []):
        add("redirect_mismatch")
    if "redirect_uri" in token and token.get("redirect_uri") != redirect_uri:
        add("redirect_mismatch")

    # PKCE: only S256 is accepted.
    if session.get("code_challenge_method") != "S256":
        add("pkce_method")
    else:
        verifier = session.get("code_verifier")
        if "code_verifier_echo" in token and not _same_string(
            token.get("code_verifier_echo"), verifier
        ):
            add("pkce_mismatch")
        challenge = session.get("code_challenge")
        if challenge is not None and verifier is not None:
            if not hmac.compare_digest(s256(verifier), challenge):
                add("pkce_mismatch")

    if "code" in token and callback.get("code") and not _same_string(
        token.get("code"), callback.get("code")
    ):
        add("code_mismatch")

    # ID token: split, verify the HS256 signature, then validate the claims.
    claims: dict[str, Any] | None = None
    if id_token:
        try:
            header, claims, signing_input, signature = split_jwt(id_token)
        except ValueError:
            add("bad_jwt")
        else:
            if header.get("alg") != "HS256":
                add("bad_alg")
            else:
                secret = str(client.get("client_secret", "")).encode("utf-8")
                if not hmac.compare_digest(hs256(secret, signing_input), signature):
                    add("bad_signature")

            if "typ" in header and header.get("typ") != "JWT":
                add("bad_typ")

            if _normalize_issuer(claims.get("iss")) != expected_issuer:
                add("iss_mismatch")

            audience = claims.get("aud")
            client_id = client.get("client_id")
            if isinstance(audience, str):
                if audience != client_id:
                    add("aud_mismatch")
            elif isinstance(audience, list):
                if client_id not in audience:
                    add("aud_mismatch")
                elif len(audience) > 1:
                    authorized_party = claims.get("azp")
                    if authorized_party is None:
                        add("missing_azp")
                    elif authorized_party != client_id:
                        add("azp_mismatch")
            else:
                add("aud_mismatch")

            expiration = claims.get("exp")
            if not _is_number(expiration):
                add("bad_claim")
            elif expiration <= now:
                add("expired")

            not_before = claims.get("nbf")
            if not_before is not None:
                if not _is_number(not_before):
                    add("bad_claim")
                elif not_before > now:
                    add("not_yet")

            nonce = claims.get("nonce")
            if nonce is None:
                add("missing_nonce")
            elif not _same_string(nonce, session.get("nonce")):
                add("nonce_mismatch")

            if isinstance(access_token, str) and access_token:
                access_hash = claims.get("at_hash")
                if access_hash is None:
                    add("missing_at_hash")
                elif not hmac.compare_digest(access_hash, at_hash(access_token)):
                    add("at_hash_mismatch")

    if reasons:
        return _deny(reasons)

    return {
        "decision": "allow",
        "reason_codes": [],
        "subject": claims.get("sub") if claims else None,
        "issuer": expected_issuer,
        "access_token_ok": True,
    }
