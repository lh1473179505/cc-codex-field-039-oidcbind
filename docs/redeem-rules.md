# Redeem rules

Reuse `load_json`, and the helpers in `oidcbind.b64` (`s256`, `at_hash`, `split_jwt`, `hs256`, `b64url`). Do not call a network token endpoint; the `--token` file is a captured token-endpoint JSON body. Do not accept an id_token just because inspect can print its claims.

`--now` defaults to 1763000000.

## Session and callback

The pending session is what the client stored when it sent the authorization request:

- `issuer` — expected issuer URL, no trailing slash unless it was stored that way (compare exactly after stripping a single trailing slash on both sides)
- `authorization_endpoint`, `token_endpoint`
- `redirect_uri` — must be compared *exactly* with `client.redirect_uris` membership and with any `redirect_uri` echoed in the token request metadata (`token.redirect_uri` if present). A prefix match is `redirect_mismatch`.
- `state`, `nonce`, `code_verifier`, `code_challenge_method` (public fixtures: `S256`)
- `spent` — if true, this session already redeemed a code (`replay`)

The callback query object must contain `code` and `state`. Missing code is `missing_code`. `state` must equal the session state (constant-time string compare); otherwise `state_mismatch`. If the callback has `error`, deny `authorization_error` and do not inspect the token. If the callback includes `iss`, it must equal the (normalized) session issuer; otherwise `iss_mismatch` (mix-up). If the callback omits `iss` and `client.require_iss` is true (public client: true), deny `missing_iss`.

## Token response

- `token_type` must be `Bearer` (case-insensitive). Else `bad_token_type`.
- `access_token` and `id_token` are required (`missing_token`).
- If the token body has `iss` or `issuer`, it must match the session issuer (`iss_mismatch`).
- The client must use `session.token_endpoint` as the source of this body (recorded as `token.source_endpoint` in fixtures). If `token.source_endpoint` is missing or not equal to `session.token_endpoint`, deny `token_endpoint_mismatch`. This is the other half of mix-up: a code from issuer A must not be accepted at issuer B's token endpoint.
- `token.redirect_uri`, if present, must equal the session redirect URI exactly.
- If `session.spent` is true, deny `replay` even when everything else matches.

## PKCE and code

The lab does not resend the HTTP form, but the token body may include `code_verifier_echo` in fixtures for checks. If it is present, it must equal `session.code_verifier`. Independently, you must compute `s256(session.code_verifier)` and, if the session stored `code_challenge`, compare them (`pkce_mismatch`). `code_challenge_method` other than `S256` is `pkce_method` (the only method the public client allows). If the callback `code` does not equal `token.code` when `token.code` is present, `code_mismatch`.

## ID token

Split with `split_jwt`. Header `alg` must be `HS256`; anything else including `none` is `bad_alg`. Do not use a key from the token header. The HMAC key is `client.client_secret` as UTF-8. Compare with `hmac.compare_digest` against `hs256(...)`. Failure is `bad_signature`.

Claims, all required unless noted:

- `iss` equals the normalized session issuer (`iss_mismatch`)
- `aud` is a string equal to `client.client_id`, or a list containing it. If `aud` is a list of more than one value, `azp` must be present and equal to `client.client_id` (`azp_mismatch` or `missing_azp`). A string `aud` that equals some other client is `aud_mismatch`.
- `exp` is a number; `exp <= now` is `expired`. `nbf` if present: `nbf > now` is `not_yet`. Times must be numbers, not strings (`bad_claim`).
- `nonce` must equal the session nonce (`nonce_mismatch`). Missing nonce is `missing_nonce`.
- `at_hash` must equal `at_hash(access_token)` (`at_hash_mismatch`). Missing `at_hash` is `missing_at_hash`.
- `typ` in the header, if present, must be `JWT` (exact). Else `bad_typ`.

`client_secret` must not appear in the report.

## Report

- `decision`, `reason_codes` (empty on allow)
- `subject`: the `sub` claim on allow, else null
- `issuer`: the accepted issuer on allow, else null
- `access_token_ok`: boolean (true only when at_hash and the rest passed)

Exit 0 / 1 / 2 as usual.

## Public fixtures

`--client fixtures/client.json --now 1763000000`, plus the same-named files under `fixtures/sessions`, `fixtures/callbacks`, `fixtures/tokens`:

- `ok` → allow, subject `user-alice`
- `mixup-iss` → deny `iss_mismatch` (callback iss is a different issuer)
- `mixup-endpoint` → deny `token_endpoint_mismatch`
- `bad-state` → deny `state_mismatch`
- `bad-nonce` → deny `nonce_mismatch`
- `bad-athash` → deny `at_hash_mismatch`
- `replay` → deny `replay` (session.spent is true)
- `redirect-prefix` → deny `redirect_mismatch` (token.redirect_uri is a prefix extension)
