# oidcbind

An OpenID Connect authorization-code relying-party binder. It has to join a pending session, a callback, and a captured token response: state, PKCE S256, issuer mix-up, redirect exact match, and id_token nonce / at_hash / audience.

`python -m oidcbind inspect --client fixtures/client.json --session fixtures/sessions/ok.json --callback fixtures/callbacks/ok.json --token fixtures/tokens/ok.json` already prints unverified claims. `redeem` is still a stub; printing claims is not acceptance.

Standard library only. No Docker, no OIDC SDK, no network calls.
