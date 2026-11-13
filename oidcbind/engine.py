"""OIDC authorization-code redemption. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any


def redeem(
    client: dict[str, Any],
    session: dict[str, Any],
    callback: dict[str, Any],
    token: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    raise NotImplementedError("redeem is not implemented in this snapshot")
