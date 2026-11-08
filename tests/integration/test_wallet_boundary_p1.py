"""P1 boundary: a server-held key cannot be presented as user controlled."""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto.sdk import v1
from services.user_side.portal_api.app import PortalContext, PortalDesk
from user_credential_handler.handler import UserCredentialHandler


class _Store:
    def load(self):
        return {}

    def update(self, fn):
        return fn({})


class _Port:
    def get(self, path):
        return {}

    def post(self, path, body, owner):
        return {}


def _ctx(handler, profile):
    ports = {name: _Port() for name in ("tp", "ap", "phc", "agent")}
    return PortalContext(wallet_root=Path("."), store=_Store(), auth=None,
                         handlers={handler.owner: handler}, execution_profile=profile,
                         **ports)


def test_service_held_test_key_cannot_be_claimed_as_user_controlled(tmp_path):
    handler = UserCredentialHandler(tmp_path / "wallet")
    assert handler.user_controlled is False
    with pytest.raises(Exception, match="独立控钥"):
        PortalDesk(_ctx(handler, "user-controlled"))._executor(handler.owner)


def test_production_profile_rejects_server_side_signing(tmp_path):
    handler = UserCredentialHandler(tmp_path / "wallet")
    with pytest.raises(Exception, match="拒绝代签"):
        PortalDesk(_ctx(handler, "production"))._executor(handler.owner)


def test_prepared_cr_endpoint_rejects_plain_identity_fields(tmp_path):
    class _Controlled:
        def __init__(self, owner):
            self.owner = owner

        def custody_profile(self):
            return "user-controlled"

    hsm = v1.make_demo_hsm(domain="USER")
    handler = _Controlled(v1.owner_of(hsm.pubkey()))
    desk = PortalDesk(_ctx(handler, "user-controlled"))
    with pytest.raises(ValueError, match="只接受"):
        desk.create_application(handler.owner, {"pii": {"ID": "synthetic"}, "bi": {}})
