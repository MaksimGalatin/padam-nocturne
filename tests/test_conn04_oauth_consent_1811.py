"""Фаза 2 аудита GLM, CONN-04: согласие OAuth только явное; токен владельца только из формы согласия."""
import base64, hashlib

import pytest

from padam import oauth


def _req(srv, **extra):
    c = srv.register_client({"redirect_uris": ["http://127.0.0.1:9/cb"], "client_name": "t"})
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    p = {"response_type": "code", "client_id": c["client_id"], "redirect_uri": "http://127.0.0.1:9/cb",
         "code_challenge": challenge, "code_challenge_method": "S256", "scope": "padam:write", "state": "s1",
         "owner_token": "owner-secret"}
    p.update(extra)
    return p


def test_без_решения_отказ():
    srv = oauth.LocalOAuth21Server("http://127.0.0.1:9", "owner-secret")
    redirect = srv.approve_or_deny(_req(srv))          # decision опущен
    assert "error=access_denied" in redirect and "code=" not in redirect


def test_явное_согласие_выдаёт_код():
    srv = oauth.LocalOAuth21Server("http://127.0.0.1:9", "owner-secret")
    assert "code=" in srv.approve_or_deny(_req(srv, decision="approve"))


def test_заголовок_authorization_не_подставляется():
    import inspect
    from padam import mcp_server
    src = inspect.getsource(mcp_server)
    assert 'oa_params["owner_token"] = auth_hdr' not in src
