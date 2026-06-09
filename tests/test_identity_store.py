from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_agent_safe_protecter.identity.store import IdentityStore


class IdentityStoreTests(unittest.TestCase):
    def test_verification_roundtrip(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "id.sqlite3"
        store = IdentityStore(tmp)
        try:
            store.save_verification("email", "a@b.com", "123456", "register_email", 3600)
            self.assertTrue(
                store.consume_verification("email", "a@b.com", "123456", "register_email")
            )
            self.assertFalse(
                store.consume_verification("email", "a@b.com", "123456", "register_email")
            )
        finally:
            store.close()

    def test_email_link_verify_and_consume(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "id.sqlite3"
        store = IdentityStore(tmp)
        try:
            raw = store.save_email_verification_link(
                "link@example.com", "register_email_link", 3600
            )
            self.assertTrue(len(raw) >= 10)
            self.assertTrue(
                store.verify_email_link_token(
                    "link@example.com",
                    raw,
                    "register_email_link",
                    consume=False,
                )
            )
            self.assertTrue(
                store.verify_email_link_token(
                    "link@example.com",
                    raw,
                    "register_email_link",
                    consume=True,
                )
            )
            self.assertFalse(
                store.verify_email_link_token(
                    "link@example.com",
                    raw,
                    "register_email_link",
                    consume=False,
                )
            )
        finally:
            store.close()

    def test_password_login_multi_id(self) -> None:
        tmp = Path(tempfile.mkdtemp()) / "id.sqlite3"
        store = IdentityStore(tmp)
        try:
            store.create_user_with_password(
                username="u1",
                email="u1@example.com",
                phone="13800138000",
                password="secretsecret",
                email_verified=True,
                phone_verified=True,
            )
            self.assertEqual(store.verify_password_login("u1", "secretsecret"), "u1")
            self.assertEqual(
                store.verify_password_login("u1@example.com", "secretsecret"), "u1"
            )
            self.assertEqual(store.verify_password_login("13800138000", "secretsecret"), "u1")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
