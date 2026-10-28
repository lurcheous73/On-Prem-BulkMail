"""Synthetic identity and actual-handler HTTP checks; no real mail or portal calls."""
import copy
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.cookies import SimpleCookie
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grange_ct400_sso as sso
import patch_app

SUBJECT = "11111111-1111-4111-8111-111111111111"
NEW_SUBJECT = "22222222-2222-4222-8222-222222222222"
BASELINE = Path(os.environ.get("MEET_BASELINE_PATH", "/tmp/grange-meet-canada-baseline.py"))


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="grange-meet-sso-test-")
        self.root = Path(self.temp.name)
        self.path = self.root / "private.json"
        self.audit = self.root / "audit.jsonl"
        self.now = int(time.time())
        self.context = {"HOSTS": {"julie": {"name": "Existing Julie", "email": "old@example.invalid", "admin": False},
                                  "support": {"name": "Existing Support", "email": "support@example.invalid", "admin": True}},
                        "SESSIONS": {"existing-token": {"username": "julie", "expires": self.now + 28800}}}
        self.original_hosts = copy.deepcopy(self.context["HOSTS"])
        self.cfg = {"enabled": True, "client_secret": "fixture-secret-" + "x" * 40,
                    "subjects": {SUBJECT: "julie", NEW_SUBJECT: "ct400-new"},
                    "additional_hosts": {"ct400-new": {"name": "New Work Host", "email": "new@example.invalid", "admin": False}}}
        self.calls = []
        self.identity = {"issuer": sso.ISSUER, "subject": SUBJECT, "username": "untrusted-profile-name",
                         "email": "profile@example.invalid", "display_name": "Work User", "auth_time": self.now}
        self.write_config()
        self.client = sso.PortalClient(self.context, self.path, self.exchange, lambda: self.now, self.audit)

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self):
        self.path.write_text(json.dumps(self.cfg))

    def exchange(self, cfg, code, verifier):
        self.calls.append((code, verifier))
        return {"identity": dict(self.identity), "expires_in": 900}

    def flow(self):
        target, cookie = self.client.begin()
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
        parsed = SimpleCookie(); parsed.load(cookie)
        return params, parsed[sso.PENDING_COOKIE].value, target, cookie

    def finish(self, params, nonce, **extra):
        values = {"state": params["state"][0], "code": "c" * 43, **extra}
        return self.client.finish(urllib.parse.urlencode(values), nonce)

    def test_begin_uses_pinned_broker_state_pkce_and_secure_cookie(self):
        params, nonce, target, cookie = self.flow()
        self.assertTrue(target.startswith(sso.BROKER_ORIGIN + "/?"))
        self.assertEqual(params["redirect_uri"], [sso.CALLBACK])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(len(nonce), 43)
        self.assertNotIn(self.cfg["client_secret"], target + cookie)
        self.assertIn("HttpOnly; Secure; SameSite=Lax", cookie)
        self.assertTrue(cookie.startswith("__Host-"))
        self.assertIn("Path=/;", cookie)
        self.assertNotIn("Domain=", cookie)
        pending = self.client.pending[sso._token_hash(nonce)]
        self.assertEqual(params["code_challenge"], [sso._challenge(pending["verifier"])])

    def test_mapped_guid_preserves_legacy_owner_and_privileges(self):
        params, nonce, _, _ = self.flow()
        cookie = self.finish(params, nonce)
        parsed = SimpleCookie(); parsed.load(cookie)
        session = self.context["SESSIONS"][parsed[sso.SESSION_COOKIE].value]
        self.assertEqual(session["username"], "julie")
        self.assertEqual(session["subject"], SUBJECT)
        self.assertEqual(session["expires"], self.now + 900)
        for name, profile in self.original_hosts.items():
            self.assertEqual(self.context["HOSTS"][name], profile)
        self.assertIn("existing-token", self.context["SESSIONS"])

    def test_additional_hosts_are_explicit_and_nonadmin(self):
        self.identity["subject"] = NEW_SUBJECT
        params, nonce, _, _ = self.flow()
        self.finish(params, nonce)
        self.assertFalse(self.context["HOSTS"]["ct400-new"]["admin"])
        self.assertEqual(len(self.context["HOSTS"]), 3)

    def test_login_audit_has_guid_without_codes_tokens_or_passwords(self):
        params, nonce, target, _ = self.flow()
        cookie = self.finish(params, nonce)
        content = self.audit.read_text()
        record = json.loads(content)
        self.assertEqual(record["ct400_subject"], SUBJECT)
        self.assertEqual(record["host_username"], "julie")
        for secret in [nonce, "c" * 43, self.cfg["client_secret"], self.calls[0][1]]:
            self.assertNotIn(secret, content)
        self.assertEqual(self.audit.stat().st_mode & 0o777, 0o600)

    def test_same_callback_cannot_create_two_sessions(self):
        params, nonce, _, _ = self.flow()
        self.finish(params, nonce)
        with self.assertRaises(sso.SSOError): self.finish(params, nonce)
        self.assertEqual(len(self.calls), 1)

    def test_wrong_browser_cookie_cannot_consume_flow(self):
        params, nonce, _, _ = self.flow()
        with self.assertRaises(sso.SSOError): self.finish(params, "x" * 43)
        self.finish(params, nonce)
        self.assertEqual(len(self.calls), 1)

    def test_wrong_state_consumes_flow_without_exchange(self):
        params, nonce, _, _ = self.flow()
        with self.assertRaises(sso.SSOError): self.finish(params, nonce, state="x" * 43)
        with self.assertRaises(sso.SSOError): self.finish(params, nonce)
        self.assertEqual(self.calls, [])

    def test_duplicate_state_rejected(self):
        params, nonce, _, _ = self.flow()
        with self.assertRaises(sso.SSOError):
            self.client.finish("state=" + params["state"][0] + "&state=" + params["state"][0] + "&code=" + "c" * 43, nonce)
        self.assertEqual(self.calls, [])

    def test_expired_flow_rejected(self):
        params, nonce, _, _ = self.flow(); self.now += 121
        with self.assertRaises(sso.SSOError): self.finish(params, nonce)
        self.assertEqual(self.calls, [])

    def test_portal_logged_out_does_not_create_session(self):
        params, nonce, _, _ = self.flow()
        with self.assertRaisesRegex(sso.SSOError, "work_login_required"):
            self.finish(params, nonce, error="login_required")
        self.assertEqual(len(self.context["SESSIONS"]), 1)
        self.assertEqual(self.calls, [])

    def test_unmapped_subject_does_not_merge_by_email_or_name(self):
        self.identity.update(subject="33333333-3333-4333-8333-333333333333", username="julie", email="old@example.invalid")
        params, nonce, _, _ = self.flow()
        with self.assertRaisesRegex(sso.SSOError, "host_access_not_configured"): self.finish(params, nonce)
        self.assertEqual(len(self.context["SESSIONS"]), 1)

    def test_wrong_issuer_rejected(self):
        self.identity["issuer"] = "https://other.example.invalid"
        params, nonce, _, _ = self.flow()
        with self.assertRaises(sso.SSOError): self.finish(params, nonce)

    def test_old_identity_rejected(self):
        self.identity["auth_time"] = self.now - 121
        params, nonce, _, _ = self.flow()
        with self.assertRaises(sso.SSOError): self.finish(params, nonce)

    def test_mapping_revocation_invalidates_existing_portal_session(self):
        params, nonce, _, _ = self.flow(); self.finish(params, nonce)
        session = next(s for s in self.context["SESSIONS"].values() if s.get("subject"))
        self.assertTrue(self.client.valid_session(session))
        del self.cfg["subjects"][SUBJECT]; self.write_config()
        self.assertFalse(self.client.valid_session(session))
        self.assertTrue(self.client.valid_session(self.context["SESSIONS"]["existing-token"]))

    def test_disabled_or_malformed_config_retains_local_sessions(self):
        for content in ["{}", "broken-json", json.dumps({**self.cfg, "enabled": False}), json.dumps({**self.cfg, "enabled": "true"})]:
            self.path.write_text(content)
            self.assertIsNone(self.client.config())
            self.assertTrue(self.client.valid_session(self.context["SESSIONS"]["existing-token"]))

    def test_config_cannot_override_existing_hosts_or_map_admin(self):
        self.cfg["additional_hosts"]["julie"] = {"name": "Different", "email": "different@example.invalid"}
        self.write_config(); self.assertIsNone(self.client.config())
        del self.cfg["additional_hosts"]["julie"]
        self.cfg["subjects"][SUBJECT] = "support"
        self.write_config(); self.assertIsNone(self.client.config())
        self.assertEqual(self.context["HOSTS"], self.original_hosts)

    def test_config_cannot_change_broker_or_callback(self):
        for key in ["broker_origin", "issuer", "redirect_uri"]:
            self.cfg[key] = "https://attacker.example.invalid/"
            self.write_config(); self.assertIsNone(self.client.config())
            del self.cfg[key]

    def test_pending_flows_bounded(self):
        self.client.pending = {str(i): {"expires": self.now + 10} for i in range(sso.MAX_PENDING)}
        with self.assertRaises(sso.SSOError): self.client.begin()
        self.now += 11
        self.client.begin()
        self.assertEqual(len(self.client.pending), 1)

    def test_unwritable_audit_prevents_unaudited_portal_session(self):
        self.client.audit_path = self.root / "missing" / "audit.jsonl"
        params, nonce, _, _ = self.flow()
        with self.assertRaisesRegex(sso.SSOError, "audit_unavailable"): self.finish(params, nonce)
        self.assertEqual(len(self.context["SESSIONS"]), 1)

    def test_redirects_cannot_forward_client_secret(self):
        with self.assertRaises(sso.SSOError): sso.NoRedirect().redirect_request(None, None, 307, "", {}, "https://other.example.invalid")


class ActualHandlerTests(ClientTests):
    # Reuse only the fixture helpers, not ClientTests' test methods.
    def setUp(self):
        super().setUp()
        raw = BASELINE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), patch_app.BASELINE_SHA256)
        source = patch_app.render(raw).decode().replace(patch_app.HOOK, "").split(patch_app.MARKER)[0]
        self.ns = {"__name__": "meet_test_fixture"}
        exec(compile(source, str(BASELINE), "exec"), self.ns)
        self.ns["DB"] = str(self.root / "meetings.sqlite")
        self.ns["get_stats"] = lambda: {}
        self.ns["check_host_password"] = lambda name, password: name in ["julie", "support"] and password == "synthetic-password"
        self.ns["send_meeting_links"] = lambda *args: self.fail("No message may be sent by these tests")
        self.ns["init_db"]()
        with self.ns["db"]() as db:
            db.execute("INSERT INTO meetings(title,room,mode,owner,created_at) VALUES('Fixture room','fixture-room','normal','julie',?)", [self.now])
        self.before_hosts = copy.deepcopy(self.ns["HOSTS"])
        handler = sso.wrap_handler(self.ns["Handler"], self.ns, self.path, self.exchange, lambda: self.now, self.audit)
        handler.log_message = lambda *args: None
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.http_client = handler.portal_client

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)
        super().tearDown()

    def request(self, path, cookie="", method="GET", body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Cookie": cookie} if cookie else {}
        if body is not None:
            body = urllib.parse.urlencode(body); headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        result = conn.getresponse(); data = result.read().decode(); values = result.getheaders(); status = result.status; conn.close()
        return status, values, data

    def http_flow(self):
        status, headers, _ = self.request("/host/")
        self.assertEqual(status, 302)
        values = dict(headers)
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(values["Location"]).query)
        cookie = values["Set-Cookie"].split(";", 1)[0]
        return params, cookie

    def portal_login(self):
        params, cookie = self.http_flow()
        status, headers, _ = self.request(sso.CALLBACK_PATH + "?" + urllib.parse.urlencode({"state": params["state"][0], "code": "c" * 43}), cookie)
        self.assertEqual(status, 302)
        return next(v.split(";", 1)[0] for k, v in headers if k == "Set-Cookie" and v.startswith(sso.SESSION_COOKIE + "="))

    def test_http_auto_login_creates_existing_host_session(self):
        cookie = self.portal_login()
        status, _, body = self.request("/host/", cookie)
        self.assertEqual(status, 200)
        self.assertIn("Julie Foster", body)
        for name, profile in self.before_hosts.items(): self.assertEqual(self.ns["HOSTS"][name], profile)

    def test_http_missing_portal_login_falls_back_without_redirect_loop(self):
        params, cookie = self.http_flow()
        status, headers, _ = self.request(sso.CALLBACK_PATH + "?" + urllib.parse.urlencode({"state": params["state"][0], "error": "login_required"}), cookie)
        self.assertEqual(status, 302)
        target = dict(headers)["Location"]
        status, _, body = self.request(target)
        self.assertEqual(status, 200)
        self.assertIn("Continue with work account", body)
        self.assertIn('name="password"', body)

    def test_http_existing_local_password_login_is_preserved(self):
        status, headers, _ = self.request("/host/login", method="POST", body={"username": "julie", "password": "synthetic-password"})
        self.assertEqual(status, 302)
        cookie = dict(headers)["Set-Cookie"].split(";", 1)[0]
        status, _, body = self.request("/host/", cookie)
        self.assertEqual(status, 200)
        self.assertIn("Julie Foster", body)
        self.assertEqual(self.calls, [])

    def test_http_signout_does_not_immediately_sign_back_in(self):
        cookie = self.portal_login()
        status, headers, _ = self.request("/host/logout", cookie)
        self.assertEqual(status, 302)
        self.assertEqual(dict(headers)["Location"], "/host/login?signed_out=1")
        self.assertEqual(self.ns["SESSIONS"], {})
        self.assertEqual(self.request("/host/login?signed_out=1")[0], 200)

    def test_http_action_audit_pins_ct400_guid_without_sending_mail(self):
        cookie = self.portal_login()
        status, _, _ = self.request("/host/delete", cookie, "POST", {"id": "1"})
        self.assertEqual(status, 302)
        records = [json.loads(line) for line in self.audit.read_text().splitlines()]
        self.assertEqual([r["event"] for r in records], ["portal_login", "host_action_attempt", "host_action_response"])
        self.assertTrue(all(r["ct400_subject"] == SUBJECT for r in records))
        self.assertEqual(records[-1]["http_status"], 302)

    def test_http_callback_headers_prevent_code_caching_and_referrers(self):
        params, cookie = self.http_flow()
        status, headers, _ = self.request(sso.CALLBACK_PATH + "?state=" + params["state"][0] + "&code=" + "c" * 43, cookie)
        self.assertEqual(status, 302)
        self.assertEqual(dict(headers)["Cache-Control"], "no-store")
        self.assertEqual(dict(headers)["Referrer-Policy"], "no-referrer")

    def test_http_delayed_callback_preserves_newly_established_local_session(self):
        params, pending_cookie = self.http_flow()
        _, headers, _ = self.request("/host/login", method="POST", body={"username": "support", "password": "synthetic-password"})
        local_cookie = dict(headers)["Set-Cookie"].split(";", 1)[0]
        status, headers, _ = self.request(sso.CALLBACK_PATH + "?" + urllib.parse.urlencode({"state": params["state"][0], "code": "c" * 43}), pending_cookie + "; " + local_cookie)
        self.assertEqual(status, 302)
        self.assertFalse(any(k == "Set-Cookie" and v.startswith(sso.SESSION_COOKIE + "=") for k, v in headers))
        self.assertEqual(len(self.ns["SESSIONS"]), 1)
        self.assertEqual(next(iter(self.ns["SESSIONS"].values()))["username"], "support")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.http_client.pending, {})

    def test_http_standard_host_cannot_delete_another_owners_room(self):
        with self.ns["db"]() as db:
            db.execute("UPDATE meetings SET owner='martin' WHERE id=1")
        cookie = self.portal_login()
        status, _, _ = self.request("/host/delete", cookie, "POST", {"id": "1"})
        self.assertEqual(status, 403)
        with self.ns["db"]() as db:
            self.assertEqual(db.execute("SELECT deleted FROM meetings WHERE id=1").fetchone()[0], 0)
        self.assertEqual(json.loads(self.audit.read_text().splitlines()[-1])["http_status"], 403)

    def test_http_existing_admin_can_delete_another_owners_room(self):
        _, headers, _ = self.request("/host/login", method="POST", body={"username": "support", "password": "synthetic-password"})
        cookie = dict(headers)["Set-Cookie"].split(";", 1)[0]
        status, _, _ = self.request("/host/delete", cookie, "POST", {"id": "1"})
        self.assertEqual(status, 302)
        with self.ns["db"]() as db:
            self.assertEqual(db.execute("SELECT deleted FROM meetings WHERE id=1").fetchone()[0], 1)


# Do not rerun the unit cases inherited for fixture setup in the HTTP subclass.
for name in list(ClientTests.__dict__):
    if name.startswith("test_"):
        setattr(ActualHandlerTests, name, None)


class PatchTests(unittest.TestCase):
    def test_exact_baseline_patch_only_adds_startup_hook_and_delete_guard(self):
        original = BASELINE.read_bytes()
        patched = patch_app.render(original)
        self.assertEqual(patched.decode().replace(patch_app.INSERT, patch_app.MARKER).replace(patch_app.DELETE_REPLACEMENT, patch_app.DELETE_MARKER), original.decode())
        self.assertIn("Handler = wrap_handler(Handler, globals())", patched.decode())

    def test_changed_source_is_refused(self):
        with self.assertRaises(ValueError): patch_app.render(BASELINE.read_bytes() + b"\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
