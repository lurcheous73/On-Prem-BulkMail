#!/usr/bin/env python3
"""Real app routes and a certificate-verified local HTTPS Workspace fixture only."""
import base64
import contextlib
import hashlib
import html
import http.cookiejar
import http.server
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
PETER_ID = "11111111-1111-4111-8111-111111111111"
CLONE_ID = "22222222-2222-4222-8222-222222222222"
passed = []
api_calls = []


def check(name, value):
    assert value, name
    passed.append(name)
    print("PASS", name, flush=True)


def profile(clone=False):
    return {"id": CLONE_ID if clone else PETER_ID,
            "userName": "clone.work" if clone else "peter.work",
            "email": "peter@example.invalid", "displayName": "Verified work member",
            "status": 1, "activationStatus": 1, "isVisitor": False, "isAdmin": True}


class Workspace(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        token = self.headers.get("Authorization", "")
        api_calls.append((self.command, self.path, token))
        if self.path == "/api/2.0/people/@self.json" and token in ["fixture-portal-peter", "fixture-portal-clone"]:
            status, value = 200, profile(token.endswith("clone"))
        elif self.path == "/api/2.0/people/peter.work.json" and token == "fixture-portal-peter":
            status, value = 200, profile()
        else:
            status, value = 401, {}
        body = json.dumps({"status": 0, "response": value}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Redirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, request, fp, code, message, headers):
        if headers.get("Location") == "?":
            parts = urllib.parse.urlsplit(request.full_url)
            headers.replace_header("Location", urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
        return super().http_error_302(request, fp, code, message, headers)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def browser(follow=True):
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(Redirect() if follow else NoRedirect(), urllib.request.HTTPCookieProcessor(jar))
    client.jar = jar
    return client


def portal_cookie(client, value):
    for item in list(client.jar):
        if item.name == "asc_auth_key":
            client.jar.clear(item.domain, item.path, item.name)
    if value is not None:
        client.jar.set_cookie(http.cookiejar.Cookie(0, "asc_auth_key", value, None, False, "127.0.0.1", False, False,
                                                   "/", True, False, None, True, None, None, {}, False))


def free_port():
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix="bulkmail-portal-http-") as temp:
    root = pathlib.Path(temp)
    shutil.copytree(REPO / "app", root / "app")
    (root / "data").mkdir()
    (root / "sessions").mkdir()
    main = root / "app/index.php"
    main.write_text(main.read_text().replace("const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';", f"const DB_FILE = '{root}/data/bulkmail.sqlite';")
                    .replace("const DATA_DIR = '/var/lib/bulkmail';", f"const DATA_DIR = '{root}/data';")
                    .replace("const DELIVERY_ENABLED = true;", "const DELIVERY_ENABLED = false;"))
    db = sqlite3.connect(root / "data/bulkmail.sqlite")
    db.row_factory = sqlite3.Row
    db.executescript((REPO / "database/schema.sql").read_text())
    password = secrets.token_urlsafe(24)
    password_hash = subprocess.check_output(["php", "-r", "echo password_hash($argv[1],PASSWORD_DEFAULT);", password]).decode()
    db.executemany("INSERT INTO users(id,username,password_hash,display_name,email,is_admin) VALUES(?,?,?,?,?,?)", [
        (1, "QAAdmin", password_hash, "QA Local Administrator", "admin@example.invalid", 1),
        (2, "Peter", password_hash, "Peter Arnold", "peter@example.invalid", 1),
        (3, "Other", password_hash, "Other member", "other@example.invalid", 0)])
    db.execute("INSERT INTO contacts(owner_user_id,name,email) VALUES(2,'Retained contact','contact@example.invalid')")
    db.commit()
    users_before = [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")]
    cert, key = root / "fixture-cert.pem", root / "fixture-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Workspace)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    fixture.socket = context.wrap_socket(fixture.socket, server_side=True)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    issuer = f"https://127.0.0.1:{fixture.server_port}"
    callback = "https://meet.example.invalid/host/auth/ct400/callback"
    client_secret = secrets.token_urlsafe(48)
    settings = {"identity": {"enabled": True, "auto_login": True, "base_url": issuer, "directory_token": "", "allow_http": False,
                             "sso_clients": {"meet-host": {"enabled": True, "secret": client_secret, "redirect_uri": callback}}}}
    config = root / "integrations.php"

    def write_config():
        encoded = base64.b64encode(json.dumps(settings).encode()).decode()
        config.write_text("<?php return json_decode(base64_decode('" + encoded + "'), true);")

    write_config()
    port = free_port()
    base = f"http://127.0.0.1:{port}/"
    env = dict(os.environ, BULKMAIL_INTEGRATIONS_CONFIG=str(config))
    log = open(root / "php.log", "w+")
    process = subprocess.Popen(["php", "-d", f"session.save_path={root}/sessions", "-d", f"curl.cainfo={cert}",
                                "-S", f"127.0.0.1:{port}", "-t", str(root / "app")], env=env, stdout=log, stderr=log)

    def request(client, path, fields=None):
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        return client.open(urllib.request.Request(base + path, data=data), timeout=15)

    def get(client, path):
        with request(client, path) as response:
            return response.read().decode()

    def post(client, path, fields):
        with request(client, path, fields) as response:
            return response.read().decode()

    def csrf(page):
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        assert match, "Missing CSRF form"
        return html.unescape(match[1])

    def redirect_location(client, path, fields=None):
        try:
            request(client, path, fields)
        except urllib.error.HTTPError as error:
            assert error.code == 302, error.code
            return error.headers["Location"]
        raise AssertionError("Expected controlled redirect")

    try:
        for attempt in range(60):
            try:
                page = get(browser(), "?page=login")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise AssertionError("PHP fixture did not start")
        db.execute("INSERT INTO user_identity_links(user_id,issuer,external_id,external_username,external_email,external_display_name,external_login_enabled,verified_at,linked_by_user_id) VALUES(2,?,?, 'peter.work','peter@example.invalid','Peter Work',1,CURRENT_TIMESTAMP,1)", [issuer, PETER_ID])
        db.commit()
        check("Existing local login remains the default form", '<option value="local">Existing Bulk Mail account</option>' in page and "Sign in with work portal" in page)
        n = len(api_calls)
        page = get(browser(), "?page=login&asc_auth_key=fixture-portal-peter&token=fixture-portal-peter")
        check("Query-string tokens cannot trigger portal authentication", 'name="password"' in page and len(api_calls) == n)
        peter = browser()
        portal_cookie(peter, "fixture-portal-peter")
        page = get(peter, "?page=history")
        check("A real request cookie signs into the existing Peter account on GET", "Peter Arnold" in page and "Log out" in page and "Sent / Mailing History" in page)
        check("Portal self identity was checked over trusted local HTTPS", api_calls[-1] == ("GET", "/api/2.0/people/@self.json", "fixture-portal-peter"))
        audit = db.execute("SELECT * FROM audit_identity ORDER BY audit_id DESC LIMIT 1").fetchone()
        check("Automatic sign-in audit records its portal identity source", audit["actor_user_id"] == 2 and audit["authentication_method"] == "ct400_portal" and audit["authenticated_ct400_id"] == PETER_ID)
        no_post_login = browser(False)
        portal_cookie(no_post_login, "fixture-portal-peter")
        n = len(api_calls)
        location = redirect_location(no_post_login, "?page=users", {"action": "save", "user_id": "2", "display_name": "Must not apply"})
        check("An unauthenticated POST is not upgraded into an authenticated action", location == "?page=login" and len(api_calls) == n and db.execute("SELECT display_name FROM users WHERE id=2").fetchone()[0] == "Peter Arnold")
        admin = browser()
        page = get(admin, "?page=login")
        portal_cookie(admin, "fixture-portal-peter")
        n = len(api_calls)
        page = post(admin, "?page=login", {"csrf": csrf(page), "username": "QAAdmin", "password": password, "login_method": "local"})
        check("Local password sign-in is retained even when another portal user has a cookie", "QA Local Administrator" in page and len(api_calls) == n)
        page = get(admin, "?page=history")
        check("Portal cookie never takes over an already signed-in local account", "QA Local Administrator" in page and len(api_calls) == n)
        page = get(peter, "?page=logout")
        n = len(api_calls)
        check("Logout leaves the local login form visible while preserving the portal cookie", 'name="password"' in page and any(c.name == "asc_auth_key" for c in peter.jar))
        page = get(peter, "?page=history")
        check("Following logout does not immediately auto-login again", 'name="password"' in page and len(api_calls) == n)
        try:
            post(peter, "?page=login", {"csrf": "wrong", "login_method": "portal"})
            denied = False
        except urllib.error.HTTPError as error:
            denied = error.code == 400
        check("Explicit work re-entry requires CSRF", denied)
        page = post(peter, "?page=login", {"csrf": csrf(page), "login_method": "portal"})
        check("Explicit work sign-in clears logout suppression", "Log out" in page and "Peter Arnold" in page)
        portal_cookie(peter, None)
        check("Removing the portal cookie revokes its app session on the next request", 'name="password"' in get(peter, "?page=history"))
        portal_cookie(peter, "fixture-portal-peter")
        get(peter, "?page=history")
        portal_cookie(peter, "invalid-portal-cookie")
        check("Changing to an invalid portal cookie revokes the session immediately", 'name="password"' in get(peter, "?page=history"))
        clone = browser()
        portal_cookie(clone, "fixture-portal-clone")
        check("An unlinked identity with Peter's email cannot take his account", 'name="password"' in get(clone, "?page=history"))
        page = get(admin, "?page=identity_users")
        n = len(api_calls)
        page = post(admin, "?page=identity_users", {"csrf": csrf(page), "action": "lookup", "lookup": "peter.work"})
        check("Directory lookup verifies the current cookie without a stored directory token", PETER_ID in page and [c[1] for c in api_calls[n:]] == ["/api/2.0/people/@self.json", "/api/2.0/people/peter.work.json"])
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(24)
        auth = {"client_id": "meet-host", "redirect_uri": callback, "response_type": "code", "code_challenge_method": "S256", "code_challenge": challenge, "state": state}
        broker = browser(False)
        portal_cookie(broker, "fixture-portal-peter")
        location = redirect_location(broker, "?page=portal_sso_authorize&" + urllib.parse.urlencode(auth))
        result = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        check("Browser broker route verifies the portal and returns only a one-time code", location.startswith(callback + "?") and result.get("state") == [state] and len(result.get("code", [])) == 1 and "fixture-portal-peter" not in location)
        exchange = {"client_id": "meet-host", "client_secret": client_secret, "redirect_uri": callback, "grant_type": "authorization_code", "code_verifier": verifier, "code": result["code"][0]}
        body = post(browser(), "?page=portal_sso_token", exchange)
        claims = json.loads(body)
        check("Backend token route works without a browser login or portal cookie", claims["identity"]["subject"] == PETER_ID and 'name="password"' not in body)
        no_portal = browser(False)
        location = redirect_location(no_portal, "?page=portal_sso_authorize&" + urllib.parse.urlencode(auth))
        check("Broker cannot mint identity from a missing portal cookie", urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("error") == ["login_required"])
        portal_cookie(peter, "fixture-portal-peter")
        get(peter, "?page=history")
        db.execute("UPDATE user_identity_links SET active=0 WHERE user_id=2")
        db.commit()
        check("Disabling the explicit identity link revokes a portal session immediately", 'name="password"' in get(peter, "?page=history"))
        check("Revoking a portal link leaves local login sessions usable", "QA Local Administrator" in get(admin, "?page=history"))
        db.execute("UPDATE user_identity_links SET active=1 WHERE user_id=2")
        db.commit()
        settings["identity"]["auto_login"] = "true"
        write_config()
        flag_client = browser()
        portal_cookie(flag_client, "fixture-portal-peter")
        n = len(api_calls)
        check("String auto-login settings fail closed in real HTTP requests", 'name="password"' in get(flag_client, "?page=history") and len(api_calls) == n)
        check("All existing accounts, passwords and roles remain byte-for-byte unchanged", [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")] == users_before)
        session_data = "".join(p.read_text() for p in (root / "sessions").iterdir() if p.is_file())
        check("Sessions never store raw portal cookies or broker client secrets", "fixture-portal-peter" not in session_data and client_secret not in session_data)
        check("Authentication workflows create no mail or messaging campaigns", db.execute("SELECT COUNT(*) FROM mailings").fetchone()[0] == 0 and db.execute("SELECT COUNT(*) FROM message_campaigns").fetchone()[0] == 0)
        check("Database integrity and existing contact ownership remain valid", db.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and not db.execute("PRAGMA foreign_key_check").fetchall() and db.execute("SELECT owner_user_id FROM contacts").fetchone()[0] == 2)
        print(f"PASS {len(passed)} portal HTTP checks; synthetic data and local HTTPS only.", flush=True)
    except Exception:
        log.flush()
        log.seek(0)
        print(log.read(), flush=True)
        raise
    finally:
        process.terminate()
        process.wait(timeout=10)
        fixture.shutdown()
        fixture.server_close()
        log.close()
        db.close()
