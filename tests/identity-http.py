#!/usr/bin/env python3
"""Exercise the actual login/account routes against a loopback ONLYOFFICE fixture."""
import contextlib
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
offline = False
api_calls = []


def check(name, value):
    if not value:
        raise AssertionError(name)
    passed.append(name)
    print("PASS", name, flush=True)


def profile(name):
    return {"id": PETER_ID if name == "peter.ct400" else CLONE_ID,
            "userName": name, "email": "peter@example.invalid", "displayName": "CT400 " + name,
            "status": 1, "activationStatus": 1, "isVisitor": False, "isAdmin": False}


class Workspace(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, data, status=200):
        body = json.dumps({"response": data, "status": 0, "statusCode": status}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        api_calls.append(("GET", self.path))
        if offline:
            return self.reply({}, 503)
        token = self.headers.get("Authorization", "")
        if self.path == "/api/2.0/people/@self.json" and token.startswith("self-"):
            return self.reply(profile(token[5:]))
        if token != "fixture-directory-token":
            return self.reply({}, 401)
        if self.path == "/api/2.0/people/peter.ct400.json":
            return self.reply(profile("peter.ct400"))
        return self.reply({}, 404)

    def do_POST(self):
        api_calls.append(("POST", self.path))
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if offline:
            return self.reply({}, 503)
        if self.path != "/api/2.0/authentication.json" or data.get("password") != "fixture-work-password":
            return self.reply({}, 401)
        return self.reply({"token": "self-" + data["userName"]}, 201)


class Redirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, request, fp, code, message, headers):
        # urllib retains the old query for Location: ?; a browser clears it.
        if headers.get("Location") == "?":
            parts = urllib.parse.urlsplit(request.full_url)
            headers.replace_header("Location", urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
        return super().http_error_302(request, fp, code, message, headers)


def browser():
    return urllib.request.build_opener(Redirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def free_port():
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix="bulkmail-identity-http-") as tmp:
    root = pathlib.Path(tmp)
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
    local_password = secrets.token_urlsafe(24)
    password_hash = subprocess.check_output(["php", "-r", "echo password_hash($argv[1],PASSWORD_DEFAULT);", local_password]).decode()
    db.executemany("INSERT INTO users(id,username,password_hash,display_name,email,is_admin) VALUES(?,?,?,?,?,?)", [
        (1, "QAAdmin", password_hash, "QA Administrator", "admin@example.invalid", 1),
        (2, "Peter", password_hash, "Peter Arnold", "peter@example.invalid", 1),
        (3, "Other", password_hash, "Other member", "other@example.invalid", 0)])
    db.execute("INSERT INTO contacts(owner_user_id,name,email) VALUES(2,'Retained contact','contact@example.invalid')")
    db.commit()
    before = [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")]
    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Workspace)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    config = root / "integrations.php"
    config.write_text("<?php return ['identity'=>['enabled'=>true,'base_url'=>'http://127.0.0.1:" + str(fixture.server_port) + "','allow_http'=>true,'directory_token'=>'fixture-directory-token']];")
    port = free_port()
    base = f"http://127.0.0.1:{port}/"
    env = dict(os.environ, BULKMAIL_INTEGRATIONS_CONFIG=str(config))
    log = open(root / "php.log", "w+")
    process = subprocess.Popen(["php", "-d", f"session.save_path={root}/sessions", "-S", f"127.0.0.1:{port}", "-t", str(root / "app")], env=env, stdout=log, stderr=log)

    def get(client, path):
        return client.open(base + path, timeout=10).read().decode()

    def csrf(page):
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        if not match:
            raise AssertionError("Missing CSRF form: " + page[:180])
        return html.unescape(match.group(1))

    def post(client, path, data):
        request = urllib.request.Request(base + path, urllib.parse.urlencode(data).encode())
        return client.open(request, timeout=15).read().decode()

    def login(client, username, password=local_password, method="local"):
        page = get(client, "?page=login")
        return post(client, "?page=login", {"csrf": csrf(page), "username": username, "password": password, "login_method": method})

    def expect_status(name, status, fn):
        try:
            fn()
        except urllib.error.HTTPError as error:
            check(name, error.code == status)
            return
        check(name, False)

    try:
        for _ in range(60):
            try:
                get(browser(), "?page=login")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        peter = browser()
        check("Peter can still use his existing local login", "Log out" in login(peter, "Peter"))
        check("Login preserves Peter and every existing user", [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")] == before)
        admin = browser()
        login(admin, "QAAdmin")
        other = browser()
        login(other, "Other")
        expect_status("Non-admin cannot open account integration", 403, lambda: get(other, "?page=identity_users"))
        page = get(admin, "?page=identity_users")
        token = csrf(page)
        page = post(admin, "?page=identity_users", {"csrf": token, "action": "lookup", "lookup": "peter.ct400"})
        check("Verified directory lookup previews the exact CT400 person", PETER_ID in page and 'name="user_id"' in page)
        data = {"csrf": token, "action": "link", "lookup": "peter.ct400", "external_id": CLONE_ID, "user_id": 2, "external_login_enabled": 1}
        page = post(admin, "?page=identity_users", data)
        check("Forged identity fails through the HTTP route", "profile changed" in page and db.execute("SELECT COUNT(*) FROM user_identity_links").fetchone()[0] == 0)
        data.update(external_id=PETER_ID, csrf="wrong")
        expect_status("Identity mutation requires CSRF", 400, lambda: post(admin, "?page=identity_users", data))
        data["csrf"] = token
        page = post(admin, "?page=identity_users", data)
        check("Administrator can explicitly link Peter without replacement", "identity linked" in page and [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")] == before)
        check("Peter contact ownership remains intact", db.execute("SELECT owner_user_id FROM contacts").fetchone()[0] == 2)
        external = browser()
        page = login(external, "peter.ct400", "fixture-work-password", "ct400")
        check("External login authenticates into Peter's existing account", "Log out" in page and "Peter Arnold" in page)
        audit = db.execute("SELECT * FROM audit_identity ORDER BY audit_id DESC LIMIT 1").fetchone()
        check("HTTP login audit separates verified CT400 from local login", audit["actor_user_id"] == 2 and audit["authentication_method"] == "ct400" and audit["authenticated_ct400_id"] == PETER_ID)
        clone = browser()
        check("Same-email unlinked identity cannot enter Peter account", "Login failed" in login(clone, "clone.ct400", "fixture-work-password", "ct400"))
        page = get(admin, "?page=audit")
        check("Audit page displays captured CT400 ID and sign-in method", PETER_ID in page and "CT400 verified" in page and "Local password" in page)
        # A synthetic historical email provides a real public unsubscribe link.
        unsubscribe_token = secrets.token_hex(24)
        db.execute("INSERT INTO mailings(id,initiated_by_user_id,acting_for_user_id,sender_email,subject,body_html,status) VALUES(1,2,2,'peter@example.invalid','Historic fixture','<p>Historic fixture</p>','sent')")
        db.execute("INSERT INTO mailing_recipients(mailing_id,contact_id,email,unsubscribe_token,status) VALUES(1,1,'contact@example.invalid',?,'sent')", [unsubscribe_token])
        db.commit()
        token = csrf(get(admin, "?page=identity_users"))
        post(admin, "?page=identity_users", {"csrf": token, "action": "disable", "user_id": 2})
        unsubscribe_page = get(external, "?page=unsubscribe&t=" + unsubscribe_token)
        check("Revoked CT400 session cannot block public unsubscribe GET", "Stop marketing emails" in unsubscribe_page and 'name="password"' not in unsubscribe_page)
        unsubscribe_result = post(external, "?page=unsubscribe&t=" + unsubscribe_token, {"csrf": csrf(unsubscribe_page)})
        check("Public unsubscribe POST works after clearing a revoked session", "Unsubscribed" in unsubscribe_result and db.execute("SELECT COUNT(*) FROM suppressions WHERE owner_user_id=2 AND email='contact@example.invalid'").fetchone()[0] == 1)
        check("Disabling external link invalidates existing external session", 'name="password"' in get(external, "?"))
        check("Disabling external link preserves Peter's local session", "Log out" in get(peter, "?"))
        offline = True
        calls_before = len(api_calls)
        fresh = browser()
        check("CT400 outage does not block Peter's local login", "Log out" in login(fresh, "Peter") and len(api_calls) == calls_before)
        check("Entire route exercise preserves Peter's existing password and role", [dict(row) for row in db.execute("SELECT * FROM users ORDER BY id")] == before)
        check("No email or message send is queued by identity operations", db.execute("SELECT COUNT(*) FROM mailings WHERE status='queued'").fetchone()[0] == 0 and db.execute("SELECT COUNT(*) FROM mailing_recipients WHERE status='queued'").fetchone()[0] == 0)
        check("Identity HTTP database remains consistent", db.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and not db.execute("PRAGMA foreign_key_check").fetchall())
        print(f"PASS {len(passed)} identity HTTP checks; synthetic accounts and loopback API only.", flush=True)
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
