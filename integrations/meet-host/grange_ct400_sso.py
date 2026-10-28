"""CT400 portal identity adapter for the existing Grange meeting host app.

No SMTP, password-file or meeting-database operations are performed here.
The browser carries only a short-lived code; the portal cookie stays on work.
"""
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from html import escape
from pathlib import Path

CONFIG_PATH = "/etc/grange-meet-ct400.json"
AUDIT_PATH = "/var/lib/grange-meet-sso/audit.jsonl"
BROKER_ORIGIN = "https://work.the-grange.uk:9443"
ISSUER = "https://work.the-grange.uk"
CALLBACK = "https://meet.the-grange.uk/host/auth/ct400/callback"
START_PATH = "/host/auth/ct400/start"
CALLBACK_PATH = "/host/auth/ct400/callback"
PENDING_COOKIE = "__Host-grange_ct400_pending"
SESSION_COOKIE = "grange_meet_session"
FLOW_SECONDS = 120
MAX_PENDING = 1000
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
GUID_PATTERN = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
DIAGNOSTIC_REASONS = frozenset({
    "received", "redirect", "session_created", "existing_session", "internal_error",
    "work_login_required", "work_login_unavailable", "work_login_busy",
    "invalid_login_state", "expired_login_state", "invalid_login_code",
    "broker_redirect_rejected", "broker_unavailable", "invalid_broker_response",
    "invalid_identity", "host_access_not_configured", "audit_unavailable",
})


class SSOError(Exception):
    """Fixed diagnostics only; never include remote bodies or secret values."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SSOError("broker_redirect_rejected")


def _token_hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _challenge(verifier):
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _cookie(headers, name):
    try:
        cookies = SimpleCookie()
        cookies.load(headers.get("Cookie", ""))
        value = cookies.get(name)
        return value.value if value else ""
    except Exception:
        return ""


def _set_cookie(name, value, seconds):
    path = "/" if name.startswith("__Host-") else "/host/"
    return f"{name}={value}; Path={path}; Max-Age={seconds}; HttpOnly; Secure; SameSite=Lax"


def _connect_address(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError()
    if value == "":
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError() from None


class PinnedBrokerHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a configured numeric address; authenticate the original host."""

    def __init__(self, host, port, address):
        self.connect_address = ipaddress.ip_address(_connect_address(address))
        super().__init__(host, port, timeout=8, context=ssl.create_default_context())

    def connect(self):
        # A numeric socket avoids hostname resolution and environment proxies.
        # TLS still verifies the original broker name with the system trust store.
        raw = socket.socket(socket.AF_INET6 if self.connect_address.version == 6 else socket.AF_INET,
                            socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.connect((str(self.connect_address), self.port))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _pinned_exchange(payload, address):
    origin = urllib.parse.urlsplit(BROKER_ORIGIN)
    if origin.scheme != "https" or not origin.hostname:
        raise SSOError("broker_unavailable")
    connection = PinnedBrokerHTTPSConnection(origin.hostname, origin.port or 443, address)
    try:
        connection.request("POST", "/?page=portal_sso_token", body=payload,
                           headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise SSOError("broker_redirect_rejected")
        if response.status != 200:
            raise SSOError("broker_unavailable")
        return response.read(16385)
    finally:
        connection.close()


def load_config(path, original_hosts):
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 65536:
            raise ValueError()
        cfg = json.loads(raw)
        if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
            return None
        if cfg.get("broker_origin", BROKER_ORIGIN) != BROKER_ORIGIN or cfg.get("issuer", ISSUER) != ISSUER or cfg.get("redirect_uri", CALLBACK) != CALLBACK:
            raise ValueError()
        secret = cfg.get("client_secret")
        if not isinstance(secret, str) or not 32 <= len(secret) <= 512 or re.search(r"[\x00-\x20\x7f]", secret):
            raise ValueError()
        if cfg.get("client_id", "meet-host") != "meet-host":
            raise ValueError()
        connect_address = _connect_address(cfg.get("broker_connect_address", ""))
        additions = cfg.get("additional_hosts", {})
        subjects = cfg.get("subjects", {})
        if not isinstance(additions, dict) or not isinstance(subjects, dict) or not subjects:
            raise ValueError()
        if len(additions) > 100 or len(subjects) > 100:
            raise ValueError()
        clean_hosts = {}
        for name, profile in additions.items():
            if not isinstance(name, str) or not re.fullmatch(r"ct400-[a-z0-9][a-z0-9_-]{0,47}", name) or name in original_hosts:
                raise ValueError()
            if not isinstance(profile, dict) or profile.get("admin", False) is not False:
                raise ValueError()
            display, email = profile.get("name"), profile.get("email")
            if not isinstance(display, str) or not 1 <= len(display) <= 200 or re.search(r"[\x00-\x1f\x7f]", display):
                raise ValueError()
            if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+", email):
                raise ValueError()
            clean_hosts[name] = {"name": display, "email": email, "admin": False}
        known = set(original_hosts) | set(clean_hosts)
        clean_subjects = {}
        for subject, name in subjects.items():
            if not isinstance(subject, str) or not GUID_PATTERN.fullmatch(subject) or not isinstance(name, str) or name not in known:
                raise ValueError()
            # Existing administrators retain their local login; portal mapping
            # must not implicitly grant those privileges to a CT400 identity.
            if original_hosts.get(name, {}).get("admin"):
                raise ValueError()
            if name in clean_subjects.values():
                raise ValueError()
            clean_subjects[subject] = name
        return {"client_id": "meet-host", "client_secret": secret, "subjects": clean_subjects,
                "additional_hosts": clean_hosts, "broker_connect_address": connect_address}
    except (OSError, ValueError, TypeError, UnicodeError):
        return None


def exchange_code(cfg, code, verifier):
    payload = json.dumps({"grant_type": "authorization_code", "client_id": cfg["client_id"],
                          "client_secret": cfg["client_secret"], "redirect_uri": CALLBACK,
                          "code": code, "code_verifier": verifier}).encode()
    try:
        address = _connect_address(cfg.get("broker_connect_address", ""))
        if address:
            raw = _pinned_exchange(payload, address)
        else:
            request = urllib.request.Request(BROKER_ORIGIN + "/?page=portal_sso_token", data=payload,
                                             headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=8) as response:
                if response.status != 200:
                    raise SSOError("broker_unavailable")
                raw = response.read(16385)
        if len(raw) > 16384:
            raise SSOError("invalid_broker_response")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise SSOError("invalid_broker_response")
        return result
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        raise SSOError("broker_unavailable") from None


class PortalClient:
    def __init__(self, context, config_path=CONFIG_PATH, exchange=None, clock=time.time, audit_path=AUDIT_PATH):
        self.context = context
        self.original_hosts = dict(context["HOSTS"])
        self.config_path = config_path
        self.exchange = exchange or exchange_code
        self.clock = clock
        self.audit_path = audit_path
        self.pending = {}

    def audit(self, event, session, **details):
        record = {"time": int(self.clock()), "event": event, "host_username": session["username"],
                  "authentication_method": session.get("authentication_method", "local"),
                  "ct400_issuer": session.get("issuer"), "ct400_subject": session.get("subject"),
                  "auth_time": session.get("auth_time"), **details}
        raw = (json.dumps(record, separators=(",", ":")) + "\n").encode()
        try:
            fd = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                if os.write(fd, raw) != len(raw):
                    raise OSError()
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise SSOError("audit_unavailable") from None

    def config(self):
        cfg = load_config(self.config_path, self.original_hosts)
        if cfg:
            # Existing host dictionaries and ownership strings are not rewritten.
            for name, profile in cfg["additional_hosts"].items():
                self.context["HOSTS"][name] = profile
        return cfg

    def begin(self):
        cfg = self.config()
        if not cfg:
            raise SSOError("work_login_unavailable")
        now = self.clock()
        self.pending = {k: v for k, v in self.pending.items() if v["expires"] > now}
        if len(self.pending) >= MAX_PENDING:
            raise SSOError("work_login_busy")
        nonce, state, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        self.pending[_token_hash(nonce)] = {"state": state, "verifier": verifier, "expires": now + FLOW_SECONDS}
        params = {"page": "portal_sso_authorize", "client_id": cfg["client_id"], "response_type": "code",
                  "redirect_uri": CALLBACK, "state": state, "code_challenge_method": "S256", "code_challenge": _challenge(verifier)}
        return BROKER_ORIGIN + "/?" + urllib.parse.urlencode(params), _set_cookie(PENDING_COOKIE, nonce, FLOW_SECONDS)

    def finish(self, query, cookie):
        if not TOKEN_PATTERN.fullmatch(cookie or ""):
            raise SSOError("invalid_login_state")
        # Consume the flow before exchange. Even a failed callback cannot be replayed.
        pending = self.pending.pop(_token_hash(cookie), None)
        now = self.clock()
        if not pending or pending["expires"] <= now:
            raise SSOError("expired_login_state")
        if len(query) > 2048:
            raise SSOError("invalid_login_state")
        params = urllib.parse.parse_qs(query, keep_blank_values=True, max_num_fields=5)
        if any(len(v) != 1 for v in params.values()) or set(params) - {"state", "code", "error"}:
            raise SSOError("invalid_login_state")
        state = params.get("state", [""])[0]
        if not TOKEN_PATTERN.fullmatch(state) or not hmac.compare_digest(state, pending["state"]):
            raise SSOError("invalid_login_state")
        if "error" in params:
            raise SSOError("work_login_required" if params["error"] == ["login_required"] else "work_login_unavailable")
        code = params.get("code", [""])[0]
        if not TOKEN_PATTERN.fullmatch(code):
            raise SSOError("invalid_login_code")
        cfg = self.config()
        if not cfg:
            raise SSOError("work_login_unavailable")
        result = self.exchange(cfg, code, pending["verifier"])
        identity = result.get("identity") if isinstance(result, dict) else None
        lifetime = result.get("expires_in") if isinstance(result, dict) else None
        if not isinstance(identity, dict) or type(lifetime) is not int or not 60 <= lifetime <= 900:
            raise SSOError("invalid_identity")
        subject, issuer, auth_time = identity.get("subject"), identity.get("issuer"), identity.get("auth_time")
        if not isinstance(subject, str) or not GUID_PATTERN.fullmatch(subject) or issuer != ISSUER or type(auth_time) is not int or not now - 120 <= auth_time <= now + 30:
            raise SSOError("invalid_identity")
        username = cfg["subjects"].get(subject)
        if not username:
            raise SSOError("host_access_not_configured")
        token = secrets.token_urlsafe(32)
        expires = min(now + lifetime, auth_time + 900)
        session = {"username": username, "expires": expires, "authentication_method": "ct400_portal",
                   "issuer": issuer, "subject": subject, "auth_time": auth_time}
        self.audit("portal_login", session)
        self.context["SESSIONS"][token] = session
        return _set_cookie(SESSION_COOKIE, token, max(1, int(expires - now)))

    def cancel(self, cookie):
        if TOKEN_PATTERN.fullmatch(cookie or ""):
            self.pending.pop(_token_hash(cookie), None)

    def valid_session(self, session):
        if not session or session.get("authentication_method") != "ct400_portal":
            return True
        cfg = self.config()
        return bool(cfg and session.get("issuer") == ISSUER and cfg["subjects"].get(session.get("subject")) == session.get("username")
                    and session.get("expires", 0) > self.clock())


def wrap_handler(base_handler, context, config_path=CONFIG_PATH, exchange=None, clock=time.time, audit_path=AUDIT_PATH):
    client = PortalClient(context, config_path, exchange, clock, audit_path)
    client.config()

    class CT400Handler(base_handler):
        portal_client = client

        def _portal_diagnostic(self, stage, reason):
            # Do not interpolate an exception, URL, cookie, identity, or remote
            # body into the journal. Request logging already removes SSO query
            # strings; these fixed outcomes reveal where a browser stopped.
            self.log_message("CT400 SSO %s", json.dumps({
                "stage": stage if stage in ("start", "callback") else "unknown",
                "reason": reason if reason in DIAGNOSTIC_REASONS else "internal_error",
            }, separators=(",", ":")))

        def _portal_redirect(self, location, cookies=()):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", "0")
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()

        def session(self):
            session = super().session()
            if not client.valid_session(session):
                token = _cookie(self.headers, SESSION_COOKIE)
                context["SESSIONS"].pop(token, None)
                return None
            return session

        def login(self, error=""):
            enabled = bool(client.config())
            work = (f'<p><a class="button" href="{START_PATH}">Continue with work account</a></p>'
                    '<p class="small">Use your signed-in work portal account. If needed, '
                    '<a href="https://work.the-grange.uk/" target="_blank" rel="noopener noreferrer">sign in to the work portal</a>, '
                    'then return here.</p>') if enabled else ""
            message = f'<div class="err">{escape(error)}</div>' if error else ""
            body = context["page"]('<h1>The Grange Meet</h1><p>Authorised meeting hosts</p>' + message + work +
                                   '<form method="post" action="/host/login"><label>Existing host username</label>'
                                   '<input name="username" required><label>Password</label>'
                                   '<input name="password" type="password" required><button>Sign in</button></form>')
            raw = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == CALLBACK_PATH:
                self._portal_diagnostic("callback", "received")
                cookies = [_set_cookie(PENDING_COOKIE, "", 0)]
                # A local/portal login established while the browser was away
                # takes precedence over this delayed authorization callback.
                if self.session():
                    client.cancel(_cookie(self.headers, PENDING_COOKIE))
                    self._portal_diagnostic("callback", "existing_session")
                    self._portal_redirect("/host/", cookies)
                    return
                try:
                    cookies.append(client.finish(parsed.query, _cookie(self.headers, PENDING_COOKIE)))
                    self._portal_diagnostic("callback", "session_created")
                    self._portal_redirect("/host/", cookies)
                except Exception as error:
                    # Fixed message only. No code, state, cookie or broker body is logged.
                    self._portal_diagnostic("callback", str(error) if isinstance(error, SSOError) else "internal_error")
                    reason = "required" if isinstance(error, SSOError) and str(error) == "work_login_required" else "unavailable"
                    self._portal_redirect("/host/login?work=" + reason, cookies)
                return
            if parsed.path == START_PATH:
                try:
                    target, cookie = client.begin()
                    self._portal_diagnostic("start", "redirect")
                    self._portal_redirect(target, [cookie])
                except SSOError as error:
                    self._portal_diagnostic("start", str(error))
                    self.login("Work sign-in is temporarily unavailable. Your existing host login still works.")
                return
            if parsed.path == "/host/login":
                error = {"work=required": "Sign in to the work portal, then choose Continue with work account.",
                         "work=unavailable": "Work sign-in could not be completed. Please retry or use your existing host login."}.get(parsed.query, "")
                self.login(error)
                return
            if self.path == "/host/logout":
                token = _cookie(self.headers, SESSION_COOKIE)
                context["SESSIONS"].pop(token, None)
                self._portal_redirect("/host/login?signed_out=1", [_set_cookie(SESSION_COOKIE, "", 0), _set_cookie(PENDING_COOKIE, "", 0)])
                return
            if self.path in ("/host", "/host/") and not self.creator() and client.config():
                try:
                    target, cookie = client.begin()
                    self._portal_diagnostic("start", "redirect")
                    self._portal_redirect(target, [cookie])
                except SSOError as error:
                    self._portal_diagnostic("start", str(error))
                    self.login("Work sign-in is temporarily unavailable. Your existing host login still works.")
                return
            return super().do_GET()

        def send_response(self, code, message=None):
            self._portal_response_code = code
            return super().send_response(code, message)

        def do_POST(self):
            session = self.session()
            path = urllib.parse.urlsplit(self.path).path
            if not session or session.get("authentication_method") != "ct400_portal" or path == "/host/login":
                return super().do_POST()
            # Capture immutable identity before the existing action handler runs.
            actor = dict(session)
            request_id = secrets.token_hex(12)
            try:
                client.audit("host_action_attempt", actor, path=path, request_id=request_id)
            except SSOError:
                self.send_error(503, "Account logging is temporarily unavailable. Please retry.")
                return
            try:
                return super().do_POST()
            finally:
                try:
                    client.audit("host_action_response", actor, path=path, request_id=request_id,
                                 http_status=getattr(self, "_portal_response_code", None))
                except SSOError:
                    self.log_message("CT400 host action completion audit unavailable")

        def log_request(self, code="-", size="-"):
            if urllib.parse.urlsplit(self.path).path.startswith("/host/auth/ct400/"):
                self.log_message('"%s %s %s" %s %s', self.command, urllib.parse.urlsplit(self.path).path, self.request_version, str(code), str(size))
            else:
                super().log_request(code, size)

    return CT400Handler
