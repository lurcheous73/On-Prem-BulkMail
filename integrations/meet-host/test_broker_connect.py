"""Loopback-only broker TLS tests; disposable CA and synthetic client values."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grange_ct400_sso as sso

HOST = "broker-route.example.invalid"
SECRET = "fixture-private-client-secret-" + "x" * 40
CODE, VERIFIER = "c" * 43, "v" * 43
RESULT = {"identity": {"issuer": sso.ISSUER, "subject": "44444444-4444-4444-8444-444444444444"},
          "expires_in": 900}
DEFAULT_CONTEXT = ssl.create_default_context


class Broker(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append((self.path, self.headers.get("Host"), body))
        self.send_response(self.server.status)
        if 300 <= self.server.status < 400:
            self.send_header("Location", "https://must-not-follow.example.invalid/")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.server.body)))
        self.end_headers()
        try: self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError): pass


class BrokerConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="meet-broker-route-")
        cls.root = Path(cls.temp.name)
        cls.ca, cls.ca_key = cls.root / "ca.pem", cls.root / "ca.key"
        cls.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=Disposable Meet broker fixture CA", "-keyout", str(cls.ca_key), "-out", str(cls.ca))
        cls.certs = {}
        for name, host in (("good", HOST), ("wrong", "wrong-name.example.invalid")):
            key, csr, cert, ext = [cls.root / (name + suffix) for suffix in (".key", ".csr", ".pem", ".ext")]
            ext.write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
            cls.openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name,
                        "-keyout", str(key), "-out", str(csr))
            cls.openssl("x509", "-req", "-in", str(csr), "-CA", str(cls.ca), "-CAkey", str(cls.ca_key),
                        "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", str(cert))
            cls.certs[name] = (cert, key)

    @classmethod
    def openssl(cls, *args):
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    @contextlib.contextmanager
    def server(self, certificate="good", address="127.0.0.1", status=200, body=None):
        server_type = http.server.ThreadingHTTPServer
        if ":" in address:
            class IPv6Server(http.server.ThreadingHTTPServer): address_family = socket.AF_INET6
            server_type = IPv6Server
        server = server_type((address, 0), Broker)
        server.requests, server.names, server.status = [], [], status
        server.body = json.dumps(RESULT).encode() if body is None else body
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, self.certs[certificate]))
        context.set_servername_callback(lambda _, name, __: server.names.append(name))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try: yield server
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def exchange(self, server, address="127.0.0.1", trust=True):
        cfg = {"client_id": "meet-host", "client_secret": SECRET, "broker_connect_address": address}
        origin = "https://" + HOST + ":" + str(server.server_port)
        make_context = lambda: DEFAULT_CONTEXT(cafile=str(self.ca)) if trust else DEFAULT_CONTEXT()
        captured = io.StringIO()
        with patch.object(sso, "BROKER_ORIGIN", origin), \
             patch.object(sso.ssl, "create_default_context", side_effect=make_context), \
             patch.object(sso.socket, "getaddrinfo", side_effect=AssertionError("Pinned request must not resolve DNS")), \
             patch.object(sso.urllib.request, "build_opener", side_effect=AssertionError("Pinned request must not use an environment proxy")), \
             patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"}), \
             contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            try:
                return sso.exchange_code(cfg, CODE, VERIFIER)
            finally:
                self.assertEqual(captured.getvalue(), "")

    def test_pinned_tls_preserves_hostname_port_sni_callback_secret_code_and_pkce_without_dns_or_proxy(self):
        with self.server() as server:
            self.assertEqual(self.exchange(server), RESULT)
            self.assertEqual(len(server.requests), 1)
            path, host, body = server.requests[0]
            self.assertEqual(path, "/?page=portal_sso_token")
            self.assertEqual(host, HOST + ":" + str(server.server_port))
            self.assertEqual(server.names, [HOST])
            self.assertEqual(json.loads(body), {"grant_type": "authorization_code", "client_id": "meet-host",
                "client_secret": SECRET, "redirect_uri": sso.CALLBACK, "code": CODE, "code_verifier": VERIFIER})

    def test_wrong_hostname_certificate_is_rejected_before_any_secret_is_sent(self):
        with self.server(certificate="wrong") as server:
            with self.assertRaisesRegex(sso.SSOError, "^broker_unavailable$"): self.exchange(server)
            self.assertEqual(server.requests, [])

    def test_untrusted_certificate_is_rejected_before_any_secret_is_sent(self):
        with self.server() as server:
            with self.assertRaisesRegex(sso.SSOError, "^broker_unavailable$"): self.exchange(server, trust=False)
            self.assertEqual(server.requests, [])

    def test_redirect_is_rejected_without_replaying_code_or_secret(self):
        with self.server(status=307) as server:
            with self.assertRaisesRegex(sso.SSOError, "^broker_redirect_rejected$"): self.exchange(server)
            self.assertEqual(len(server.requests), 1)

    def test_non_success_status_is_rejected_with_fixed_private_diagnostic(self):
        with self.server(status=503, body=(SECRET + CODE + VERIFIER).encode()) as server:
            with self.assertRaisesRegex(sso.SSOError, "^broker_unavailable$"): self.exchange(server)
            self.assertEqual(len(server.requests), 1)

    def test_oversized_or_invalid_response_is_rejected_without_exposing_body(self):
        for body, reason in ((b"x" * 16385, "invalid_broker_response"),
                             ((SECRET + CODE).encode(), "broker_unavailable"), (b"[]", "invalid_broker_response")):
            with self.subTest(reason=reason), self.server(body=body) as server:
                with self.assertRaisesRegex(sso.SSOError, "^" + reason + "$"): self.exchange(server)

    def test_invalid_pin_never_falls_back_to_dns_or_unpinned_transport(self):
        cfg = {"client_id": "meet-host", "client_secret": SECRET}
        for value in (None, False, 123, [], {}, "bad.example.invalid", "127.0.0.1,192.0.2.1", "[::1]", "fe80::1%eth0"):
            with self.subTest(value=value), patch.object(sso, "_pinned_exchange") as pinned, \
                 patch.object(sso.urllib.request, "build_opener") as unpinned:
                with self.assertRaisesRegex(sso.SSOError, "^broker_unavailable$"):
                    sso.exchange_code({**cfg, "broker_connect_address": value}, CODE, VERIFIER)
                pinned.assert_not_called(); unpinned.assert_not_called()

    def test_omitted_and_empty_pin_preserve_original_urllib_request_and_timeout(self):
        cfg = {"client_id": "meet-host", "client_secret": SECRET}
        for extra in ({}, {"broker_connect_address": ""}):
            with self.subTest(extra=extra), patch.object(sso, "_pinned_exchange") as pinned, \
                 patch.object(sso.urllib.request, "build_opener") as factory:
                response = factory.return_value.open.return_value.__enter__.return_value
                response.status = 200; response.read.return_value = json.dumps(RESULT).encode()
                self.assertEqual(sso.exchange_code({**cfg, **extra}, CODE, VERIFIER), RESULT)
                pinned.assert_not_called()
                self.assertIsInstance(factory.call_args.args[0], sso.NoRedirect)
                request = factory.return_value.open.call_args.args[0]
                self.assertEqual(request.full_url, sso.BROKER_ORIGIN + "/?page=portal_sso_token")
                self.assertEqual(request.method, "POST")
                self.assertEqual(factory.return_value.open.call_args.kwargs, {"timeout": 8})
                self.assertEqual(json.loads(request.data)["redirect_uri"], sso.CALLBACK)

    def test_ipv6_literal_uses_same_authenticated_hostname(self):
        try:
            probe = socket.socket(socket.AF_INET6); probe.bind(("::1", 0)); probe.close()
        except OSError: self.skipTest("IPv6 loopback unavailable")
        with self.server(address="::1") as server:
            self.assertEqual(self.exchange(server, "::1"), RESULT)
            self.assertEqual(server.names, [HOST])


if __name__ == "__main__": unittest.main(verbosity=2)
