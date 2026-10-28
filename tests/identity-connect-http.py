#!/usr/bin/env python3
"""Trusted localhost HTTPS route tests using disposable certificates and synthetic cookies."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

REPO = Path(__file__).resolve().parents[1]
HOST = 'workspace-pin.example.invalid'
SECRET = 'fixture-private-cookie-not-a-real-session'
PROFILE = {'id': '44444444-4444-4444-8444-444444444444', 'userName': 'fixture-private-user',
           'email': 'fixture-private@example.invalid', 'displayName': 'Fixture member',
           'status': 1, 'activationStatus': 1, 'isVisitor': False}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get('Host'), self.headers.get('Authorization')))
        body = json.dumps({'status': 0, 'response': PROFILE}).encode()
        self.send_response(302 if self.server.redirect else 200)
        if self.server.redirect: self.send_header('Location', '/must-not-follow')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PrivateRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='bulkmail-private-route-')
        cls.root = Path(cls.tmp.name)
        cls.ca = cls.root / 'ca.pem'
        cls.ca_key = cls.root / 'ca.key'
        cls.openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=Disposable private-route fixture CA',
                    '-keyout', str(cls.ca_key), '-out', str(cls.ca))
        cls.certs = {}
        for name, san in [('good', 'DNS:' + HOST + ',IP:127.0.0.1,IP:::1'),
                          ('wrong', 'DNS:wrong-name.example.invalid')]:
            key, csr, cert, ext = [cls.root / (name + suffix) for suffix in ('.key', '.csr', '.pem', '.ext')]
            ext.write_text('subjectAltName=' + san + '\nextendedKeyUsage=serverAuth\n')
            cls.openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + name,
                        '-keyout', str(key), '-out', str(csr))
            cls.openssl('x509', '-req', '-in', str(csr), '-CA', str(cls.ca), '-CAkey', str(cls.ca_key),
                        '-CAcreateserial', '-days', '1', '-extfile', str(ext), '-out', str(cert))
            cls.certs[name] = (cert, key)
        cls.harness = cls.root / 'request.php'
        cls.harness.write_text('''<?php
require $argv[1].'/app/bulkmail-integrations.php';
require $argv[1].'/app/bulkmail-identity.php';
$_COOKIE=['asc_auth_key'=>'fixture-private-cookie-not-a-real-session'];
$_GET=['connect_address'=>'192.0.2.99']; $_POST=$_GET;
$_SERVER['HTTP_X_CONNECT_ADDRESS']='192.0.2.99';
try {
    $cfg=bm_identity_config(); $profile=bm_identity_portal_profile($cfg);
    echo json_encode(['ok'=>true,'issuer'=>bm_identity_issuer($cfg),'id'=>$profile['id']]);
} catch (BMIdentityException $e) {
    echo json_encode(['ok'=>false,'reason'=>$e->reason,'http'=>$e->httpStatus,'curl'=>$e->curlCode]);
}
''')

    @classmethod
    def openssl(cls, *args):
        subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    @contextlib.contextmanager
    def server(self, certificate='good', address='127.0.0.1', redirect=False):
        server_type = http.server.ThreadingHTTPServer
        if ':' in address:
            class IPv6Server(http.server.ThreadingHTTPServer): address_family = socket.AF_INET6
            server_type = IPv6Server
        server = server_type((address, 0), Handler)
        server.requests, server.names, server.redirect = [], [], redirect
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, self.certs[certificate]))
        context.set_servername_callback(lambda _, name, __: server.names.append(name))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try: yield server
        finally: server.shutdown(); server.server_close(); thread.join(timeout=2)

    def request(self, origin, address='', proxy=None, trust=True):
        config = self.root / 'integrations.php'
        settings = {'identity': {'enabled': True, 'auto_login': True, 'base_url': origin,
                                 'connect_address': address, 'allow_http': False}}
        # The private file is the only input that controls the actual connection route.
        config.write_text('<?php return json_decode(' + repr(json.dumps(settings)) + ', true);')
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
        env['BULKMAIL_INTEGRATIONS_CONFIG'] = str(config)
        if proxy: env['https_proxy'] = proxy
        command = ['php']
        if trust: command += ['-d', 'curl.cainfo=' + str(self.ca)]
        result = subprocess.run(command + [str(self.harness), str(REPO)], env=env,
                                capture_output=True, text=True, timeout=18, check=True)
        for secret in (SECRET, PROFILE['id'], PROFILE['userName'], PROFILE['email'], origin, str(address)):
            if secret: self.assertNotIn(secret, result.stderr)
        return json.loads(result.stdout), result.stderr

    def test_nonexistent_hostname_is_pinned_with_original_host_sni_and_identity(self):
        with self.server() as server:
            origin = 'https://' + HOST + ':' + str(server.server_port)
            result, logs = self.request(origin, '127.0.0.1', proxy='http://127.0.0.1:1')
            self.assertEqual(result, {'ok': True, 'issuer': origin, 'id': PROFILE['id']})
            self.assertEqual(server.requests, [('/api/2.0/people/@self.json', HOST + ':' + str(server.server_port), SECRET)])
            self.assertIn(HOST, server.names)
            record = next(json.loads(line.split('BulkMail portal identity ', 1)[1]) for line in logs.splitlines()
                          if '"outcome":"api_result"' in line)
            self.assertEqual(record['curl_code'], 0)
            self.assertEqual(record['http_status'], 200)
            for key in ['dns_ms', 'connect_ms', 'tls_ms', 'first_byte_ms', 'total_ms']:
                self.assertIs(type(record[key]), int); self.assertTrue(0 <= record[key] <= 300000)

    def test_wrong_hostname_certificate_is_rejected_even_when_its_ca_is_trusted(self):
        with self.server('wrong') as server:
            result, _ = self.request('https://' + HOST + ':' + str(server.server_port), '127.0.0.1')
            self.assertEqual(result, {'ok': False, 'reason': 'transport_failed', 'http': 0, 'curl': 60})
            self.assertEqual(server.requests, [])

    def test_untrusted_certificate_is_rejected(self):
        with self.server() as server:
            result, _ = self.request('https://' + HOST + ':' + str(server.server_port), '127.0.0.1', trust=False)
            self.assertEqual(result, {'ok': False, 'reason': 'transport_failed', 'http': 0, 'curl': 60})
            self.assertEqual(server.requests, [])

    def test_redirect_is_not_followed(self):
        with self.server(redirect=True) as server:
            result, _ = self.request('https://' + HOST + ':' + str(server.server_port), '127.0.0.1')
            self.assertEqual(result, {'ok': False, 'reason': 'http_rejected', 'http': 302, 'curl': 0})
            self.assertEqual(len(server.requests), 1)

    def test_invalid_pin_fails_before_any_request_instead_of_falling_back(self):
        with self.server() as server:
            origin = 'https://127.0.0.1:' + str(server.server_port)
            result, _ = self.request(origin, '127.0.0.1,192.0.2.7')
            self.assertEqual(result, {'ok': False, 'reason': 'request_invalid', 'http': 0, 'curl': 0})
            self.assertEqual(server.requests, [])

    def test_unpinned_flow_ignores_request_address_claims_and_uses_ordinary_transport(self):
        with self.server() as server:
            origin = 'https://127.0.0.1:' + str(server.server_port)
            result, _ = self.request(origin)
            self.assertEqual(result, {'ok': True, 'issuer': origin, 'id': PROFILE['id']})
            self.assertEqual(len(server.requests), 1)

    def test_ipv6_destination_uses_the_same_https_hostname(self):
        try:
            probe = socket.socket(socket.AF_INET6); probe.bind(('::1', 0)); probe.close()
        except OSError: self.skipTest('IPv6 loopback is unavailable in this local test environment')
        with self.server(address='::1') as server:
            origin = 'https://' + HOST + ':' + str(server.server_port)
            result, _ = self.request(origin, '::1')
            self.assertEqual(result, {'ok': True, 'issuer': origin, 'id': PROFILE['id']})
            self.assertIn(HOST, server.names)


if __name__ == '__main__': unittest.main(verbosity=2)
