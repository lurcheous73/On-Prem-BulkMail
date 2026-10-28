#!/usr/bin/env python3
"""Real PHP session/SQLite lock diagnostics using local disposable data only."""
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[1]
PREFIX = 'BulkMail request bootstrap '
SENSITIVE = 'fixture-private-cookie-user-query-and-header'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_): return None


class BootstrapFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='bulkmail-bootstrap-review-')
        cls.root = Path(cls.temporary.name)
        shutil.copytree(REPO / 'app', cls.root / 'app')
        (cls.root / 'sessions').mkdir()
        cls.database = cls.root / 'fixture.sqlite'
        main = cls.root / 'app/index.php'
        main.write_text(main.read_text().replace("const DB_FILE = '/var/lib/bulkmail/bulkmail.sqlite';",
                       "const DB_FILE = '" + str(cls.database) + "';")
                       .replace("const DATA_DIR = '/var/lib/bulkmail';", "const DATA_DIR = '" + str(cls.root) + "';")
                       .replace('const DELIVERY_ENABLED = true;', 'const DELIVERY_ENABLED = false;'))
        with sqlite3.connect(cls.database) as db:
            db.executescript((REPO / 'database/schema.sql').read_text())
            db.execute("INSERT INTO users(id,username,password_hash,display_name,email,is_admin) VALUES(1,?,?,?,?,0)",
                       ('Fixture', 'not-a-real-password-hash', SENSITIVE, 'fixture@example.invalid'))
        cls.config = cls.root / 'integrations.php'
        cls.config.write_text("<?php return ['identity'=>['enabled'=>true,'auto_login'=>true,"
                              "'base_url'=>'https://workspace.example.invalid','sso_clients'=>['meet-host'=>["
                              "'enabled'=>true,'secret'=>'fixture-32-character-client-secret-only',"
                              "'redirect_uri'=>'https://meet.example.invalid/callback']]]];")
        with contextlib.closing(socket.socket()) as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        cls.base = 'http://127.0.0.1:' + str(port) + '/'
        cls.logpath = cls.root / 'php.log'
        cls.log = cls.logpath.open('w+')
        cls.process = subprocess.Popen(['php', '-d', 'session.auto_start=0', '-d',
            'session.save_path=' + str(cls.root / 'sessions'), '-S', '127.0.0.1:' + str(port),
            '-t', str(cls.root / 'app')], env=dict(os.environ, BULKMAIL_INTEGRATIONS_CONFIG=str(cls.config)),
            stdout=cls.log, stderr=cls.log)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2): break
            except OSError:
                if time.monotonic() > deadline: raise
                time.sleep(.02)
        cls.client = urllib.request.build_opener(NoRedirect())

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try: cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired: cls.process.kill(); cls.process.wait(timeout=5)
        cls.log.close(); cls.temporary.cleanup()

    def records(self, offset):
        records = []
        for line in self.logpath.read_text().splitlines()[offset:]:
            if PREFIX in line: records.append(json.loads(line.split(PREFIX, 1)[1]))
        return records

    def offset(self): return len(self.logpath.read_text().splitlines())

    def request(self, path='?page=login', headers=None, data=None):
        request = urllib.request.Request(self.base + path, headers=headers or {}, data=data)
        try: response = self.client.open(request, timeout=8)
        except urllib.error.HTTPError as error: response = error
        with response:
            return response.status, dict(response.headers), response.read()

    @contextlib.contextmanager
    def locked_session(self):
        # This is a newly created local fixture session, never a real account/session.
        session_id = 'fixture-bootstrap-session'
        code = r'''session_id($argv[1]); session_start();
$_SESSION=['user_id'=>1,'portal_auto_login_suppressed'=>true,'private_fixture'=>$argv[2]];
session_write_close(); session_start(); echo "LOCKED\n"; flush(); fgets(STDIN); session_write_close();'''
        holder = subprocess.Popen(['php', '-d', 'session.save_path=' + str(self.root / 'sessions'),
                                  '-r', code, session_id, SENSITIVE], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), 'LOCKED')
        try: yield {'Cookie': 'PHPSESSID=' + session_id}, holder
        finally:
            if holder.poll() is None:
                holder.stdin.write('\n'); holder.stdin.flush()
            holder.communicate(timeout=5)

    def wait_for(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() > deadline: self.fail('local fixture did not reach the expected stage')
            time.sleep(.01)

    def test_normal_bulkmail_route_still_waits_for_its_session_and_reports_the_wait(self):
        offset = self.offset()
        with concurrent.futures.ThreadPoolExecutor() as pool, self.locked_session() as (headers, holder):
            future = pool.submit(self.request, '?page=login', headers)
            self.wait_for(lambda: any(x['stage'] == 'ingress' for x in self.records(offset)))
            time.sleep(.15)
            self.assertFalse(future.done())
            self.assertNotIn('session_ready', [x['stage'] for x in self.records(offset)])
            holder.stdin.write('\n'); holder.stdin.flush(); holder.wait(timeout=5)
            status, _, _ = future.result(timeout=5)
        self.assertEqual(status, 302)  # Existing local session still redirects away from login.
        records = self.records(offset)
        ready = next(x for x in records if x['stage'] == 'session_ready')
        self.assertGreaterEqual(ready['elapsed_ms'], 100)
        self.assertTrue(ready['session_cookie_present'])
        self.assertIn('session_present', [x.get('reason') for x in records])
        self.assertEqual(records[-1]['stage'], 'shutdown')

    def test_authorize_does_not_wait_for_an_unrelated_local_session_or_use_it(self):
        query = urllib.parse.urlencode({'page': 'portal_sso_authorize', 'client_id': 'meet-host',
            'redirect_uri': 'https://meet.example.invalid/callback', 'response_type': 'code',
            'code_challenge_method': 'S256', 'code_challenge': 'a' * 43, 'state': 'b' * 32})
        offset = self.offset()
        with concurrent.futures.ThreadPoolExecutor() as pool, self.locked_session() as (headers, _):
            future = pool.submit(self.request, '?' + query, headers)
            try: status, response_headers, _ = future.result(timeout=1)
            except concurrent.futures.TimeoutError:
                self.fail('broker authorization blocked behind the local PHP session lock')
        self.assertEqual(status, 302)
        self.assertIn('error=login_required', response_headers['Location'])
        self.assertNotIn('Set-Cookie', response_headers)
        stages = [x['stage'] for x in self.records(offset)]
        self.assertIn('session_skipped_broker', stages)
        self.assertNotIn('session_ready', stages)

    def test_token_still_requires_client_auth_without_reading_or_rotating_local_session(self):
        offset = self.offset()
        with concurrent.futures.ThreadPoolExecutor() as pool, self.locked_session() as (headers, _):
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            body = urllib.parse.urlencode({'client_id': 'meet-host', 'client_secret': SENSITIVE}).encode()
            future = pool.submit(self.request, '?page=portal_sso_token', headers, body)
            try: status, response_headers, response = future.result(timeout=1)
            except concurrent.futures.TimeoutError:
                self.fail('broker token exchange blocked behind the local PHP session lock')
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(response), {'error': 'invalid_client'})
        self.assertNotIn('Set-Cookie', response_headers)
        self.assertIn('session_skipped_broker', [x['stage'] for x in self.records(offset)])

    def test_database_lock_is_distinguished_from_the_session_lock(self):
        self.request()  # Complete initial schema creation before holding SQLite exclusively.
        offset = self.offset()
        with sqlite3.connect(self.database, timeout=5) as db, concurrent.futures.ThreadPoolExecutor() as pool:
            db.execute('BEGIN EXCLUSIVE')
            future = pool.submit(self.request)
            self.wait_for(lambda: any(x['stage'] == 'database_ready' for x in self.records(offset)))
            time.sleep(.15)
            stages = [x['stage'] for x in self.records(offset)]
            self.assertIn('session_ready', stages)
            self.assertNotIn('schema_ready', stages)
            self.assertFalse(future.done())
            db.rollback()
            status, _, _ = future.result(timeout=5)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(next(x for x in self.records(offset) if x['stage'] == 'schema_ready')['elapsed_ms'], 100)

    def test_diagnostics_accept_only_fixed_routes_headers_reasons_and_never_secrets(self):
        code = r'''$_GET=['page'=>$argv[2],'state'=>$argv[2]];
$_COOKIE=['asc_auth_key'=>$argv[2],session_name()=>$argv[2]];
$_SERVER=['REQUEST_METHOD'=>$argv[2],'HTTP_SEC_FETCH_DEST'=>$argv[2],'HTTP_SEC_FETCH_SITE'=>$argv[2],
'HTTP_AUTHORIZATION'=>$argv[2],'HTTP_REFERER'=>$argv[2],'REQUEST_URI'=>$argv[2]];
$_SESSION=['user_id'=>999,'display_name'=>$argv[2],'draft'=>['body_html'=>$argv[2]]];
require $argv[1]; bm_request_diagnostic('ingress'); bm_request_diagnostic('auto_login_gate',$argv[2]);'''
        result = subprocess.run(['php', '-r', code, str(REPO / 'app/bulkmail-request-diagnostics.php'), SENSITIVE],
                                capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout, '')
        self.assertNotIn(SENSITIVE, result.stderr)
        records = [json.loads(line.split(PREFIX, 1)[1]) for line in result.stderr.splitlines() if PREFIX in line]
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertEqual((record['route'], record['method'], record['fetch_dest'], record['fetch_site']),
                             ('other', 'other', 'other', 'other'))
            self.assertTrue(record['portal_cookie_present'])
            self.assertTrue(record['session_cookie_present'])
        self.assertEqual(records[1]['reason'], 'other')
        self.assertNotIn('user_id', records[0])


if __name__ == '__main__': unittest.main(verbosity=2)
