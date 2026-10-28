import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('activity_helper', root / 'request-imap-activity.py')
activity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activity)

GUID = '00000000-0000-0000-0000-000000000001'
SETTINGS = {'host': 'redis.example.test', 'port': 6379, 'tls': False,
            'user': 'fixture-user', 'password': 'fixture-password'}


class FakeRedis:
    def __init__(self, subscribers=1, timeout=False):
        self.calls, self.closed, self.subscribers, self.timeout = [], False, subscribers, timeout

    def command(self, *args):
        self.calls.append(args)
        if args == ('PING',):
            return b'PONG'
        if args == ('PUBSUB', 'NUMSUB', activity.CHANNEL):
            return [activity.CHANNEL.encode(), self.subscribers]
        if args[0] == 'PUBLISH':
            if self.timeout:
                raise TimeoutError('sensitive server detail fixture-password')
            return self.subscribers
        raise AssertionError('Unexpected Redis command')

    def close(self):
        self.closed = True


class ActivitySafety(unittest.TestCase):
    def test_json_comments_trailing_commas_preserve_string_content(self):
        raw = b'{/*comment*/"URL":"http://host/a/*x*/", "password":"comma,}and\\\"//",//line\n"Hosts":[{"Port":"6379",},],}'
        value = activity.json_config(raw)
        self.assertEqual(value['URL'], 'http://host/a/*x*/')
        self.assertEqual(value['password'], 'comma,}and"//')
        self.assertEqual(value['Hosts'], [{'Port': '6379'}])
        with self.assertRaises(activity.Stop):
            activity.json_config('{"Password":"one","password":"two"}')

    def test_configuration_provider_order_and_private_environment_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            service, config = base / 'service', base / 'config'
            service.mkdir()
            config.mkdir()
            (service / 'appsettings.json').write_text(json.dumps({'pathToConf': str(config)}))
            for name in ('appsettings', 'storage', 'mail', 'elastic'):
                (config / (name + '.json')).write_text('{}')
            (config / 'mail.json').write_text(json.dumps({'Mail': {'ImapSync': {'Redis': {
                'Hosts': [{'Host': 'redis.example.test', 'Port': '6379'}],
                'Password': 'base-fixture', 'Ssl': False}}}}))
            (config / 'mail.production.json').write_text('{//native override\n"mail":{"ImapSync":{"Redis":{"Password":"file-fixture",},},},}')
            env = {'ENVIRONMENT': 'production', 'mail__ImapSync__Redis__Password': 'env-fixture'}
            with patch.object(activity, 'CONFIG_DIR', config):
                effective, name = activity.effective_config(service, env, {})
                self.assertEqual(activity.redis_settings(effective)['password'], 'env-fixture')
                effective, _ = activity.effective_config(service, env, {'mail:imapsync:redis:password': 'cli-fixture'})
            self.assertEqual(name, 'production')
            self.assertEqual(activity.redis_settings(effective)['password'], 'cli-fixture')

    def test_unsupported_redis_modes_fail_before_connection(self):
        base = {'mail:imapsync:redis:hosts:0:host': 'redis.example.test',
                'mail:imapsync:redis:hosts:0:port': 6379}
        self.assertEqual(activity.redis_settings(base)['port'], 6379)
        for key, value in (('connectionstring', 'fixture'), ('hosts:1:host', 'other.example.test'),
                           ('issentinelcluster', True), ('keyprefix', 'other:'),
                           ('hosts:0:host', 'redis://user:fixture-password@host')):
            with self.subTest(key=key), self.assertRaises(activity.Stop):
                activity.redis_settings({**base, 'mail:imapsync:redis:' + key: value})

    def test_application_arguments_are_literal_configuration(self):
        result = activity.process_arguments(['/usr/bin/dotnet', str(activity.SERVICE_DLL),
                                             '--ENVIRONMENT', 'production', '--mail:ImapSync:Redis:Ssl=false'],
                                            activity.SERVICE_DIR)
        self.assertEqual(result, {'environment': 'production', 'mail:imapsync:redis:ssl': 'false'})
        with self.assertRaises(activity.Stop):
            activity.process_arguments(['/usr/bin/other'], activity.SERVICE_DIR)

    def test_payload_is_only_normal_alive_notification(self):
        self.assertEqual(json.loads(activity.activity_payload(GUID)), {
            'Object': {'UserName': GUID, 'Tenant': 1, 'MailBoxId': 0, 'Folder': -1, 'Tags': None}, 'Action': 1})
        with self.assertRaises(activity.Stop):
            activity.activity_payload('00000000-0000-0000-0000-000000000000')

    def test_default_probe_does_not_publish_or_read_keys(self):
        client = FakeRedis()
        result = activity.request(SETTINGS, GUID, False, lambda settings: client)
        self.assertEqual(client.calls, [('PING',), ('PUBSUB', 'NUMSUB', activity.CHANNEL)])
        self.assertFalse(result['published'])
        self.assertFalse(result['tracking_ready'])
        self.assertTrue(client.closed)

    def test_no_subscriber_stops_before_publish(self):
        client = FakeRedis(subscribers=0)
        with self.assertRaises(activity.Stop):
            activity.request(SETTINGS, GUID, True, lambda settings: client)
        self.assertFalse(any(call[0] == 'PUBLISH' for call in client.calls))
        self.assertTrue(client.closed)

    def test_publish_happens_once_on_exact_channel(self):
        client = FakeRedis()
        result = activity.request(SETTINGS, GUID, True, lambda settings: client)
        sends = [call for call in client.calls if call[0] == 'PUBLISH']
        self.assertEqual(sends, [('PUBLISH', activity.CHANNEL, activity.activity_payload(GUID))])
        self.assertTrue(result['published'])
        self.assertFalse(result['tracking_ready'])

    def test_uncertain_publish_stops_without_retry_or_secret_output(self):
        client = FakeRedis(timeout=True)
        with self.assertRaisesRegex(activity.Stop, 'outcome is unknown') as caught:
            activity.request(SETTINGS, GUID, True, lambda settings: client)
        self.assertEqual(sum(call[0] == 'PUBLISH' for call in client.calls), 1)
        self.assertNotIn('fixture-password', str(caught.exception))
        self.assertTrue(client.closed)

    def test_resp_errors_are_redacted(self):
        client = activity.Redis.__new__(activity.Redis)
        client.stream = io.BytesIO(b'-ERR authentication fixture-password\r\n')
        with self.assertRaises(activity.Stop) as caught:
            client._read()
        self.assertNotIn('fixture-password', str(caught.exception))

    def test_main_outputs_no_credentials_or_plain_user_guid(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['activity', '--user-guid', GUID]), \
                patch.object(activity, 'native_context', return_value=(SETTINGS, {'service_pid': 123})), \
                patch.object(activity, 'request', return_value={'published': False}), \
                contextlib.redirect_stdout(output):
            activity.main()
        self.assertNotIn(SETTINGS['password'], output.getvalue())
        self.assertNotIn(SETTINGS['user'], output.getvalue())
        self.assertNotIn(GUID, output.getvalue())
        self.assertIn('redis_auth_configured', output.getvalue())


if __name__ == '__main__':
    unittest.main()
