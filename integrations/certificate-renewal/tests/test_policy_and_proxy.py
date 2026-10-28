"""Pure renewal deadline and narrowly scoped proxy transformation regressions."""
import datetime as dt
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from renewal_common import DAY, RenewalError, renewal_due, retry_at
from proxy_config import patch_acme_fallback, patch_proxy_consumer_paths

HTTP = '''server {
    listen 80;
    server_name mx2.brimstonecottage.uk;
    location ^~ /.well-known/acme-challenge/ {
        root /data/letsencrypt-acme-challenge;
        try_files $uri @xeams_mx2_acme;
    }
    location @xeams_mx2_acme {
        proxy_set_header Host $host;
        proxy_pass http://10.44.0.10:80;
    }
    location ~ "^/[A-Za-z0-9]{8}\\.htm$" {
        proxy_pass http://10.44.0.10:80;
    }
    location / { return 404; }
}
'''
HTTPS = '''server {
    listen 443 ssl;
    server_name mx2.brimstonecottage.uk;
    ssl_certificate /etc/letsencrypt/live/mx2.brimstonecottage.uk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mx2.brimstonecottage.uk/privkey.pem;
    location / { return 404; }
}
'''
UNRELATED = '''server {
    listen 443 ssl;
    server_name mta-sts.brimstonecottage.uk;
    ssl_certificate /etc/letsencrypt/live/mta-sts.brimstonecottage.uk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mta-sts.brimstonecottage.uk/privkey.pem;
    location / { return 404; }
}
'''


class Policy(unittest.TestCase):
    def test_deadline_is_anchored_to_not_before_not_deployment(self):
        before, after = 1000000, 1000000 + 90 * DAY
        policy = renewal_due(before, after, before + 27 * DAY, before + 27 * DAY)
        self.assertEqual(policy['next_due_at'], before + 28 * DAY)
        self.assertFalse(policy['due'])
        self.assertTrue(renewal_due(before, after, now=before + 28 * DAY)['due'])

    def test_future_state_cannot_postpone_deadline(self):
        result = renewal_due(1000000, 1000000 + 90 * DAY, 1000000 + 80 * DAY, 1000000 + 20 * DAY)
        self.assertEqual(result['next_due_at'], 1000000 + 28 * DAY)

    def test_six_day_certificate_renews_at_four_days(self):
        result = renewal_due(1000000, 1000000 + 6 * DAY, now=1000000)
        self.assertEqual(result['next_due_at'], 1000000 + 4 * DAY)
        self.assertFalse(result['due'])
        self.assertEqual(result['policy_reason'], 'expiry_safeguard')

    def test_nan_and_oversized_interval_rejected(self):
        for args in ({'not_before': float('nan'), 'not_after': 1000},
                     {'not_before': 1000, 'not_after': 1000 + 90 * DAY, 'interval_days': 29}):
            with self.assertRaises(RenewalError):
                renewal_due(**args)

    def test_retry_backoff_and_server_deadline(self):
        self.assertEqual(retry_at(1, 90 * DAY, now=1000), 4600)
        self.assertEqual(retry_at(10, 90 * DAY, now=1000), 1000 + 12 * 3600)
        self.assertEqual(retry_at(10, 6 * DAY, now=1000), 1000 + 3 * 3600)
        self.assertEqual(retry_at(1, 90 * DAY, now=1000, retry_after=99999), 99999)


class ProxyTransform(unittest.TestCase):
    def test_only_selected_http_block_changes_and_outage_falls_back(self):
        result = patch_acme_fallback(UNRELATED + HTTP + HTTPS, 'mx2.brimstonecottage.uk')
        self.assertTrue(result.startswith(UNRELATED))
        self.assertTrue(result.endswith(HTTPS))
        self.assertIn('root /data/letsencrypt-acme-challenge;', result)
        self.assertIn('try_files $uri @central_mx2_acme;', result)
        self.assertIn('error_page 404 502 503 504 = @xeams_mx2_acme;', result)
        self.assertIn('proxy_pass http://10.50.0.80:8099;', result)
        self.assertNotIn('proxy_pass http://10.50.0.80:8099/', result)
        self.assertIn('location ~ "^/[A-Za-z0-9]{8}\\.htm$"', result)
        self.assertIn('location / { return 404; }', result)

    def test_duplicate_or_changed_native_block_rejected(self):
        for text in (HTTP + HTTP, HTTP.replace('@xeams_mx2_acme', '@unexpected')):
            with self.assertRaises(RenewalError):
                patch_acme_fallback(text, 'mx2.brimstonecottage.uk')

    def test_repeat_patch_requires_explicit_review(self):
        result = patch_acme_fallback(HTTP, 'mx2.brimstonecottage.uk')
        with self.assertRaises(RenewalError):
            patch_acme_fallback(result, 'mx2.brimstonecottage.uk')

    def test_dedicated_https_paths_touch_only_the_approved_vhost(self):
        result = patch_proxy_consumer_paths(UNRELATED + HTTP + HTTPS)
        self.assertTrue(result.startswith(UNRELATED + HTTP))
        self.assertIn('ssl_certificate /etc/grange-certificate-renewal/consumers/mx2/fullchain.pem;', result)
        self.assertIn('ssl_certificate_key /etc/grange-certificate-renewal/consumers/mx2/privkey.pem;', result)
        self.assertEqual(result.count('/etc/letsencrypt/live/mta-sts.brimstonecottage.uk/'), 2)

    def test_combined_canada_transform_moves_both_approved_https_consumers(self):
        result = patch_proxy_consumer_paths(UNRELATED + HTTP + HTTPS)
        result = patch_proxy_consumer_paths(result, 'mta-sts.brimstonecottage.uk')
        self.assertIn('/consumers/mx2/fullchain.pem;', result)
        self.assertIn('/consumers/brimstone-mtasts/fullchain.pem;', result)
        self.assertIn('/consumers/brimstone-mtasts/privkey.pem;', result)
        self.assertIn(HTTP, result)
        self.assertNotIn('/etc/letsencrypt/live/', result)


if __name__ == '__main__':
    unittest.main()
