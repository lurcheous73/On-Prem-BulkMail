#!/usr/bin/env python3
"""Pure, guarded transformations of the inspected Brimstone proxy blocks.

Writes a separate candidate only. The operator must combine consumer-path
changes, check the original hash, run nginx -t, and reload transactionally.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from renewal_common import require


def server_blocks(text):
    # These inspected custom include files contain top-level server blocks.
    # Ignore braces in comments/quoted regexes (notably the native {8} route).
    result = []
    for match in re.finditer(r'(?m)^server\s*\{', text):
        index, depth, quote, comment, escaped = match.end() - 1, 0, None, False, False
        while index < len(text):
            character = text[index]
            if comment:
                if character == '\n':
                    comment = False
            elif escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif quote:
                if character == quote:
                    quote = None
            elif character in ('"', "'"):
                quote = character
            elif character == '#':
                comment = True
            elif character == '{':
                depth += 1
            elif character == '}':
                depth -= 1
                if depth == 0:
                    result.append((match.start(), index + 1))
                    break
            index += 1
        else:
            raise ValueError('custom proxy server block is not balanced')
    require(bool(result), 'no inspected top-level server blocks found')
    return result


def target_block(text, host, port):
    selected = []
    for start, end in server_blocks(text):
        block = text[start:end]
        if re.search(r'(?m)^\s*server_name\s+' + re.escape(host) + r';\s*$', block) and re.search(
                r'(?m)^\s*listen\s+' + str(port) + r'(?:\s|;)', block):
            selected.append((start, end, block))
    require(len(selected) == 1, 'expected exactly one inspected proxy server block')
    return selected[0]


def patch_acme_fallback(text, hostname):
    require(hostname in ('mx1.brimstonecottage.uk', 'mx2.brimstonecottage.uk'), 'HTTP fallback hostname outside scope')
    start, end, block = target_block(text, hostname, 80)
    number = hostname[2]
    old_route, central_route = '@xeams_mx' + number + '_acme', '@central_mx' + number + '_acme'
    require(central_route not in text, 'central fallback already exists; review idempotent deployment separately')
    expected = 'try_files $uri ' + old_route + ';'
    require(block.count(expected) == 1 and block.count('location ' + old_route + ' {') == 1,
            'native fallback does not match the inspected proxy configuration')
    require('root /data/letsencrypt-acme-challenge;' in block, 'local Certbot webroot must remain first')
    addition = '''    # Central public CSR HTTP-01 tokens; keep local webroot and Xeams fallback.
    location CENTRAL {
        proxy_set_header Host HOSTNAME;
        proxy_set_header X-Forwarded-Proto http;
        proxy_connect_timeout 3s;
        proxy_read_timeout 5s;
        proxy_pass http://10.50.0.80:8099;
        proxy_intercept_errors on;
        error_page 404 502 503 504 = NATIVE;
    }

'''.replace('CENTRAL', central_route).replace('HOSTNAME', hostname).replace('NATIVE', old_route)
    changed = block.replace(expected, 'try_files $uri ' + central_route + ';', 1)
    changed = changed.replace('    location ' + old_route + ' {', addition + '    location ' + old_route + ' {', 1)
    require(changed.count('proxy_pass http://10.50.0.80:8099;') == 1, 'central fallback insertion count invalid')
    return text[:start] + changed + text[end:]


def patch_proxy_consumer_paths(text, host='mx2.brimstonecottage.uk'):
    require(host in ('mx2.brimstonecottage.uk', 'mta-sts.brimstonecottage.uk'), 'HTTPS consumer hostname outside approved CT102 scope')
    start, end, block = target_block(text, host, 443)
    original = '/etc/letsencrypt/live/' + host + '/'
    leaf_directory = 'mx2' if host == 'mx2.brimstonecottage.uk' else 'brimstone-mtasts'
    destination = '/etc/grange-certificate-renewal/consumers/' + leaf_directory + '/'
    for directive, leaf in (('ssl_certificate', 'fullchain.pem'), ('ssl_certificate_key', 'privkey.pem')):
        expected = directive + ' ' + original + leaf + ';'
        require(block.count(expected) == 1, 'expected exactly one original dedicated HTTPS consumer path')
        block = block.replace(expected, directive + ' ' + destination + leaf + ';', 1)
    return text[:start] + block + text[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--hostname', choices=('mx1.brimstonecottage.uk', 'mx2.brimstonecottage.uk'), required=True)
    parser.add_argument('--dedicated-https-consumer', action='store_true')
    parser.add_argument('--dedicated-mtasts-consumer', action='store_true')
    args = parser.parse_args()
    source, destination = Path(args.input), Path(args.output)
    require(source.resolve() != destination.resolve() and not destination.exists(), 'write only a new separate proxy candidate')
    original = source.read_text()
    result = patch_acme_fallback(original, args.hostname)
    if args.dedicated_https_consumer:
        require(args.hostname == 'mx2.brimstonecottage.uk', 'dedicated HTTPS path change only approved on Canada CT102')
        result = patch_proxy_consumer_paths(result)
    if args.dedicated_mtasts_consumer:
        require(args.hostname == 'mx2.brimstonecottage.uk', 'dedicated MTA-STS paths only approved on Canada CT102')
        result = patch_proxy_consumer_paths(result, 'mta-sts.brimstonecottage.uk')
    destination.write_text(result)
    print(json.dumps({'source_sha256': hashlib.sha256(original.encode()).hexdigest(),
                      'candidate_sha256': hashlib.sha256(result.encode()).hexdigest(),
                      'live_configuration_changed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
