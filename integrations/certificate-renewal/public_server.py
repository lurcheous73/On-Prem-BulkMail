#!/usr/bin/env python3
"""Private read-only publication of enrolled public certificate bundles.

No directory listing, uploads, redirects, filesystem path arguments or privileged
operations. Bind/address/source allowlists come from a root-owned configuration.
"""
from __future__ import annotations
import argparse
import http.server
import ipaddress
import json
from pathlib import Path
import re
import socketserver
import stat
import sys

ALLOWED_NAMES = frozenset(('mx1.the-grange.uk', 'mx2.the-grange.uk',
                           'mx1.brimstonecottage.uk', 'mx2.brimstonecottage.uk'))


def read_public_file(root, relative, limit):
    root = Path(root).resolve(strict=True)
    candidate = root.joinpath(*relative)
    # Never follow a link out of (or within) the controlled publication tree.
    cursor = root
    for part in relative:
        if part in ('', '.', '..') or '/' in part or '\\' in part:
            raise ValueError('invalid path component')
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError('symlink refused')
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError('path outside public root')
    st = resolved.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        raise ValueError('invalid public file')
    data = resolved.read_bytes()
    if len(data) > limit or b'PRIVATE KEY' in data:
        raise ValueError('unsafe public payload')
    return data


def make_handler(config):
    names = frozenset(config['hosts'])
    if not names or not names <= ALLOWED_NAMES:
        raise ValueError('host scope invalid')
    sources = frozenset(str(ipaddress.ip_address(value)) for value in config['allowed_sources'])
    challenge_names = frozenset(config.get('http_challenge_hosts', []))
    if not challenge_names <= names:
        raise ValueError('challenge host scope invalid')

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'PublicCertificateService/1'
        sys_version = ''

        def log_message(self, format_string, *args):
            # Do not log challenge filenames, query strings, headers or bodies.
            pass

        def do_HEAD(self):
            self.respond(False)

        def do_GET(self):
            self.respond(True)

        def respond(self, include_body):
            route, host, status = 'invalid', None, 404
            content_type, data = 'application/json', b'{"error":"not_found"}\n'
            try:
                source = str(ipaddress.ip_address(self.client_address[0]))
                if source not in sources:
                    status, data = 403, b'{"error":"source_not_allowed"}\n'
                elif self.path == '/healthz':
                    route, status, data = 'health', 200, b'{"status":"ok"}\n'
                else:
                    bundle = re.fullmatch(r'/v1/([a-z0-9.-]+)\.json', self.path)
                    challenge = re.fullmatch(r'/acme/([a-z0-9.-]+)/([A-Za-z0-9_-]{16,200})', self.path)
                    standard = re.fullmatch(r'/\.well-known/acme-challenge/([A-Za-z0-9_-]{16,200})', self.path)
                    challenge_host = self.headers.get('Host', '').lower()
                    if bundle and bundle.group(1) in names:
                        host, route = bundle.group(1), 'certificate'
                        data = read_public_file(config['public_dir'], (host + '.json',), 131072)
                        obj = json.loads(data)
                        if obj.get('schema') != 1 or obj.get('hostname') != host or not isinstance(obj.get('fullchain_pem'), str):
                            raise ValueError('invalid certificate envelope')
                        status = 200
                    elif challenge and challenge.group(1) in challenge_names:
                        host, route = challenge.group(1), 'acme_challenge'
                        data = read_public_file(config['challenge_dir'],
                            (host, '.well-known', 'acme-challenge', challenge.group(2)), 4096)
                        if not re.fullmatch(rb'[A-Za-z0-9_.-]+\n?', data):
                            raise ValueError('invalid challenge payload')
                        content_type, status = 'text/plain', 200
                    elif standard and challenge_host in challenge_names:
                        host, route = challenge_host, 'acme_challenge'
                        data = read_public_file(config['challenge_dir'],
                            (host, '.well-known', 'acme-challenge', standard.group(1)), 4096)
                        if not re.fullmatch(rb'[A-Za-z0-9_.-]+\n?', data):
                            raise ValueError('invalid challenge payload')
                        content_type, status = 'text/plain', 200
            except (OSError, ValueError, KeyError):
                status, data = 404, b'{"error":"not_found"}\n'
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            if include_body:
                self.wfile.write(data)
            print(json.dumps({'event': 'public_request', 'source': self.client_address[0],
                              'route': route, 'hostname': host, 'status': status}), flush=True)

    return Handler


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    address = ipaddress.ip_address(config['bind_address'])
    if not address.is_private or address.is_unspecified or address.is_multicast:
        raise ValueError('publisher must bind one explicit private address')
    port = int(config.get('port', 8099))
    if not 1024 <= port <= 65535:
        raise ValueError('publisher requires an unprivileged port')
    with Server((str(address), port), make_handler(config)) as server:
        print(json.dumps({'event': 'public_server_started', 'address': str(address), 'port': port}), flush=True)
        server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'event': 'public_server_failed', 'error_type': type(error).__name__}), flush=True)
        sys.exit(1)
