#!/usr/bin/env python3
"""Inspect native ImapSync settings; optionally request normal user activity.

Run inside the community container. Default mode publishes nothing. Redis
credentials stay in this process and are never placed in subprocess arguments,
environment variables, logs or output. This creates no authentication session.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys
import uuid

SERVICE = 'onlyofficeMailImap.service'
SERVICE_DIR = pathlib.Path('/var/www/onlyoffice/Services/MailImap')
SERVICE_DLL = SERVICE_DIR / 'ASC.Mail.ImapSync.Service.dll'
SERVICE_HASH = 'ffeef42868c9dc0c190ddb56b4dda2b384145bc9f6ef51d09af17f3bf2583b16'
CONFIG_DIR = pathlib.Path('/etc/onlyoffice/communityserver')
CHANNEL = 'asc:channel:insert:asc.mail.core.entities.cachedtenantusermailbox'


class Stop(RuntimeError):
    """A fixed, nonsecret diagnostic safe to display."""


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def json_config(raw):
    """Read the comments/trailing commas accepted by .NET JSON configuration."""
    text = raw.decode('utf-8-sig') if isinstance(raw, bytes) else raw
    out, index, quoted, escaped = [], 0, False, False
    while index < len(text):
        char = text[index]
        if quoted:
            out.append(char)
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            index += 1
        elif char == '"':
            quoted = True
            out.append(char)
            index += 1
        elif text.startswith('//', index):
            end = text.find('\n', index + 2)
            index = len(text) if end < 0 else end
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            require(end >= 0, 'Unterminated JSON configuration comment')
            out.append(' ')
            index = end + 2
        else:
            out.append(char)
            index += 1
    require(not quoted, 'Unterminated JSON configuration string')
    text, out, quoted, escaped = ''.join(out), [], False, False
    for index, char in enumerate(text):
        if quoted:
            out.append(char)
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            out.append(char)
        elif char == ',':
            tail = text[index + 1:].lstrip()
            if not tail.startswith(('}', ']')):
                out.append(char)
        else:
            out.append(char)
    def unique_object(pairs):
        result, seen = {}, set()
        for key, value in pairs:
            require(key.casefold() not in seen, 'Duplicate native configuration key')
            seen.add(key.casefold())
            result[key] = value
        return result
    try:
        result = json.loads(''.join(out), object_pairs_hook=unique_object)
    except (ValueError, TypeError):
        raise Stop('Native JSON configuration could not be parsed') from None
    require(isinstance(result, dict), 'Configuration root must be an object')
    return result


def flatten(value, prefix='', result=None):
    result = {} if result is None else result
    if isinstance(value, dict):
        for key, child in value.items():
            flatten(child, (prefix + ':' if prefix else '') + key.casefold(), result)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            flatten(child, prefix + ':' + str(index), result)
    else:
        require(prefix not in result, 'Duplicate native configuration key')
        result[prefix] = value
    return result


def config_file(path, required=False):
    if not path.exists():
        require(not required, 'A required native configuration file is absent')
        return {}
    raw = path.read_bytes()
    require(len(raw) <= 4 * 1024 * 1024, 'Native configuration file exceeds the read bound')
    return flatten(json_config(raw))


def process_arguments(argv, cwd):
    """Only interpret the application arguments, never dotnet runtime switches."""
    index = next((i for i, value in enumerate(argv)
                  if (cwd / value).resolve() in (SERVICE_DLL, SERVICE_DLL.with_suffix(''))), None)
    require(index is not None, 'The running unit does not target the reviewed ImapSync application')
    args, values, index = argv[index + 1:], {}, 0
    while index < len(args):
        key = args[index]
        require(key.startswith('--'), 'Unsupported native command-line configuration form')
        key = key[2:]
        if '=' in key:
            key, value = key.split('=', 1)
        else:
            index += 1
            require(index < len(args), 'Native command-line configuration value is absent')
            value = args[index]
        require(bool(key), 'Native command-line configuration key is empty')
        values[key.replace('__', ':').casefold()] = value
        index += 1
    return values


def effective_config(cwd, environment, command_line):
    env = {key.replace('__', ':').casefold(): value for key, value in environment.items()}
    host_environment = environment.get('DOTNET_ENVIRONMENT') or environment.get('ASPNETCORE_ENVIRONMENT') or 'Production'
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', host_environment), 'Unsupported native host environment name')
    initial = {'environment': host_environment}
    initial.update(config_file(cwd / 'appsettings.json'))
    initial.update(config_file(cwd / ('appsettings.' + host_environment + '.json')))
    initial.update(env)
    initial.update(command_line)
    path = initial.get('pathtoconf')
    require(isinstance(path, str) and bool(path), 'Native pathToConf is absent')
    directory = (cwd / path.replace('\\', '/')).resolve()
    require(directory == CONFIG_DIR, 'Native configuration directory differs from this reviewed deployment')
    name = str(initial.get('environment', 'Production'))
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name), 'Unsupported native configuration environment')
    merged = dict(initial)
    # Exact order used by MailHostExtensions.AddMailJsonFiles.
    for base in ('appsettings', 'storage', 'mail', 'elastic'):
        merged.update(config_file(directory / (base + '.json'), required=True))
        merged.update(config_file(directory / (base + '.' + name + '.json')))
    merged.update(env)
    merged.update(command_line)
    return merged, name


def truth(value):
    require(str(value).casefold() in ('true', 'false'), 'Unexpected native boolean setting')
    return str(value).casefold() == 'true'


def redis_settings(config):
    prefix = 'mail:imapsync:redis:'
    settings = {key[len(prefix):]: value for key, value in config.items() if key.startswith(prefix)}
    require(settings, 'Native ImapSync Redis settings are absent')
    require(not settings.get('connectionstring'), 'Redis connection-string mode requires separate review')
    require(not settings.get('servicename') and not truth(settings.get('issentinelcluster', False)),
            'Sentinel mode requires separate review')
    require(not settings.get('keyprefix'), 'Redis key-prefix mode requires separate review')
    indices = {key.split(':')[1] for key in settings if key.startswith('hosts:')}
    require(indices == {'0'}, 'Exactly one native Redis endpoint is required')
    host = settings.get('hosts:0:host')
    require(isinstance(host, str) and re.fullmatch(r'[A-Za-z0-9_.:\-]{1,253}', host), 'Invalid native Redis endpoint')
    try:
        port = int(settings.get('hosts:0:port', 6379))
    except (TypeError, ValueError):
        raise Stop('Invalid native Redis port') from None
    require(1 <= port <= 65535, 'Invalid native Redis port')
    password, user = settings.get('password') or '', settings.get('user') or ''
    require(isinstance(password, str) and isinstance(user, str), 'Unsupported native Redis credential format')
    return {'host': host, 'port': port, 'tls': truth(settings.get('ssl', False)),
            'password': password, 'user': user}


def native_context():
    def systemctl(*args):
        result = subprocess.run(['systemctl', *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5)
        require(result.returncode == 0, 'Native ImapSync service status check failed')
        return result.stdout.decode().strip()
    require(systemctl('is-active', SERVICE) == 'active', 'Native ImapSync service is not active')
    pid = int(systemctl('show', SERVICE, '--property=MainPID', '--value'))
    require(pid > 0, 'Native ImapSync PID is absent')
    require(hashlib.sha256(SERVICE_DLL.read_bytes()).hexdigest() == SERVICE_HASH,
            'Native ImapSync DLL is not the reviewed v3 artifact')
    proc = pathlib.Path('/proc') / str(pid)
    cwd = (proc / 'cwd').resolve()
    require(cwd == SERVICE_DIR, 'Native service working directory differs from the reviewed deployment')
    raw_env = (proc / 'environ').read_bytes()
    require(len(raw_env) <= 1024 * 1024, 'Process environment exceeds the read bound')
    environment = dict(item.decode().split('=', 1) for item in raw_env.split(b'\0') if b'=' in item)
    argv = [item.decode() for item in (proc / 'cmdline').read_bytes().split(b'\0') if item]
    arguments = process_arguments(argv, cwd)
    config, name = effective_config(cwd, environment, arguments)
    # Reject a restart between reads; a new invocation can inspect the new process.
    require(systemctl('show', SERVICE, '--property=MainPID', '--value') == str(pid),
            'Native service restarted during configuration inspection')
    return redis_settings(config), {'service_pid': pid, 'environment': name,
                                    'configuration_directory': str(CONFIG_DIR)}


class Redis:
    def __init__(self, settings):
        connection = socket.create_connection((settings['host'], settings['port']), timeout=7)
        if settings['tls']:
            connection = ssl.create_default_context().wrap_socket(connection, server_hostname=settings['host'])
        self.connection = connection
        self.stream = connection.makefile('rb')
        if settings['password'] or settings['user']:
            auth = ['AUTH'] + ([settings['user']] if settings['user'] else []) + [settings['password']]
            require(self.command(*auth) == b'OK', 'Native Redis authentication failed')

    def _read(self, depth=0):
        require(depth <= 3, 'Unexpected Redis reply nesting')
        line = self.stream.readline(8193)
        require(len(line) <= 8192 and line.endswith(b'\r\n'), 'Unexpected Redis reply framing')
        kind, value = line[:1], line[1:-2]
        if kind == b'+':
            return value
        if kind == b'-':
            # A server error may echo command arguments; never print its text.
            raise Stop('Redis rejected the bounded maintenance request')
        if kind == b':':
            return int(value)
        if kind == b'$':
            length = int(value)
            require(0 <= length <= 65536, 'Unexpected Redis bulk reply size')
            data = self.stream.read(length + 2)
            require(len(data) == length + 2 and data.endswith(b'\r\n'), 'Incomplete Redis bulk reply')
            return data[:-2]
        if kind == b'*':
            count = int(value)
            require(0 <= count <= 16, 'Unexpected Redis array reply size')
            return [self._read(depth + 1) for _ in range(count)]
        raise Stop('Unexpected Redis reply type')

    def command(self, *parts):
        require(parts[0] in ('AUTH', 'PING', 'PUBSUB', 'PUBLISH'), 'Unsupported Redis maintenance command')
        encoded = [str(part).encode('utf-8') for part in parts]
        wire = ('*' + str(len(encoded)) + '\r\n').encode()
        wire += b''.join(('$' + str(len(part)) + '\r\n').encode() + part + b'\r\n' for part in encoded)
        self.connection.sendall(wire)
        return self._read()

    def close(self):
        self.stream.close()
        self.connection.close()


def activity_payload(user_guid):
    user = uuid.UUID(user_guid)
    require(user.int != 0, 'The user GUID must identify a verified account')
    return json.dumps({'Object': {'UserName': str(user), 'Tenant': 1,
                                  'MailBoxId': 0, 'Folder': -1, 'Tags': None}, 'Action': 1},
                      separators=(',', ':'))


def request(settings, user_guid, publish, client_factory=Redis):
    client = client_factory(settings)
    try:
        require(client.command('PING') == b'PONG', 'Native Redis PING failed')
        subscribers = client.command('PUBSUB', 'NUMSUB', CHANNEL)
        require(isinstance(subscribers, list) and len(subscribers) == 2
                and subscribers[0] == CHANNEL.encode() and type(subscribers[1]) is int
                and subscribers[1] >= 1, 'No subscriber for the exact native ImapSync activity channel')
        result = {'subscribers_before': subscribers[1], 'published': False,
                  'channel': CHANNEL, 'tracking_ready': False}
        if publish:
            # Exactly one ordinary alive notification. No queue writes, mail
            # actions, session creation or automatic publish retries occur.
            try:
                count = client.command('PUBLISH', CHANNEL, activity_payload(user_guid))
            except Exception:
                raise Stop('Activity publication outcome is unknown; do not retry blindly') from None
            require(type(count) is int and count >= 1, 'Activity publication was not acknowledged by a subscriber; do not retry blindly')
            result.update(published=True, subscribers_notified=count)
        return result
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user-guid', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    user = str(uuid.UUID(args.user_guid))
    settings, metadata = native_context()
    metadata.update(redis_host=settings['host'], redis_port=settings['port'], redis_tls=settings['tls'],
                    redis_auth_configured=bool(settings['password'] or settings['user']),
                    user_guid_sha256=hashlib.sha256(user.encode()).hexdigest())
    print(json.dumps({'phase': 'native_configuration_verified', **metadata}, sort_keys=True), flush=True)
    result = request(settings, user, args.publish)
    print(json.dumps({'phase': 'activity_requested' if args.publish else 'read_only_probe', **result}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'phase': 'stopped', 'error_type': type(exc).__name__,
                          'reason': str(exc) if isinstance(exc, Stop) else 'Native maintenance check failed; inspect privately',
                          'automatic_retry': False}, sort_keys=True), flush=True)
        raise SystemExit(1)
