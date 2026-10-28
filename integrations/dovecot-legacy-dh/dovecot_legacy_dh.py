#!/usr/bin/env python3
"""Inspect Dovecot 2.1.17 public DH parameters or build a separate candidate.

This does not install files, change configuration, signal services, generate a
private key, or connect to a server. The legacy selectors are dispatch slots,
not a validated measure of the DER prime size. Both retain their native names
while receiving the same verified RFC7919 ffdhe3072 public parameters.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

MAX_NATIVE_BYTES = 1024
FFDHE3072_DER_SHA256 = 'e6c929eaf5be4558cbe49edc31017c7f646723bdc006270bed368afde14acb14'


class ParameterError(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise ParameterError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tlv(data, offset, wanted):
    require(offset + 2 <= len(data) and data[offset] == wanted, 'invalid DER tag or truncated header')
    length = data[offset + 1]
    offset += 2
    if length & 128:
        width = length & 127
        require(1 <= width <= 2 and offset + width <= len(data), 'invalid DER length')
        raw = data[offset:offset + width]
        require(raw[0] != 0, 'noncanonical DER length')
        length = int.from_bytes(raw, 'big')
        require(length >= 128, 'noncanonical DER short length')
        offset += width
    require(offset + length <= len(data), 'truncated DER value')
    return data[offset:offset + length], offset + length


def dh_values(der):
    sequence, end = tlv(der, 0, 0x30)
    require(end == len(der), 'trailing bytes after DH DER')
    numbers = []
    offset = 0
    while offset < len(sequence):
        raw, offset = tlv(sequence, offset, 0x02)
        require(raw and not raw[0] & 128, 'DH integer must be positive')
        require(len(raw) == 1 or raw[0] != 0 or raw[1] & 128, 'noncanonical DH integer')
        numbers.append(int.from_bytes(raw, 'big'))
        require(len(numbers) <= 3, 'unexpected DH integer count')
    require(len(numbers) in (2, 3) and numbers[0] > 0 and numbers[1] in (2, 5),
            'unexpected DH parameters')
    return {'bits': numbers[0].bit_length(), 'generator': numbers[1]}


def parse_native(raw):
    require(0 < len(raw) <= MAX_NATIVE_BYTES, 'native DH file is empty or exceeds 1024-byte cap')
    records = []
    offset = 0
    while True:
        require(offset + 4 <= len(raw), 'missing native DH terminator')
        slot = struct.unpack_from('<i', raw, offset)[0]
        offset += 4
        if slot == 0:
            require(offset == len(raw), 'trailing native DH bytes')
            break
        require(slot in (512, 1024), 'unsupported native DH selector')
        require(offset + 4 <= len(raw), 'truncated native DH length')
        length = struct.unpack_from('<i', raw, offset)[0]
        offset += 4
        require(0 < length <= MAX_NATIVE_BYTES and offset + length <= len(raw), 'invalid native DH record length')
        der = raw[offset:offset + length]
        offset += length
        values = dh_values(der)
        records.append({'selector': slot, 'der': der, **values})
    require([record['selector'] for record in records] == [512, 1024],
            'native DH record sequence differs from inspected version')
    return records


def public_summary(raw):
    records = parse_native(raw)
    return {'sha256': digest(raw), 'size': len(raw), 'byte_order': 'little',
            'records': [{'selector': record['selector'], 'actual_prime_bits': record['bits'],
                         'generator': record['generator'], 'der_sha256': digest(record['der'])}
                        for record in records]}


def validate_strong_der(der):
    require(digest(der) == FFDHE3072_DER_SHA256, 'public DH group differs from pinned RFC7919 ffdhe3072')
    values = dh_values(der)
    require(values == {'bits': 3072, 'generator': 2}, 'unexpected strong DH prime or generator')
    try:
        result = subprocess.run(['openssl', 'dhparam', '-inform', 'DER', '-check', '-noout'],
                                input=der, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ParameterError('OpenSSL DH validation could not complete') from None
    require(result.returncode == 0, 'OpenSSL rejected strong DH parameters')


def build(original, expected_original_sha256, strong_der):
    require(digest(original) == expected_original_sha256, 'original public DH file hash changed')
    parse_native(original)
    validate_strong_der(strong_der)
    result = b''.join(struct.pack('<ii', slot, len(strong_der)) + strong_der
                      for slot in (512, 1024)) + struct.pack('<i', 0)
    require(len(result) <= MAX_NATIVE_BYTES, 'candidate exceeds native size limit')
    require(all(record['bits'] == 3072 for record in parse_native(result)), 'candidate validation failed')
    return result


def write_new_candidate(path, data):
    # Exclusive creation cannot overwrite an installed file or an old review
    # artifact. Installation and restart belong to a separate guarded step.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect')
    inspect.add_argument('--file', required=True)
    create = commands.add_parser('build')
    create.add_argument('--original', required=True)
    create.add_argument('--expected-original-sha256', required=True)
    create.add_argument('--der', required=True)
    create.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        require(sys.byteorder == 'little' and struct.calcsize('@i') == 4,
                'runtime ABI differs from inspected little-endian 32-bit native integers')
        if args.command == 'inspect':
            result = {'event': 'public_parameters_inspected', **public_summary(Path(args.file).read_bytes())}
        else:
            source = Path(args.original)
            original = source.read_bytes()
            candidate = build(original, args.expected_original_sha256, Path(args.der).read_bytes())
            require(source.read_bytes() == original, 'original public parameters changed during build')
            write_new_candidate(args.output, candidate)
            result = {'event': 'separate_candidate_built', 'original_sha256': digest(original),
                      **public_summary(candidate)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ParameterError):
        print(json.dumps({'event': 'failed', 'reason': 'public parameter validation or exclusive candidate creation failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
