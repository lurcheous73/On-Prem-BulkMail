#!/usr/bin/env python3
"""Extend the existing Jitsi request/referrer redaction for portal callbacks."""
import argparse
from pathlib import Path


def render(source):
    old = b"(?:jwt|token)="
    new = b"(?:jwt|token|code|state|code_challenge)="
    if source.count(old) != 2 or b"log_format jitsi_log" not in source:
        raise ValueError("Expected the reviewed request and referrer log redaction rules")
    return source.replace(old, new)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("Write a reviewable copy instead of replacing live configuration")
    with args.output.open("xb") as output:
        output.write(render(args.source.read_bytes()))
    print("Log redaction copy prepared; routing and services remain unchanged.")
