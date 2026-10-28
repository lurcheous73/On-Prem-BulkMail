#!/usr/bin/env python3
"""Independent issuer/publisher regressions using ephemeral keys and no network.

Run: python -B integrations/certificate-renewal/tests/test_independent_issuer_review.py
Requires cryptography for generating synthetic dated certificates.
"""
import contextlib
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import issuer
import public_server
import renewal_common as common


def main():
    checks = []

    def check(name, value):
        assert value, name
        checks.append(name)
        print("PASS", name)

    with tempfile.TemporaryDirectory(prefix="renewal-independent-review-") as directory:
        root = Path(directory)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        day = dt.timedelta(days=1)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local review fixture CA")])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - 400 * day).not_valid_after(now + 400 * day)
              .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
              .sign(ca_key, hashes.SHA256()))

        def pem(certificate):
            return certificate.public_bytes(serialization.Encoding.PEM)

        ca_path = root / "fixture-ca.pem"
        ca_path.write_bytes(pem(ca))
        host = "mx1.the-grange.uk"

        def leaf(start, end):
            certificate = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(ca_key, hashes.SHA256()))
            return pem(certificate) + pem(ca)

        old_raw = leaf(now - 28 * day, now + 62 * day)
        new_raw = leaf(now, now + 64 * day)
        spki = hashlib.sha256(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

        def validate(data, sans, pin):
            return common.validate_bundle(data, sans, pin, now=now.timestamp(), ca_file=ca_path)

        old = validate(old_raw, [host], spki)
        new = validate(new_raw, [host], spki)
        check("90 to 64 day transition accepts a two-day expiry advance",
              common.replacement_is_newer(old, new)
              and new["not_after"] - old["not_after"] == 2 * common.DAY)
        for label, end in [("same expiry", now + 62 * day), ("older expiry", now + 61 * day)]:
            candidate = validate(leaf(now, end), [host], spki)
            try:
                common.replacement_is_newer(old, candidate)
            except common.RenewalError:
                rejected = True
            else:
                rejected = False
            check("Transition still rejects " + label, rejected)
        try:
            validate(leaf(now + day, now + 65 * day), [host], spki)
        except common.RenewalError:
            rejected = True
        else:
            rejected = False
        check("Transition still rejects a future notBefore", rejected)
        config = {"public_dir": str(root / "public"), "state_dir": str(root / "state"),
                  "hosts": {host: {"sans": [host], "spki_sha256": spki}}}
        item = config["hosts"][host]
        attempt = root / "state" / "attempts" / host / "previous"
        attempt.mkdir(parents=True)
        state = {"attempt_directory": str(attempt)}
        with mock.patch.object(issuer, "validate_bundle", side_effect=validate), contextlib.redirect_stdout(io.StringIO()):
            for label, raw in [("malformed", b"not a certificate"),
                               ("expired", leaf(now - 90 * day, now - day)),
                               ("stale", leaf(now - 40 * day, now + 50 * day))]:
                (attempt / "fullchain.pem").write_bytes(raw)
                assert issuer.recover_bundle(config, host, item, state, old) is None, label
            (attempt / "fullchain.pem").write_bytes(new_raw)
            assert issuer.recover_bundle(config, host, item, state, old)["sha256"] == new["sha256"]
        check("Malformed, expired and older retained attempts permit retry; valid new output recovers", True)
        try:
            issuer.recover_bundle(config, host, item, {"attempt_directory": str(root / "outside")}, old)
        except common.RenewalError:
            blocked = True
        else:
            blocked = False
        check("Attempt paths outside the private per-host root remain blocked", blocked)

        log = root / "issuance.log"
        log.write_text("retry after 2026-10-28 12:00:00-05:00\nretry after 2026-10-28 18:00:00+02:00\n")
        check("Retry-After respects offsets and selects the latest real UTC instant",
              issuer.parse_retry_after(log) == dt.datetime(2026, 10, 28, 17, tzinfo=dt.timezone.utc).timestamp())
        log.write_text("retry after 2026-10-28 12:00:00 UTC\n")
        check("Retry-After accepts the native UTC suffix",
              issuer.parse_retry_after(log) == dt.datetime(2026, 10, 28, 12, tzinfo=dt.timezone.utc).timestamp())
        log.write_text("retry after 2026-13-99 12:00:00Z\n")
        check("Invalid Retry-After dates use normal bounded backoff", issuer.parse_retry_after(log) is None)

        # Exercise real orchestration with only ACME issuance replaced by a local fixture.
        issuer.publish(config, host, old, old["not_before"])
        state_path = root / "state" / "issuance" / (host + ".json")
        (attempt / "fullchain.pem").write_bytes(b"incomplete")
        common.atomic_json(state_path, {"schema": 1, "certificate_sha256": old["sha256"],
            "last_successful_issuance_at": old["not_before"], "attempt_directory": str(attempt),
            "failures": 1, "next_attempt_at": 0})
        calls = []

        def order(cfg, hostname, enrollment, output, staging):
            calls.append(hostname)
            (output / "fullchain.pem").write_bytes(new_raw)
            return 0

        with mock.patch.object(issuer, "validate_bundle", side_effect=validate), \
                mock.patch.object(issuer, "run_certbot", side_effect=order), \
                contextlib.redirect_stdout(io.StringIO()):
            issuer.process_host(config, host, apply=True, retry_only=True)
        check("Incomplete prior output reaches one eligible order and validated publication",
              calls == [host] and json.loads(state_path.read_text())["phase"] == "issued_and_published"
              and issuer.published(config, host, item)["sha256"] == new["sha256"])

        challenge_host = "mx1.brimstonecottage.uk"
        token = "a" * 32
        challenge_root = root / "challenge"
        challenge_path = challenge_root / challenge_host / ".well-known" / "acme-challenge"
        challenge_path.mkdir(parents=True)
        (challenge_path / token).write_bytes(b"token.public-key-thumbprint")
        handler = public_server.make_handler({"hosts": [challenge_host], "allowed_sources": ["127.0.0.1"],
            "http_challenge_hosts": [challenge_host], "challenge_dir": str(challenge_root),
            "public_dir": str(root / "public")})

        def response(host_header, source="127.0.0.1", method="GET"):
            obj = handler.__new__(handler)
            obj.client_address = (source, 12345)
            obj.path = "/.well-known/acme-challenge/" + token
            obj.headers = {"Host": host_header}
            obj.wfile = io.BytesIO()
            statuses = []
            obj.send_response = statuses.append
            obj.send_header = lambda *args: None
            obj.end_headers = lambda: None
            with contextlib.redirect_stdout(io.StringIO()):
                obj.respond(method == "GET")
            return statuses[0], obj.wfile.getvalue()

        check("Standard HTTP-01 dispatch requires the exact approved Host",
              response(challenge_host) == (200, b"token.public-key-thumbprint")
              and response("other.example.invalid")[0] == 404)
        check("Standard HTTP-01 rejects unapproved sources even with a valid Host",
              response(challenge_host, "127.0.0.2")[0] == 403)
        check("HEAD exposes no challenge payload body", response(challenge_host, method="HEAD") == (200, b""))
        (challenge_path / token).unlink()
        (challenge_path / token).symlink_to(ca_path)
        check("Standard HTTP-01 rejects symlinked challenge files", response(challenge_host)[0] == 404)
    print(f"PASS {len(checks)} independent issuer/publisher checks; synthetic keys and no network.")


if __name__ == "__main__":
    main()
