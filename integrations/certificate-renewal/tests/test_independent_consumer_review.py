#!/usr/bin/env python3
"""Independent local transaction regressions; service/network boundaries are mocked."""
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mx_consumer as consumer
from renewal_common import RenewalError


class ConsumerReview(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mx-independent-review-")
        self.root = Path(self.temporary.name)
        self.xeams = self.root / "xeams"
        self.files = {"pfx": self.xeams / "config/letenc.pfx",
                      "chain": self.xeams / "letsEncrypt/domain-chain.crt",
                      "dates": self.xeams / "letsEncrypt/properties.dat"}
        self.original = {"pfx": b"synthetic-original-pfx", "chain": b"synthetic-original-chain",
                         "dates": b"expDate=1\nnotAfter=1\nnotBefore=1\nregDate=1\nrenewalAfter=1\n"}
        for name, path in self.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.original[name])
            path.chmod(0o644 if name == "chain" else 0o600)
        self.key, self.csr, self.xml = (self.xeams / "letsEncrypt/domain.key",
                                       self.xeams / "letsEncrypt/domain.csr", self.xeams / "config/AppConfig.xml")
        self.key.write_bytes(b"synthetic-private-key-placeholder")
        self.csr.write_bytes(b"synthetic-csr-placeholder")
        self.xml.write_text("<config><sslCertificateFileName>config/letenc.pfx</sslCertificateFileName>"
                            "<sslCertificatePassword encrypted='false'>synthetic-local-password</sslCertificatePassword>"
                            "<sslCertKeystoreType>PKCS12</sslCertKeystoreType></config>")
        self.patches = contextlib.ExitStack()
        self.patches.enter_context(mock.patch.multiple(consumer, ROOT=self.xeams, FILES=self.files,
            KEY=self.key, CSR=self.csr, CONFIG=self.xml, PENDING=self.xeams / "config/letenc.pfx.new"))
        self.events = []
        self.patches.enter_context(mock.patch.object(consumer, "stop_service", side_effect=lambda: self.events.append("stop")))
        self.patches.enter_context(mock.patch.object(consumer, "start_service", side_effect=lambda: self.events.append("start")))
        self.patches.enter_context(mock.patch.object(consumer, "verify_peers", side_effect=lambda h, fp, *a, **k: self.events.append(("verify", fp))))
        self.patches.enter_context(mock.patch.object(consumer, "pair_healthy", side_effect=lambda h: self.events.append("paired_health")))
        self.patches.enter_context(mock.patch.object(consumer, "in_install_window", return_value=True))
        self.patches.enter_context(mock.patch.object(consumer, "emit"))
        self.config = {"hostname": "mx1.the-grange.uk", "state_dir": str(self.root / "state"),
                       "backup_dir": str(self.root / "backup")}
        now = time.time()
        self.old = {"sans": ("mx1.the-grange.uk",), "spki_sha256": "a" * 64, "sha256": "b" * 64,
                    "not_before": now - 28 * 86400, "not_after": now + 62 * 86400}
        self.new = {**self.old, "sha256": "c" * 64, "not_before": now, "not_after": now + 64 * 86400,
                    "fullchain_pem": b"synthetic-new-chain"}
        self.preflight = consumer.preflight_guard()
        self.staging = self.root / "staging"
        self.staging.mkdir()
        (self.staging / "replacement.pfx").write_bytes(b"synthetic-new-pfx")

    def tearDown(self):
        self.patches.close()
        self.temporary.cleanup()

    def saved_transaction(self):
        return json.loads((Path(self.config["state_dir"]) / "transaction.json").read_text())

    def install(self):
        consumer.install(self.config, self.old, self.new, self.staging, self.preflight)

    def pending(self, original=False):
        self.install()
        manifest = self.saved_transaction()
        manifest["phase"] = "stopped" if original else "files_installed"
        if original:
            for name, path in self.files.items():
                path.write_bytes(self.original[name])
        consumer.transaction_state(self.config, manifest)
        self.events.clear()
        return manifest

    def test_success_preserves_key_settings_owners_and_backups(self):
        self.install()
        manifest = self.saved_transaction()
        self.assertEqual(manifest["phase"], "committed")
        self.assertEqual(self.events, ["paired_health", ("verify", self.old["sha256"]),
            "paired_health", "stop", "start", ("verify", self.new["sha256"])])
        consumer.verify_identity_guard(manifest)
        for name, path in self.files.items():
            actual = consumer.snapshot(path)
            self.assertEqual(actual["sha256"], manifest["replacement_hashes"][name])
            for field in ("mode", "uid", "gid"):
                self.assertEqual(actual[field], self.preflight["files"][name][field])
            self.assertEqual((Path(manifest["backup"]) / (name + ".backup")).read_bytes(), self.original[name])

    def test_failed_new_certificate_verification_restores_all_original_files(self):
        def verify(host, fingerprint, *args, **kwargs):
            self.events.append(("verify", fingerprint))
            if fingerprint == self.new["sha256"]:
                raise RenewalError("synthetic failed post-install verification")
        with mock.patch.object(consumer, "verify_peers", side_effect=verify):
            with self.assertRaises(RenewalError):
                self.install()
        self.assertEqual(self.saved_transaction()["phase"], "rolled_back")
        self.assertEqual(self.events.count("stop"), 2)
        self.assertEqual(self.events.count("start"), 2)
        self.assertEqual(self.events[-1], ("verify", self.old["sha256"]))
        for name, path in self.files.items():
            self.assertEqual(path.read_bytes(), self.original[name])
            self.assertEqual(consumer.snapshot(path), self.preflight["files"][name])

    def test_unchanged_originals_restart_immediately_outside_window(self):
        self.pending(original=True)
        with mock.patch.object(consumer, "in_install_window", return_value=False), \
                mock.patch.object(consumer, "pair_healthy", side_effect=AssertionError("unnecessary paired gate")):
            consumer.recover_transaction(self.config, apply=True)
        self.assertEqual(self.events, ["start", ("verify", self.old["sha256"])])
        self.assertEqual(self.saved_transaction()["phase"], "aborted_before_replace")
        for name, path in self.files.items():
            self.assertEqual(consumer.snapshot(path), self.preflight["files"][name])

    def test_dry_run_never_starts_or_writes_interrupted_originals(self):
        self.pending(original=True)
        journal = (Path(self.config["state_dir"]) / "transaction.json").read_bytes()
        with self.assertRaises(RenewalError):
            consumer.recover_transaction(self.config, apply=False)
        self.assertEqual(self.events, [])
        self.assertEqual((Path(self.config["state_dir"]) / "transaction.json").read_bytes(), journal)

    def test_healthy_completed_bytes_are_adopted_without_restart(self):
        self.pending()
        consumer.recover_transaction(self.config, apply=True)
        self.assertEqual(self.events, [("verify", self.new["sha256"])])
        self.assertEqual(self.saved_transaction()["phase"], "committed")

    def test_partial_replacement_cannot_restart_outside_its_window(self):
        self.pending()
        self.files["pfx"].write_bytes(self.original["pfx"])
        before = {name: consumer.snapshot(path) for name, path in self.files.items()}
        with mock.patch.object(consumer, "in_install_window", return_value=False):
            with self.assertRaises(RenewalError):
                consumer.recover_transaction(self.config, apply=True)
        self.assertEqual(self.events, [])
        self.assertEqual({name: consumer.snapshot(path) for name, path in self.files.items()}, before)

    def test_partial_replacement_cannot_restart_with_unhealthy_pair(self):
        self.pending()
        self.files["pfx"].write_bytes(self.original["pfx"])
        before = {name: consumer.snapshot(path) for name, path in self.files.items()}
        with mock.patch.object(consumer, "pair_healthy", side_effect=RenewalError("synthetic paired MX unavailable")):
            with self.assertRaises(RenewalError):
                consumer.recover_transaction(self.config, apply=True)
        self.assertEqual(self.events, [])
        self.assertEqual({name: consumer.snapshot(path) for name, path in self.files.items()}, before)

    def test_corrupt_last_backup_cannot_stop_or_partially_restore(self):
        manifest = self.pending()
        backup = Path(manifest["backup"])
        (backup / "dates.backup").write_bytes(b"synthetic-corrupt-last-backup")
        snapshots = {name: consumer.snapshot(path) for name, path in self.files.items()}
        with self.assertRaises(RenewalError):
            consumer.rollback(self.config, backup, manifest)
        self.assertEqual(self.events, [])
        self.assertEqual({name: consumer.snapshot(path) for name, path in self.files.items()}, snapshots)

    def test_third_party_write_during_rollback_shutdown_is_preserved(self):
        manifest = self.pending()
        before = {name: path.read_bytes() for name, path in self.files.items()}

        def stop_with_other_write():
            self.events.append("stop")
            self.files["chain"].write_bytes(b"synthetic-third-party-chain")

        with mock.patch.object(consumer, "stop_service", side_effect=stop_with_other_write):
            with self.assertRaises(RenewalError):
                consumer.rollback(self.config, Path(manifest["backup"]), manifest)
        self.assertEqual(self.events, ["stop", "start"])
        self.assertEqual(self.files["chain"].read_bytes(), b"synthetic-third-party-chain")
        for name in ("pfx", "dates"):
            self.assertEqual(self.files[name].read_bytes(), before[name])

    def test_third_party_write_during_initial_shutdown_aborts_before_replacement(self):
        def stop_with_other_write():
            self.events.append("stop")
            self.files["dates"].write_bytes(b"synthetic-third-party-dates")

        with mock.patch.object(consumer, "stop_service", side_effect=stop_with_other_write):
            with self.assertRaises(RenewalError):
                self.install()
        self.assertEqual(self.saved_transaction()["phase"], "aborted_before_replace")
        self.assertEqual(self.events[-2:], ["stop", "start"])
        self.assertEqual(self.files["dates"].read_bytes(), b"synthetic-third-party-dates")
        for name in ("pfx", "chain"):
            self.assertEqual(self.files[name].read_bytes(), self.original[name])


if __name__ == "__main__":
    unittest.main(verbosity=2)
