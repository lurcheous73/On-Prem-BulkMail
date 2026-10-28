#!/usr/bin/env python3
"""Exercise the existing-install upgrader in disposable filesystem roots only."""
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import sqlite3
import stat
import subprocess
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
RELEASE = REPO
UPGRADE = REPO / "deployment/upgrade-messaging.sh"
MIGRATE = REPO / "deployment/migrate-integrations.php"
BASELINE = subprocess.check_output(["git", "show", "35e973d85c884c64dbaeb8eae9d4d92fef328bfb:app/index.php"], cwd=REPO)
assert hashlib.sha256(BASELINE).hexdigest() == "7602fd20458f8c8ab61b0c3ec9b36fbec97bb311d0a594d15cf032224e1b501e"
passed = []


def check(name, value):
    if not value:
        raise AssertionError(name)
    passed.append(name)
    print("PASS", name, flush=True)


def users(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT * FROM users ORDER BY id").fetchall()


def fixture(path):
    app = path / "var/www/bulkmail"
    data = path / "var/lib/bulkmail"
    app.mkdir(parents=True)
    data.mkdir(parents=True)
    (app / "index.php").write_bytes(BASELINE)
    (app / "existing-asset.txt").write_text("Keep the live app assets")
    worker = path / "usr/local/sbin/bulkmail-worker.php"
    worker.parent.mkdir(parents=True)
    worker.write_text("<?php // Existing email delivery worker must stay untouched.\n")
    password_hash = subprocess.check_output(["php", "-r", "echo password_hash('synthetic-only', PASSWORD_DEFAULT);"]).decode()
    db_path = data / "bulkmail.sqlite"
    with sqlite3.connect(db_path) as db:
        db.executescript((RELEASE / "database/schema.sql").read_text())
        db.execute("INSERT INTO users(id,username,password_hash,display_name,email,organisation,is_admin,active) VALUES(2,'Peter',?,'Peter Arnold','peter@example.invalid','Derby Masonic Hall Ltd.',1,1)", [password_hash])
        db.execute("INSERT INTO contacts(owner_user_id,name,email) VALUES(2,'Preserved contact','contact@example.invalid')")
    return app, db_path, worker


def run_upgrade(root, env=None):
    result = subprocess.run(["bash", str(UPGRADE), "--root-prefix", str(root), "--source-dir", str(RELEASE)], cwd=REPO, env=env, text=True, capture_output=True)
    return result


if os.geteuid() != 0:
    raise SystemExit("This isolated-root test requires root to verify production ownership and permission settings.")

with tempfile.TemporaryDirectory(prefix="bulkmail-upgrade-") as temp:
    base = pathlib.Path(temp)
    # Keep a single immutable release throughout this test even while collaborators
    # are editing the working tree; never inherit an operator source-dir override.
    RELEASE = base / "release"
    RELEASE.mkdir()
    for directory in ["app", "worker", "systemd", "deployment", "database"]:
        shutil.copytree(REPO / directory, RELEASE / directory)
    UPGRADE = RELEASE / "deployment/upgrade-messaging.sh"
    MIGRATE = RELEASE / "deployment/migrate-integrations.php"
    refused_root = subprocess.run(["bash", str(UPGRADE), "--root-prefix", "/tmp/.."], text=True, capture_output=True)
    check("Isolated root cannot resolve back to the real filesystem root", refused_root.returncode != 0 and "must not resolve to /" in refused_root.stderr)
    sandbox = base / "successful"
    app, db_path, email_worker = fixture(sandbox)
    original_users = users(db_path)
    original_worker = email_worker.read_bytes()
    marker = base / "unexpected-systemctl-call"
    fake_bin = base / "no-services-bin"
    fake_bin.mkdir()
    fake_systemctl = fake_bin / "systemctl"
    fake_systemctl.write_text("#!/bin/sh\nprintf invoked > '" + str(marker) + "'\nexit 99\n")
    fake_systemctl.chmod(0o755)
    environment = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"])
    result = run_upgrade(sandbox, environment)
    if result.returncode:
        print(result.stdout, result.stderr)
    check("Existing-install upgrade succeeds in isolated root", result.returncode == 0)
    check("Peter's complete row, password hash and admin role remain identical", users(db_path) == original_users)
    check("Entry point switches to the incoming release", (app / "index.php").read_bytes() == (RELEASE / "app/index.php").read_bytes())
    check("Existing assets and email worker are preserved", (app / "existing-asset.txt").read_text() == "Keep the live app assets" and email_worker.read_bytes() == original_worker)
    check("Isolated root never invokes real service actions", not marker.exists())
    backups = list((sandbox / "var/backups/bulkmail").glob("messaging-*"))
    check("A timestamped private backup was created", len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o700)
    backup = backups[0]
    check("SQLite online backup contains original user rows", users(backup / "bulkmail.sqlite") == original_users and stat.S_IMODE((backup / "bulkmail.sqlite").stat().st_mode) == 0o600)
    check("Old entry point is available for code-only rollback", (backup / "files/var/www/bulkmail/index.php").read_bytes() == BASELINE)
    config = sandbox / "etc/bulkmail/integrations.php"
    check("New private config has restricted permissions", stat.S_IMODE(config.stat().st_mode) == 0o640 and config.stat().st_uid == 0)
    enabled = json.loads(subprocess.check_output(["php", "-r", "$c=require $argv[1]; echo json_encode(array_map(fn($v)=>$v['enabled'],$c));", str(config)]))
    check("All optional integrations start disabled", enabled == {"identity": False, "sms": False, "whatsapp": False})
    config.write_text(config.read_text() + "\n// Preserved operator configuration marker.\n")
    configured_bytes = config.read_bytes()
    result = run_upgrade(sandbox, environment)
    if result.returncode or users(db_path) != original_users:
        print("Repeat-upgrade diagnostic: returncode=", result.returncode,
              "users_unchanged=", users(db_path) == original_users, flush=True)
        print(result.stdout, result.stderr, flush=True)
    check("Repeating the same release is safe and idempotent", result.returncode == 0 and users(db_path) == original_users)
    check("An existing integration configuration is never overwritten", config.read_bytes() == configured_bytes)
    with sqlite3.connect(db_path) as db:
        check("Additive tables exist and no channels are granted implicitly", db.execute("SELECT COUNT(*) FROM message_channel_access").fetchone()[0] == 0 and db.execute("SELECT COUNT(*) FROM user_identity_links").fetchone()[0] == 0)
        check("Preserved address book and database references remain consistent", db.execute("SELECT owner_user_id FROM contacts").fetchone()[0] == 2 and db.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and not db.execute("PRAGMA foreign_key_check").fetchall())

    guarded = base / "unknown-code"
    guarded_app, guarded_db, _ = fixture(guarded)
    guarded_app.joinpath("index.php").write_bytes(BASELINE + b"\n// Unreviewed local change.\n")
    unknown_code = guarded_app.joinpath("index.php").read_bytes()
    guarded_users = users(guarded_db)
    result = run_upgrade(guarded, environment)
    check("Unknown live index hash refuses upgrade before replacement", result.returncode != 0 and "reviewed baseline" in result.stderr and guarded_app.joinpath("index.php").read_bytes() == unknown_code and users(guarded_db) == guarded_users)
    check("Guard refusal installs no new modules or backup", not guarded_app.joinpath("bulkmail-identity.php").exists() and not guarded.joinpath("var/backups/bulkmail").exists())

    enabled_root = base / "enabled-first-install"
    enabled_app, enabled_db, _ = fixture(enabled_root)
    enabled_config = enabled_root / "etc/bulkmail/integrations.php"
    enabled_config.parent.mkdir(parents=True)
    enabled_config.write_text("<?php return ['sms'=>['enabled'=>true]];")
    enabled_users = users(enabled_db)
    result = run_upgrade(enabled_root, environment)
    check("First installation refuses an already enabled channel", result.returncode != 0 and "requires identity, SMS and WhatsApp to remain disabled" in result.stderr and enabled_app.joinpath("index.php").read_bytes() == BASELINE and users(enabled_db) == enabled_users)

    # Deliberately fail the final unit-file install, after the new index was installed.
    failed_root = base / "rollback"
    failed_app, failed_db, failed_email_worker = fixture(failed_root)
    legacy_module = failed_app / "bulkmail-integrations.php"
    legacy_module.write_text("<?php // Previous private-config loader fixture.\n")
    legacy_bytes = legacy_module.read_bytes()
    failed_users = users(failed_db)
    failure_bin = base / "failure-bin"
    failure_bin.mkdir()
    install_executable = shutil.which("install")
    wrapper = failure_bin / "install"
    wrapper.write_text("#!/bin/sh\ncase \"$*\" in *systemd/bulkmail-messaging-worker.service*) exit 79;; esac\nexec '" + str(install_executable) + "' \"$@\"\n")
    wrapper.chmod(0o755)
    result = run_upgrade(failed_root, dict(environment, PATH=str(failure_bin) + os.pathsep + environment["PATH"]))
    check("A failure after index replacement invokes rollback", result.returncode == 79 and "restoring replaced code" in result.stderr)
    check("Rollback restores both the original index and replaced modules", failed_app.joinpath("index.php").read_bytes() == BASELINE and legacy_module.read_bytes() == legacy_bytes)
    check("Rollback removes only newly introduced files", not failed_app.joinpath("bulkmail-identity.php").exists() and not failed_root.joinpath("usr/local/sbin/bulkmail-messaging-worker.php").exists() and not failed_root.joinpath("etc/bulkmail/integrations.php").exists() and failed_email_worker.read_bytes() == original_worker)
    with sqlite3.connect(failed_db) as db:
        check("Rollback retains additive schema and never replaces the live database", db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='message_campaigns'").fetchone() is not None and users(failed_db) == failed_users)
    check("Rollback clears temporary code files", not list(failed_root.rglob(".bulkmail-upgrade.*")))

    # Prove the migration's all-user fingerprint guard actually rolls changes back.
    rejected_root = base / "fingerprint-rejection"
    _, rejected_db, _ = fixture(rejected_root)
    rejected_users = users(rejected_db)
    poison = base / "altering-migration-fixture"
    poison.mkdir()
    shutil.copy2(RELEASE / "app/bulkmail-identity.php", poison / "bulkmail-identity.php")
    poison.joinpath("bulkmail-messaging-core.php").write_text("<?php function bm_message_schema(PDO $db):void {$db->exec(\"UPDATE users SET display_name='unexpected mutation'\");}")
    result = subprocess.run(["php", str(MIGRATE), "--db=" + str(rejected_db), "--app-dir=" + str(poison)], text=True, capture_output=True)
    check("Migration detects any existing user-row mutation and rolls back", result.returncode != 0 and "user-preservation-check" in result.stderr and users(rejected_db) == rejected_users)
    with sqlite3.connect(rejected_db) as db:
        check("Failed migration rolls its schema additions back atomically", db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='user_identity_links'").fetchone()[0] == 0)
    check("Migration diagnostics never expose password hashes", rejected_users[0][2] not in result.stdout + result.stderr)

    # Keep a www-data SQLite client open while migration writes a WAL database.
    # Traversable fixture parents are deliberate; these are synthetic accounts.
    base.chmod(0o755)
    wal_root = base / "database-owner"
    _, wal_db, _ = fixture(wal_root)
    wal_users = users(wal_db)
    www = pwd.getpwnam("www-data")
    for directory in [wal_root, wal_root / "var", wal_root / "var/lib", wal_root / "var/lib/bulkmail"]:
        directory.chmod(0o755)
    os.chown(wal_db.parent, www.pw_uid, www.pw_gid)
    os.chown(wal_db, www.pw_uid, www.pw_gid)
    wal_db.chmod(0o660)

    def database_owner():
        os.initgroups(www.pw_name, www.pw_gid)
        os.setgid(www.pw_gid)
        os.setuid(www.pw_uid)

    connection = subprocess.Popen(["/usr/bin/python3", "-u", "-c", "import sqlite3,sys; db=sqlite3.connect(sys.argv[1],timeout=15); db.execute('PRAGMA journal_mode=WAL'); db.execute('SELECT COUNT(*) FROM users').fetchone(); print('ready',flush=True); input(); print(db.execute('SELECT COUNT(*) FROM message_channel_access').fetchone()[0],flush=True); db.close()", str(wal_db)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=database_owner)
    try:
        check("Synthetic www-data WAL client starts successfully", connection.stdout.readline().strip() == "ready")
        result = subprocess.run(["php", str(MIGRATE), "--db=" + str(wal_db), "--app-dir=" + str(RELEASE / "app")], text=True, capture_output=True)
        check("Migration succeeds with a concurrent www-data WAL client", result.returncode == 0)
        sidecars = [pathlib.Path(str(wal_db) + suffix) for suffix in ["-wal", "-shm"]]
        check("WAL and SHM remain owned by the existing database user", all(file.exists() and file.stat().st_uid == www.pw_uid and file.stat().st_gid == www.pw_gid for file in sidecars))
        connection.stdin.write("continue\n")
        connection.stdin.flush()
        check("Existing www-data client can read the migrated schema", connection.stdout.readline().strip() == "0")
        connection.wait(timeout=10)
        check("WAL migration also preserves every existing user field", users(wal_db) == wal_users)
    finally:
        if connection.poll() is None:
            connection.terminate()
            connection.wait(timeout=10)

print(f"PASS {len(passed)} isolated upgrade checks; no real services or live database used.", flush=True)
