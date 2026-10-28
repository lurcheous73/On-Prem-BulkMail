#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Existing-install upgrade only. --root-prefix always disables real service actions.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${BULKMAIL_SOURCE_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
ROOT_PREFIX=""
NO_SERVICES=0
PHP_FPM_SERVICE="${BULKMAIL_PHP_FPM_SERVICE:-php8.2-fpm.service}"
BASELINE_SHA="7602fd20458f8c8ab61b0c3ec9b36fbec97bb311d0a594d15cf032224e1b501e"

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
while (($#)); do
    case "$1" in
        --root-prefix) (($#>=2)) || fail 'Missing --root-prefix path.'; ROOT_PREFIX="$2"; NO_SERVICES=1; shift 2 ;;
        --no-services) NO_SERVICES=1; shift ;;
        --source-dir) (($#>=2)) || fail 'Missing --source-dir path.'; SOURCE_DIR="$2"; shift 2 ;;
        --help) printf '%s\n' 'Usage: upgrade-messaging.sh [--no-services] [--root-prefix /isolated/root] [--source-dir /release]'; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
[[ "$EUID" -eq 0 ]] || fail 'Run this existing-install upgrade as root.'
if [[ -n "$ROOT_PREFIX" ]]; then
    [[ "$ROOT_PREFIX" == /* && "$ROOT_PREFIX" != / && -d "$ROOT_PREFIX" ]] || fail 'The isolated root must be an existing absolute directory other than /.'
    ROOT_PREFIX="$(cd -- "$ROOT_PREFIX" && pwd -P)"
    [[ "$ROOT_PREFIX" != / ]] || fail 'The isolated root must not resolve to /.'
fi
[[ "$PHP_FPM_SERVICE" =~ ^php[0-9]+\.[0-9]+-fpm(\.service)?$ ]] || fail 'Invalid PHP-FPM service name.'
SOURCE_DIR="$(cd -- "$SOURCE_DIR" && pwd)"
APP_DIR="$ROOT_PREFIX/var/www/bulkmail"
DB_FILE="$ROOT_PREFIX/var/lib/bulkmail/bulkmail.sqlite"
CONFIG_FILE="$ROOT_PREFIX/etc/bulkmail/integrations.php"
WORKER_FILE="$ROOT_PREFIX/usr/local/sbin/bulkmail-messaging-worker.php"
UNIT_FILE="$ROOT_PREFIX/etc/systemd/system/bulkmail-messaging-worker.service"
BACKUP_BASE="$ROOT_PREFIX/var/backups/bulkmail"
[[ -d "$APP_DIR" && ! -L "$APP_DIR" && -f "$APP_DIR/index.php" && ! -L "$APP_DIR/index.php" ]] || fail 'Existing regular BulkMail application required.'
[[ -f "$DB_FILE" && ! -L "$DB_FILE" ]] || fail 'Existing BulkMail database required. Never run the fresh installer here.'

for tool in php python3 sha256sum install cp mv flock mktemp; do command -v "$tool" >/dev/null || fail "Required program unavailable: $tool"; done
id www-data >/dev/null 2>&1 || fail 'The www-data application user is required.'
php -r 'exit(PHP_VERSION_ID>=80200 && extension_loaded("pdo_sqlite") && extension_loaded("mbstring") && extension_loaded("curl") && extension_loaded("posix") ? 0 : 1);' || fail 'PHP 8.2+ with SQLite, mbstring, cURL and POSIX is required.'
APP_FILES=(bulkmail-integrations.php bulkmail-identity.php bulkmail-messaging-core.php bulkmail-messaging.php index.php)
for file in "${APP_FILES[@]}"; do
    [[ -f "$SOURCE_DIR/app/$file" ]] || fail "Missing application file: $file"
    php -l "$SOURCE_DIR/app/$file" >/dev/null || fail "PHP syntax failed: $file"
done
for file in worker/bulkmail-messaging-worker.php deployment/migrate-integrations.php deployment/integrations.php.example; do
    [[ -f "$SOURCE_DIR/$file" ]] || fail "Missing release file: $file"
    php -l "$SOURCE_DIR/$file" >/dev/null || fail "PHP syntax failed: $file"
done
[[ -f "$SOURCE_DIR/systemd/bulkmail-messaging-worker.service" ]] || fail 'Missing messaging worker unit.'
INCOMING_SHA="$(sha256sum "$SOURCE_DIR/app/index.php" | cut -d' ' -f1)"
guard_index() {
    local installed_sha
    installed_sha="$(sha256sum "$APP_DIR/index.php" | cut -d' ' -f1)"
    [[ "$installed_sha" == "$BASELINE_SHA" || "$installed_sha" == "$INCOMING_SHA" ]] || fail 'Installed index.php differs from the reviewed baseline and this release. Reconcile local changes before upgrading.'
}
guard_index
FIRST_INSTALL=1
if [[ -f "$WORKER_FILE" && -f "$UNIT_FILE" ]]; then FIRST_INSTALL=0; fi

check_config() {
    local path="$CONFIG_FILE"
    [[ -f "$path" ]] || path="$SOURCE_DIR/deployment/integrations.php.example"
    php /dev/stdin "$path" "$FIRST_INSTALL" <<'PHP'
<?php
try {
    ob_start();
    try { $config=require $argv[1]; } finally { ob_end_clean(); }
    if (!is_array($config)) throw new RuntimeException();
    foreach (['identity','sms','whatsapp'] as $section) {
        if (isset($config[$section]) && !is_array($config[$section])) throw new RuntimeException();
        $enabled=$config[$section]['enabled']??false;
        if (!is_bool($enabled)) throw new RuntimeException();
        if ($argv[2]==='1' && $enabled) {
            fwrite(STDERR,"First installation requires identity, SMS and WhatsApp to remain disabled.\n"); exit(1);
        }
    }
} catch (Throwable $e) { fwrite(STDERR,"Invalid private integration configuration.\n"); exit(1); }
PHP
}
check_config || fail 'Private configuration did not pass the upgrade guard.'

# Serialise upgrades without stopping or altering the existing email delivery worker.
exec 9>"$ROOT_PREFIX/var/lib/bulkmail/.messaging-upgrade.lock"
flock -n 9 || fail 'Another messaging upgrade is already running.'
guard_index

TARGETS=(var/www/bulkmail/index.php)
for file in bulkmail-integrations.php bulkmail-identity.php bulkmail-messaging-core.php bulkmail-messaging.php; do TARGETS+=("var/www/bulkmail/$file"); done
TARGETS+=(etc/bulkmail/integrations.php usr/local/sbin/bulkmail-messaging-worker.php etc/systemd/system/bulkmail-messaging-worker.service)
for relative in "${TARGETS[@]}"; do
    target="$ROOT_PREFIX/$relative"
    [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] || fail "Refusing unexpected target type: $relative"
done
install -d -m 0700 -o root -g root "$BACKUP_BASE"
BACKUP_DIR="$(mktemp -d "$BACKUP_BASE/messaging-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
chmod 0700 "$BACKUP_DIR"
mkdir -m 0700 "$BACKUP_DIR/files"
for relative in "${TARGETS[@]}"; do
    target="$ROOT_PREFIX/$relative"
    if [[ -f "$target" ]]; then
        mkdir -p -- "$BACKUP_DIR/files/$(dirname -- "$relative")"
        cp -a -- "$target" "$BACKUP_DIR/files/$relative"
        printf '%s\n' "$relative" >> "$BACKUP_DIR/existing-files.txt"
    fi
done
python3 - "$DB_FILE" "$BACKUP_DIR/bulkmail.sqlite" <<'PY'
import os, pathlib, sqlite3, sys
source = sqlite3.connect(pathlib.Path(sys.argv[1]).resolve().as_uri()+"?mode=ro", uri=True, timeout=15)
target = sqlite3.connect(sys.argv[2], timeout=15)
try:
    source.backup(target)
    if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise RuntimeError("SQLite backup integrity check failed")
finally:
    target.close()
    source.close()
os.chmod(sys.argv[2], 0o600)
PY

MUTATED=0
TEMP_FILES=()
rollback() {
    local result="$?"
    trap - EXIT
    if ((result!=0 && MUTATED)); then
        set +e
        printf '%s\n' 'Upgrade failed; restoring replaced code and pausing the messaging worker. Database changes are retained; no old database will be restored.' >&2
        if ((NO_SERVICES==0)); then
            systemctl stop bulkmail-messaging-worker.service >/dev/null 2>&1
            if ((FIRST_INSTALL)); then systemctl disable bulkmail-messaging-worker.service >/dev/null 2>&1; fi
        fi
        # Switch the old entry point back before removing any newly added dependencies.
        for relative in "${TARGETS[@]}"; do
            target="$ROOT_PREFIX/$relative"
            if [[ -f "$BACKUP_DIR/files/$relative" ]]; then
                cp -a -- "$BACKUP_DIR/files/$relative" "$target.rollback"
                mv -fT -- "$target.rollback" "$target"
            else
                rm -f -- "$target"
            fi
        done
        if ((NO_SERVICES==0)); then
            systemctl daemon-reload >/dev/null 2>&1
            systemctl reload "$PHP_FPM_SERVICE" >/dev/null 2>&1
        fi
        printf '%s\n' "Private rollback material: $BACKUP_DIR" >&2
    fi
    for temporary in "${TEMP_FILES[@]}"; do rm -f -- "$temporary"; done
    exit "$result"
}
trap rollback EXIT

atomic_install() {
    local source="$1" target="$2" mode="$3" group="$4" temporary
    mkdir -p -- "$(dirname -- "$target")"
    temporary="$(mktemp "$(dirname -- "$target")/.bulkmail-upgrade.XXXXXXXX")"
    TEMP_FILES+=("$temporary")
    install -m "$mode" -o root -g "$group" -- "$source" "$temporary"
    mv -fT -- "$temporary" "$target"
}

MUTATED=1
if ((NO_SERVICES==0)) && [[ -f "$UNIT_FILE" ]]; then
    systemctl stop bulkmail-messaging-worker.service
fi
if [[ ! -e "$CONFIG_FILE" ]]; then
    install -d -m 0750 -o root -g www-data "$(dirname -- "$CONFIG_FILE")"
    atomic_install "$SOURCE_DIR/deployment/integrations.php.example" "$CONFIG_FILE" 0640 www-data
fi
php "$SOURCE_DIR/deployment/migrate-integrations.php" --db="$DB_FILE" --app-dir="$SOURCE_DIR/app"

# Install every new dependency first. The index is the final application switch.
for file in bulkmail-integrations.php bulkmail-identity.php bulkmail-messaging-core.php bulkmail-messaging.php; do
    atomic_install "$SOURCE_DIR/app/$file" "$APP_DIR/$file" 0644 root
done
atomic_install "$SOURCE_DIR/worker/bulkmail-messaging-worker.php" "$WORKER_FILE" 0755 root
atomic_install "$SOURCE_DIR/app/index.php" "$APP_DIR/index.php" 0644 root
atomic_install "$SOURCE_DIR/systemd/bulkmail-messaging-worker.service" "$UNIT_FILE" 0644 root
check_config || fail 'Integration configuration changed during installation.'

if ((NO_SERVICES==0)); then
    systemctl daemon-reload
    systemctl reload "$PHP_FPM_SERVICE"
    systemctl enable --now bulkmail-messaging-worker.service
    systemctl is-active --quiet bulkmail-messaging-worker.service
else
    printf '%s\n' 'Service actions skipped; no PHP-FPM or systemd unit was touched at runtime.'
fi
MUTATED=0
printf '%s\n' 'Messaging code upgrade complete. Existing accounts and email delivery configuration were preserved.'
printf '%s\n' "Private backup: $BACKUP_DIR"
