#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Brimstone On-Prem BulkMail"

APP_DIR="/var/www/bulkmail"
DATA_DIR="/var/lib/bulkmail"
DB="$DATA_DIR/bulkmail.sqlite"

WORKER="/usr/local/sbin/bulkmail-worker.php"
CONFIG="/etc/on-prem-bulkmail.conf"

NGINX_AVAILABLE="/etc/nginx/sites-available/bulkmail"
NGINX_ENABLED="/etc/nginx/sites-enabled/bulkmail"

SERVICE="/etc/systemd/system/bulkmail-worker.service"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this installer as root."
    exit 1
fi

echo "============================================================"
echo " ON-PREM BULKMAIL INSTALLER"
echo "============================================================"
echo
echo "Target platform: Debian 12"
echo

ask() {
    local prompt="$1"
    local default="$2"
    local value

    read -r -p "$prompt [$default]: " value
    printf '%s' "${value:-$default}"
}

PUBLIC_HOST="$(ask "Public hostname" "bulkmail.example.com")"
PUBLIC_SCHEME="$(ask "Public scheme http/https" "http")"

SMTP_HOST="$(ask "Outbound SMTP relay" "smtp.example.com")"
SMTP_PORT="$(ask "SMTP relay port" "25")"
SMTP_HELO="$(ask "SMTP HELO hostname" "$PUBLIC_HOST")"

DEFAULT_FROM="$(ask "Initial admin email" "admin@$PUBLIC_HOST")"
ORGANISATION="$(ask "Organisation name" "My Organisation")"

DRIP_DELAY="$(ask "Seconds between SMTP deliveries" "8")"

echo
echo "SMTP authentication:"
echo "  1 - none"
echo "  2 - username/password"
read -r -p "Choice [1]: " SMTP_AUTH
SMTP_AUTH="${SMTP_AUTH:-1}"

SMTP_USER=""
SMTP_PASS=""

if [ "$SMTP_AUTH" = "2" ]; then
    read -r -p "SMTP username: " SMTP_USER
    read -r -s -p "SMTP password: " SMTP_PASS
    echo
fi

echo
echo "SMTP TLS:"
echo "  1 - opportunistic STARTTLS"
echo "  2 - require STARTTLS"
echo "  3 - no TLS requirement"
read -r -p "Choice [1]: " SMTP_TLS
SMTP_TLS="${SMTP_TLS:-1}"

case "$SMTP_TLS" in
    2) SMTP_TLS_LEVEL="encrypt" ;;
    3) SMTP_TLS_LEVEL="none" ;;
    *) SMTP_TLS_LEVEL="may" ;;
esac

PUBLIC_BASE="${PUBLIC_SCHEME}://${PUBLIC_HOST}/"

echo
echo "============================================================"
echo " CONFIGURATION"
echo "============================================================"
echo "URL          : $PUBLIC_BASE"
echo "Organisation : $ORGANISATION"
echo "SMTP relay   : $SMTP_HOST:$SMTP_PORT"
echo "SMTP HELO    : $SMTP_HELO"
echo "Admin email  : $DEFAULT_FROM"
echo "Drip delay   : ${DRIP_DELAY}s"
echo

read -r -p "Install? [Y/n]: " CONFIRM
CONFIRM="${CONFIRM:-Y}"

case "$CONFIRM" in
    y|Y|yes|YES) ;;
    *) exit 0 ;;
esac

export DEBIAN_FRONTEND=noninteractive

echo
echo "=== PACKAGES ==="

apt-get update

apt-get install -y \
    nginx \
    postfix \
    sqlite3 \
    php-fpm \
    php-cli \
    php-sqlite3 \
    php-mbstring \
    php-xml \
    php-gd \
    poppler-utils \
    imagemagick \
    ca-certificates \
    curl

echo
echo "=== PHP-FPM ==="

PHP_FPM_SOCKET="$(
    find /run/php \
        -maxdepth 1 \
        -type s \
        -name 'php*-fpm.sock' \
        | sort -V \
        | tail -1
)"

if [ -z "$PHP_FPM_SOCKET" ]; then
    echo "ERROR: PHP-FPM socket not found."
    exit 20
fi

echo "$PHP_FPM_SOCKET"

echo
echo "=== APPLICATION ==="

install -d -o root -g root -m 0755 "$APP_DIR"
cp -a "$SCRIPT_DIR/app/." "$APP_DIR/"

find "$APP_DIR" -type d -exec chmod 0755 {} \;
find "$APP_DIR" -type f -exec chmod 0644 {} \;

echo
echo "=== DATA ==="

install -d -o www-data -g www-data -m 0750 "$DATA_DIR"

for d in drafts mailings uploads
do
    install -d \
        -o www-data \
        -g www-data \
        -m 0750 \
        "$DATA_DIR/$d"
done

echo
echo "=== DATABASE ==="

if [ -e "$DB" ]; then
    cp -a \
        "$DB" \
        "${DB}.pre-install-$(date +%Y%m%d-%H%M%S)"
fi

rm -f "$DB"

sqlite3 "$DB" < "$SCRIPT_DIR/database/schema.sql"

ADMIN_HASH="$(
    php -r \
    'echo password_hash("password1", PASSWORD_DEFAULT);'
)"

SQL_FROM="$(printf '%s' "$DEFAULT_FROM" | sed "s/'/''/g")"
SQL_ORG="$(printf '%s' "$ORGANISATION" | sed "s/'/''/g")"

sqlite3 "$DB" "
INSERT INTO users
(
    username,
    password_hash,
    display_name,
    email,
    organisation,
    account_type,
    is_admin,
    active
)
VALUES
(
    'admin',
    '$ADMIN_HASH',
    'Administrator',
    '$SQL_FROM',
    '$SQL_ORG',
    'internal',
    1,
    1
);

INSERT INTO organisation_settings
(
    user_id,
    footer_name
)
VALUES
(
    1,
    '$SQL_ORG'
);

INSERT INTO sender_identities
(
    owner_user_id,
    label,
    email,
    active
)
VALUES
(
    1,
    'Default Sender',
    '$SQL_FROM',
    1
);
"

chown www-data:www-data "$DB"
chmod 0640 "$DB"

echo
echo "=== WORKER ==="

install \
    -o root \
    -g root \
    -m 0755 \
    "$SCRIPT_DIR/worker/bulkmail-worker.php" \
    "$WORKER"

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/bulkmail-worker.service" \
    "$SERVICE"

printf '%s\n' \
    "BULKMAIL_PUBLIC_BASE=$PUBLIC_BASE" \
    "BULKMAIL_MESSAGE_DOMAIN=$PUBLIC_HOST" \
    > "$CONFIG"

chmod 0644 "$CONFIG"

echo
echo "=== NGINX ==="

sed \
    "s|unix:/run/php/php8.2-fpm.sock|unix:$PHP_FPM_SOCKET|g" \
    "$SCRIPT_DIR/nginx/on-prem-bulkmail.conf" \
    > "$NGINX_AVAILABLE"

rm -f /etc/nginx/sites-enabled/default

ln -sfn \
    "$NGINX_AVAILABLE" \
    "$NGINX_ENABLED"

nginx -t

echo
echo "=== POSTFIX ==="

postconf -e "inet_interfaces = loopback-only"
postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"

postconf -e \
    "relayhost = [$SMTP_HOST]:$SMTP_PORT"

postconf -e \
    "smtp_helo_name = $SMTP_HELO"

postconf -e \
    "smtp_destination_concurrency_limit = 1"

postconf -e \
    "smtp_destination_recipient_limit = 1"

postconf -e \
    "smtp_initial_destination_concurrency = 1"

postconf -e \
    "smtp_transport_rate_delay = ${DRIP_DELAY}s"

postconf -e \
    "smtp_tls_security_level = $SMTP_TLS_LEVEL"

postconf -e \
    "smtp_tls_CApath = /etc/ssl/certs"

if [ "$SMTP_AUTH" = "2" ]; then

    printf '%s %s:%s\n' \
        "[$SMTP_HOST]:$SMTP_PORT" \
        "$SMTP_USER" \
        "$SMTP_PASS" \
        > /etc/postfix/sasl_passwd

    chmod 0600 /etc/postfix/sasl_passwd

    postmap /etc/postfix/sasl_passwd

    chmod 0600 \
        /etc/postfix/sasl_passwd \
        /etc/postfix/sasl_passwd.db

    postconf -e \
        "smtp_sasl_auth_enable = yes"

    postconf -e \
        "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"

    postconf -e \
        "smtp_sasl_security_options = noanonymous"

else

    postconf -e \
        "smtp_sasl_auth_enable = no"

fi

echo
echo "=== SERVICES ==="

systemctl daemon-reload

systemctl enable nginx
systemctl enable postfix
systemctl enable bulkmail-worker.service

systemctl restart postfix
systemctl restart nginx
systemctl restart bulkmail-worker.service

echo
echo "=== HEALTH CHECK ==="

php -l "$APP_DIR/index.php"
php -l "$WORKER"

sqlite3 "$DB" "PRAGMA integrity_check;"

nginx -t

echo -n "nginx: "
systemctl is-active nginx

echo -n "postfix: "
systemctl is-active postfix

echo -n "worker: "
systemctl is-active bulkmail-worker.service

echo
echo "=== HTTP ==="

HTTP="$(
    curl \
        -sS \
        -o /tmp/on-prem-bulkmail.html \
        -w '%{http_code}' \
        http://127.0.0.1/
)"

echo "HTTP $HTTP"

echo
echo "============================================================"
echo " ON-PREM BULKMAIL INSTALLED"
echo "============================================================"
echo
echo "URL:"
echo "  $PUBLIC_BASE"
echo
echo "Initial administrator:"
echo "  Username: admin"
echo "  Password: password1"
echo
echo "CHANGE THE PASSWORD AFTER FIRST LOGIN."
echo
echo "Delivery:"
echo "  One recipient per SMTP delivery"
echo "  One concurrent destination"
echo "  ${DRIP_DELAY}-second drip delay"
echo
echo "============================================================"
