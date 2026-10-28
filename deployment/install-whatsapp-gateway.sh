#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Installs only the optional WhatsApp transport. Does not link or send messages.
NODE_VERSION=24.22.1
NODE_SHA256=6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6
NODE_ARCHIVE_NAME="node-v${NODE_VERSION}-linux-x64.tar.xz"
NODE_DIR="/opt/bulkmail-node-${NODE_VERSION}"
SERVICE_DIR=/opt/bulkmail-whatsapp
STATE_DIR=/var/lib/bulkmail-whatsapp
ENV_FILE=/etc/bulkmail-whatsapp.env
CONFIG_FILE=/etc/bulkmail/integrations.php
UNIT_FILE=/etc/systemd/system/bulkmail-whatsapp.service
DROPIN_DIR=/etc/systemd/system/bulkmail-whatsapp.service.d
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/../services/whatsapp-gateway"
NODE_ARCHIVE=
OFFLINE=false
NO_SERVICES=false
ROTATE_TOKEN=false
WORK_DIR=
BACKUP_DIR=
ENV_TEMP=
CONFIG_TEMP=
CHANGES_STARTED=false
SUCCEEDED=false
WAS_ACTIVE=false
WAS_ENABLED=false

usage() {
  cat <<'HELP'
Usage: install-whatsapp-gateway.sh [options]
  --source-dir DIR    Gateway source directory (including package-lock.json).
  --node-archive FILE Offline official node-v24.22.1-linux-x64.tar.xz archive.
  --offline          Prohibit downloads; require bundled node_modules and runtime/archive.
  --no-services      Install files without starting/enabling/reloading systemd.
  --rotate-token     Explicitly replace both disabled-installation tokens with a new one.
  --help             Show this help.

Requires Debian 12 x86-64, root, and the existing BulkMail integrations.php file.
Existing enabled or previously linked installations require operator review and
are refused. No account, link state or outbound journal is deleted.
HELP
}
fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --source-dir|--node-archive)
      (($# >= 2)) || fail "$1 requires a path."
      if [[ $1 == --source-dir ]]; then SOURCE_DIR=$2; else NODE_ARCHIVE=$2; fi
      shift 2 ;;
    --offline) OFFLINE=true; shift ;;
    --no-services) NO_SERVICES=true; shift ;;
    --rotate-token) ROTATE_TOKEN=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[[ $EUID == 0 ]] || fail 'Run this installer as root.'
[[ -r /etc/os-release ]] || fail 'Cannot identify the operating system.'
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 12 ]] || fail 'This installer supports Debian 12 only.'
[[ $(uname -m) == x86_64 ]] || fail 'This pinned runtime is for x86-64 only.'
for command in php tar sha256sum flock mktemp install cp mv getent useradd groupadd; do
  command -v "$command" >/dev/null || fail "Required command is missing: $command"
done
if ! $NO_SERVICES; then command -v systemctl >/dev/null || fail 'systemctl is required.'; fi
getent group www-data >/dev/null || fail 'The existing www-data group is required.'
SOURCE_DIR=$(realpath -- "$SOURCE_DIR")
[[ -f $SOURCE_DIR/package.json && -f $SOURCE_DIR/package-lock.json && -f $SOURCE_DIR/src/main.mjs \
   && -f $SOURCE_DIR/deployment/bulkmail-whatsapp.service ]] || fail 'The gateway source bundle is incomplete.'
[[ -f $CONFIG_FILE && ! -L $CONFIG_FILE ]] || fail 'Install the BulkMail integrations.php configuration first; symlinks are not accepted.'
for path in "$SERVICE_DIR" "$STATE_DIR" "$ENV_FILE" "$NODE_DIR" "$UNIT_FILE" "$DROPIN_DIR"; do
  [[ ! -L $path ]] || fail 'A managed installation path is a symlink; operator review is required.'
done
for path in "$SERVICE_DIR" "$STATE_DIR" "$NODE_DIR" "$DROPIN_DIR"; do
  [[ ! -e $path || -d $path ]] || fail 'An installation directory path contains another object type; operator review is required.'
done
for path in "$ENV_FILE" "$UNIT_FILE"; do
  [[ ! -e $path || -f $path ]] || fail 'An installation file path contains another object type; operator review is required.'
done
exec 9>/run/bulkmail-whatsapp-install.lock
flock -n 9 || fail 'Another gateway installation is running.'

cleanup() {
  local result=$?
  trap - EXIT
  if $CHANGES_STARTED && ! $SUCCEEDED; then
    printf '%s\n' 'Installation failed; restoring the previous disabled service files.' >&2
    if ! $NO_SERVICES; then systemctl stop bulkmail-whatsapp.service >/dev/null 2>&1 || true; fi
    if [[ -n $BACKUP_DIR && -d $BACKUP_DIR/service-code ]]; then
      rm -rf -- "$SERVICE_DIR"
      cp -a -- "$BACKUP_DIR/service-code" "$SERVICE_DIR"
    elif [[ -n $BACKUP_DIR && -f $BACKUP_DIR/no-service-code ]]; then
      rm -rf -- "$SERVICE_DIR"
    fi
    for pair in "environment:$ENV_FILE" "integrations:$CONFIG_FILE" "unit:$UNIT_FILE"; do
      local name=${pair%%:*} destination=${pair#*:}
      if [[ -f $BACKUP_DIR/$name ]]; then cp -a -- "$BACKUP_DIR/$name" "$destination";
      elif [[ -f $BACKUP_DIR/no-$name ]]; then rm -f -- "$destination"; fi
    done
    if [[ -d $BACKUP_DIR/dropins ]]; then
      rm -rf -- "$DROPIN_DIR"; cp -a -- "$BACKUP_DIR/dropins" "$DROPIN_DIR"
    elif [[ -f $BACKUP_DIR/no-dropins ]]; then rm -rf -- "$DROPIN_DIR"; fi
    if ! $NO_SERVICES; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      if $WAS_ENABLED; then systemctl enable bulkmail-whatsapp.service >/dev/null 2>&1 || true;
      else systemctl disable bulkmail-whatsapp.service >/dev/null 2>&1 || true; fi
      if $WAS_ACTIVE; then systemctl start bulkmail-whatsapp.service >/dev/null 2>&1 || true; fi
    fi
    printf '%s\n' "Review the preserved backup at $BACKUP_DIR. Gateway state was not removed." >&2
  fi
  [[ -z $ENV_TEMP ]] || rm -f -- "$ENV_TEMP"
  [[ -z $CONFIG_TEMP ]] || rm -f -- "$CONFIG_TEMP"
  [[ -z $WORK_DIR ]] || rm -rf -- "$WORK_DIR"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
WORK_DIR=$(mktemp -d /opt/.bulkmail-whatsapp-install.XXXXXX)

# The PHP helper reads secrets itself; they are never shell arguments or output.
config_helper() {
  php /dev/stdin "$@" <<'PHP'
<?php
declare(strict_types=1);
function stop(string $message): never { fwrite(STDERR,"ERROR: ".$message."\n"); exit(1); }
function readEnv(string $path): array {
    if (!is_file($path)) return [];
    $values=[];
    foreach (file($path,FILE_IGNORE_NEW_LINES) as $line) {
        if (trim($line)==='' || str_starts_with(ltrim($line),'#')) continue;
        if (!preg_match('/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/D',$line,$match)) stop('Unrecognised environment file syntax; review it before installing.');
        if (array_key_exists($match[1],$values)) stop('Duplicate environment setting; review it before installing.');
        $value=trim($match[2]);
        if (strlen($value)>=2 && $value[0]==='"' && str_ends_with($value,'"')) {
            $value=substr($value,1,-1);
            $value=preg_replace_callback('/\\\\([\\\\"])/',static fn(array $m): string=>$m[1],$value);
        } elseif (strlen($value)>=2 && $value[0]==="'" && str_ends_with($value,"'")) $value=substr($value,1,-1);
        $values[$match[1]]=$value;
    }
    return $values;
}
function scalarTree(mixed $value): bool {
    if (is_array($value)) { foreach ($value as $item) if (!scalarTree($item)) return false; return true; }
    return is_scalar($value) || $value===null;
}
try {
    [$script,$mode,$envPath,$configPath,$statePath,$outputDir,$rotate]=$argv;
    $env=readEnv($envPath);
    if ($mode==='health') {
        if (!extension_loaded('curl')) stop('PHP curl is required for the local health check.');
        $curl=curl_init('http://127.0.0.1:8787/health');
        curl_setopt_array($curl,[CURLOPT_HTTPHEADER=>['Authorization: Bearer '.($env['GATEWAY_TOKEN']??'')],CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>1,CURLOPT_TIMEOUT=>2,CURLOPT_FOLLOWLOCATION=>false]);
        $body=curl_exec($curl);$status=(int)curl_getinfo($curl,CURLINFO_RESPONSE_CODE);curl_close($curl);
        $json=is_string($body)?json_decode($body,true):null;
        exit($status===200 && ($json['status']??null)==='disabled' && ($json['enabled']??null)===false && ($json['send_enabled']??null)===false && ($json['can_send']??null)===false ? 0 : 1);
    }
    if (!extension_loaded('pdo_sqlite') || !extension_loaded('curl')) stop('PHP pdo_sqlite and curl are required.');
    ob_start();
    try { $config=(static fn(string $path)=>require $path)($configPath); }
    finally { ob_end_clean(); }
    if (!is_array($config) || !scalarTree($config)) stop('Existing integration configuration must return an array of scalar values.');
    $wa=$config['whatsapp']??[];
    if (!is_array($wa)) stop('Existing WhatsApp configuration is not an array.');
    if (($wa['enabled']??false)!==false) stop('Existing WhatsApp app configuration is enabled or nonstandard; operator review is required.');
    foreach (['GATEWAY_ENABLED','GATEWAY_SEND_ENABLED'] as $key) {
        if (!in_array($env[$key]??'false',['false',''],true)) stop('Existing gateway connection or delivery is enabled; operator review is required.');
    }
    foreach (['GATEWAY_HOST'=>'127.0.0.1','GATEWAY_PORT'=>'8787','GATEWAY_DATA_DIR'=>$statePath] as $key=>$expected) {
        if (isset($env[$key]) && $env[$key]!==$expected) stop('Existing gateway paths or listener differ; operator review is required.');
    }
    if (isset($env['GATEWAY_SEND_TIMEOUT_MS']) && (!ctype_digit($env['GATEWAY_SEND_TIMEOUT_MS']) || (int)$env['GATEWAY_SEND_TIMEOUT_MS']<1000 || (int)$env['GATEWAY_SEND_TIMEOUT_MS']>=20000)) stop('Existing gateway timeout must be below the PHP 20-second deadline.');
    if (!in_array($wa['base_url']??'',['','http://127.0.0.1:8787'],true)) stop('Existing WhatsApp endpoint differs; operator review is required.');
    $database=$statePath.'/gateway.sqlite';
    if (is_file($database)) {
        $db=new PDO('sqlite:'.$database,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $db->exec('PRAGMA query_only=ON');
        if (!$db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='auth_values'")->fetchColumn()) stop('Existing gateway state has an unknown schema; operator review is required.');
        if ((int)$db->query('SELECT COUNT(*) FROM auth_values')->fetchColumn()>0) stop('Existing gateway has linked or previously active credentials; automatic upgrade is refused.');
        $db=null;
    } elseif (is_dir($statePath) && count(array_diff(scandir($statePath),['.','..']))>0) {
        stop('Existing gateway state is not recognised; operator review is required.');
    }
    $envToken=(string)($env['GATEWAY_TOKEN']??'');$appToken=(string)($wa['token']??'');
    foreach ([$envToken,$appToken] as $token) {
        if ($rotate!=='true' && $token!=='' && (strlen($token)<32 || strlen($token)>512 || preg_match('/[\x00-\x20\x7f]/',$token))) stop('An existing gateway token is invalid; review it explicitly.');
    }
    if ($rotate!=='true' && $envToken!=='' && $appToken!=='' && !hash_equals($envToken,$appToken)) stop('Existing gateway tokens conflict; review them or explicitly use --rotate-token.');
    if ($mode==='check') exit(0);
    if ($mode!=='prepare') stop('Invalid installer phase.');
    $token=$rotate==='true'?bin2hex(random_bytes(32)):($envToken?:($appToken?:bin2hex(random_bytes(32))));
    // Preserve every unrelated existing integration setting.
    $config['whatsapp']=array_replace($wa,['enabled'=>false,'base_url'=>'http://127.0.0.1:8787','token'=>$token,'allow_http'=>true]);
    if (!isset($config['whatsapp']['min_interval_seconds'])) $config['whatsapp']['min_interval_seconds']=8;
    $updates=['GATEWAY_TOKEN'=>$token,'GATEWAY_HOST'=>'127.0.0.1','GATEWAY_PORT'=>'8787','GATEWAY_DATA_DIR'=>$statePath,'GATEWAY_ENABLED'=>'false','GATEWAY_SEND_ENABLED'=>'false'];
    $env=array_replace(['GATEWAY_MIN_INTERVAL_MS'=>'8000','GATEWAY_SEND_TIMEOUT_MS'=>'15000'],$env,$updates);
    $lines=["# Managed WhatsApp transport configuration; keep private."];
    foreach ($env as $key=>$value) {
        if (preg_match('/[\r\n\x00]/',$value)) stop('Multiline environment settings are not supported.');
        $lines[]=$key.'="'.str_replace(['\\','"'],['\\\\','\\"'],$value).'"';
    }
    if (file_put_contents($outputDir.'/environment',implode("\n",$lines)."\n")===false
      || file_put_contents($outputDir.'/integrations',"<?php\ndeclare(strict_types=1);\n\nreturn ".var_export($config,true).";\n")===false) stop('Could not prepare private configuration.');
    chmod($outputDir.'/environment',0600);chmod($outputDir.'/integrations',0600);
} catch (Throwable $error) { stop('Installer configuration check failed; no secret values were printed.'); }
PHP
}

config_helper check "$ENV_FILE" "$CONFIG_FILE" "$STATE_DIR" "$WORK_DIR" "$ROTATE_TOKEN"
sha256sum "$CONFIG_FILE" > "$WORK_DIR/original-config.sha256"
if [[ -f $ENV_FILE ]]; then sha256sum "$ENV_FILE" > "$WORK_DIR/original-environment.sha256"; fi
if getent passwd bulkmail-whatsapp >/dev/null; then
  [[ $(getent passwd bulkmail-whatsapp | cut -d: -f6) == "$STATE_DIR" ]] || fail 'Existing service user has a different home; operator review is required.'
  case "$(getent passwd bulkmail-whatsapp | cut -d: -f7)" in /usr/sbin/nologin|/sbin/nologin|/bin/false) ;; *) fail 'Existing service user permits login; operator review is required.' ;; esac
fi
if ! $NO_SERVICES; then
  systemctl is-active --quiet bulkmail-whatsapp.service && WAS_ACTIVE=true || true
  systemctl is-enabled --quiet bulkmail-whatsapp.service && WAS_ENABLED=true || true
fi

printf '%s\n' 'Preparing the isolated, checksum-verified Node runtime.'
if [[ -d $NODE_DIR ]]; then
  [[ -f $NODE_DIR/.archive-sha256 && $(cat "$NODE_DIR/.archive-sha256") == "$NODE_SHA256" ]] || fail 'Existing isolated Node runtime has no matching installer provenance; operator review is required.'
  [[ $($NODE_DIR/bin/node --version) == "v$NODE_VERSION" ]] || fail 'Existing isolated Node runtime version differs.'
else
  if [[ -n $NODE_ARCHIVE ]]; then
    NODE_ARCHIVE=$(realpath -- "$NODE_ARCHIVE")
    [[ -f $NODE_ARCHIVE ]] || fail 'The supplied Node archive is missing.'
  else
    $OFFLINE && fail 'Offline installation requires --node-archive or the already installed isolated runtime.'
    command -v curl >/dev/null || fail 'curl is required to download the runtime.'
    NODE_ARCHIVE="$WORK_DIR/$NODE_ARCHIVE_NAME"
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
      --output "$NODE_ARCHIVE" "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_ARCHIVE_NAME}"
  fi
  [[ $(sha256sum -- "$NODE_ARCHIVE" | cut -d' ' -f1) == "$NODE_SHA256" ]] || fail 'Official Node archive checksum does not match; nothing will be extracted.'
  mkdir "$WORK_DIR/runtime"
  tar --extract --xz --file "$NODE_ARCHIVE" --directory "$WORK_DIR/runtime" --strip-components=1 --no-same-owner
  [[ $($WORK_DIR/runtime/bin/node --version) == "v$NODE_VERSION" ]] || fail 'Verified archive did not provide the expected runtime.'
  printf '%s\n' "$NODE_SHA256" > "$WORK_DIR/runtime/.archive-sha256"
  chmod -R a+rX "$WORK_DIR/runtime"
  mv -- "$WORK_DIR/runtime" "$NODE_DIR"
fi

mkdir "$WORK_DIR/service"
tar --create --file - --directory "$SOURCE_DIR" --exclude='./node_modules' --exclude='./data' --exclude='./.env' --exclude='./.git' . \
  | tar --extract --file - --directory "$WORK_DIR/service" --no-same-owner
if [[ -d $SOURCE_DIR/node_modules ]]; then
  printf '%s\n' 'Using the supplied dependency bundle; checking its locked package graph.'
  cp -a -- "$SOURCE_DIR/node_modules" "$WORK_DIR/service/node_modules"
else
  $OFFLINE && fail 'Offline installation requires node_modules in the supplied source directory.'
  printf '%s\n' 'Installing dependencies from the pinned package lock.'
  (cd "$WORK_DIR/service" && PATH="$NODE_DIR/bin:/usr/bin:/bin" \
    "$NODE_DIR/bin/node" "$NODE_DIR/lib/node_modules/npm/bin/npm-cli.js" ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
fi
(cd "$WORK_DIR/service" && "$NODE_DIR/bin/node" --input-type=module <<'JS'
import { readFileSync } from 'node:fs';
const json = file => JSON.parse(readFileSync(file,'utf8'));
const root=json('package.json'), expected=json('package-lock.json'), installed=json('node_modules/.package-lock.json');
if (root.dependencies?.baileys!=='7.0.0-rc14' || expected.packages?.['node_modules/baileys']?.version!=='7.0.0-rc14') throw new Error('Unexpected gateway Baileys pin');
for (const [path, value] of Object.entries(installed.packages ?? {})) {
  const wanted=expected.packages[path];
  if (!wanted || wanted.version!==value.version || wanted.integrity!==value.integrity) throw new Error('Dependency bundle differs from package lock');
  const actual=json(`${path}/package.json`);
  if (actual.version!==wanted.version) throw new Error('Installed package version differs from lock');
}
for (const [path, value] of Object.entries(expected.packages ?? {})) {
  if (path && !value.optional && !installed.packages?.[path]) throw new Error('Required locked dependency is missing');
}
const baileys=await import('baileys');
for (const key of ['default','BufferJSON','proto','initAuthCreds','generateMessageIDV2','makeCacheableSignalKeyStore']) if (!baileys[key]) throw new Error('Required Baileys export is missing');
await import('qrcode'); await import('proper-lockfile');
JS
)
config_helper prepare "$ENV_FILE" "$CONFIG_FILE" "$STATE_DIR" "$WORK_DIR" "$ROTATE_TOKEN"
php -l "$WORK_DIR/integrations" >/dev/null
# Refuse to overwrite configuration changed while dependencies were preparing.
sha256sum --check --status "$WORK_DIR/original-config.sha256" || fail 'Integration configuration changed during installation; retry after review.'
if [[ -f $WORK_DIR/original-environment.sha256 ]]; then
  sha256sum --check --status "$WORK_DIR/original-environment.sha256" || fail 'Gateway environment changed during installation; retry after review.'
elif [[ -e $ENV_FILE ]]; then fail 'Gateway environment appeared during installation; retry after review.'; fi
config_helper check "$ENV_FILE" "$CONFIG_FILE" "$STATE_DIR" "$WORK_DIR" "$ROTATE_TOKEN"

BACKUP_DIR="/var/backups/bulkmail-whatsapp/$(date -u +%Y%m%dT%H%M%SZ)-${WORK_DIR##*.}"
install -d -m 0700 "$BACKUP_DIR"
for pair in "environment:$ENV_FILE" "integrations:$CONFIG_FILE" "unit:$UNIT_FILE"; do
  name=${pair%%:*}; origin=${pair#*:}
  if [[ -f $origin ]]; then cp -a -- "$origin" "$BACKUP_DIR/$name"; else touch "$BACKUP_DIR/no-$name"; fi
done
if [[ -d $DROPIN_DIR ]]; then cp -a -- "$DROPIN_DIR" "$BACKUP_DIR/dropins"; else touch "$BACKUP_DIR/no-dropins"; fi
if [[ -d $SERVICE_DIR ]]; then cp -a -- "$SERVICE_DIR" "$BACKUP_DIR/service-code"; else touch "$BACKUP_DIR/no-service-code"; fi
CHANGES_STARTED=true
if ! $NO_SERVICES && $WAS_ACTIVE; then systemctl stop bulkmail-whatsapp.service; fi
if [[ -d $STATE_DIR ]]; then cp -a -- "$STATE_DIR" "$BACKUP_DIR/state"; fi
getent group bulkmail-whatsapp >/dev/null || groupadd --system bulkmail-whatsapp
getent passwd bulkmail-whatsapp >/dev/null || useradd --system --gid bulkmail-whatsapp --home-dir "$STATE_DIR" --shell /usr/sbin/nologin bulkmail-whatsapp
install -d -o bulkmail-whatsapp -g bulkmail-whatsapp -m 0700 "$STATE_DIR"
[[ ! -d $SERVICE_DIR ]] || rm -rf -- "$SERVICE_DIR"
mv -- "$WORK_DIR/service" "$SERVICE_DIR"
chown -R root:root "$SERVICE_DIR"
chmod -R a+rX "$SERVICE_DIR"
ENV_TEMP=$(mktemp /etc/.bulkmail-whatsapp-env.XXXXXX)
CONFIG_TEMP=$(mktemp /etc/bulkmail/.whatsapp-integrations.XXXXXX)
install -o root -g root -m 0600 "$WORK_DIR/environment" "$ENV_TEMP"
install -o root -g www-data -m 0640 "$WORK_DIR/integrations" "$CONFIG_TEMP"
mv -- "$ENV_TEMP" "$ENV_FILE"; ENV_TEMP=
mv -- "$CONFIG_TEMP" "$CONFIG_FILE"; CONFIG_TEMP=
install -o root -g root -m 0644 "$SERVICE_DIR/deployment/bulkmail-whatsapp.service" "$UNIT_FILE"
install -d -o root -g root -m 0755 "$DROPIN_DIR"
cat > "$DROPIN_DIR/10-runtime.conf" <<EOF
[Service]
ExecStart=
ExecStart=$NODE_DIR/bin/node $SERVICE_DIR/src/main.mjs
Environment=PATH=$NODE_DIR/bin:/usr/bin:/bin
EOF
chmod 0644 "$DROPIN_DIR/10-runtime.conf"

if $NO_SERVICES; then
  printf '%s\n' 'Gateway files installed with connection and delivery disabled; service actions were skipped.'
else
  systemctl daemon-reload
  systemctl enable --now bulkmail-whatsapp.service >/dev/null
  healthy=false
  for attempt in {1..10}; do
    if config_helper health "$ENV_FILE" "$CONFIG_FILE" "$STATE_DIR" "$WORK_DIR" false; then healthy=true; break; fi
    sleep 1
  done
  $healthy || fail 'Disabled local API did not become healthy; restoring the prior installation.'
  systemctl is-active --quiet bulkmail-whatsapp.service || fail 'The WhatsApp service did not remain active.'
  printf '%s\n' 'WhatsApp gateway installed: authenticated loopback API healthy, connection disabled, delivery disabled.'
fi
SUCCEEDED=true
printf '%s\n' "Private installation backup: $BACKUP_DIR"
