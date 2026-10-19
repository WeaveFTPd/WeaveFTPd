#!/usr/bin/env bash
# Interactive Linux installer. Requires Bash, Docker Engine and Compose v2.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deploy="$repo/docker/deploy"
image=${WEAVEFTPD_SETUP_IMAGE:-ghcr.io/weaveftpd/weaveftpd:latest}
sitebot_image=${WEAVEFTPD_SETUP_SITEBOT_IMAGE:-ghcr.io/weaveftpd/weaveftpd-sitebot:latest}
ask() {
  local answer
  IFS= read -r -p "$2${3:+ [$3]}: " answer
  printf -v "$1" '%s' "${answer:-${3:-}}"
}
secret() {
  IFS= read -r -s -p "$2: " "$1"
  printf '\n'
}
yes() { [[ "$1" == [yY] || "$1" == [yY][eE][sS] ]]; }
pull_setup() {
  [[ ${WEAVEFTPD_SETUP_PULL:-always} == never ]] || docker pull "$image"
}
usage() {
  echo 'Usage: bash docker/setup.sh [--slave-cert NAME]'
  echo 'Guide: https://github.com/WeaveFTPd/WeaveFTPd/blob/main/docker/QUICKSTART.md'
}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'This deploy pack currently requires a Linux x86_64 Docker host.' >&2; exit 1
fi
if ! docker info >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo 'Docker Engine must be running, with the Docker Compose v2 plugin installed.' >&2; exit 1
fi
if [[ ${1:-} == --slave-cert ]]; then
  [[ $# == 2 ]] || { usage; exit 1; }
  ask slave_ip "Remote slave public IPv4 address"
  cert="$deploy/runtime/master/etc/certs/ca.crt"
  [[ -f $cert ]] || { echo 'This installation has no generated master CA.' >&2; exit 1; }
  cert_owner="$(stat -c %u "$cert"):$(stat -c %g "$cert")"
  pull_setup
  docker run --rm --network none --user "$cert_owner" --mount "type=bind,src=$deploy,dst=/output" \
    --entrypoint weaveftpd-setup "$image" --issue-slave "$2" --slave-ip "$slave_ip"
  exit
elif [[ $# != 0 ]]; then usage; exit 1; fi

printf '\nWeaveFTPd Docker setup\nMaster includes a separate local storage slave. IRC is optional.\n\n'
ask role 'Install master + local slave, or a remote slave? (master/slave)' master
[[ $role == master || $role == slave ]] || { echo 'Choose master or slave.' >&2; exit 1; }
if [[ -e $deploy/$role.env || -e $deploy/runtime/$role ]]; then
  printf '\nExisting %s installation detected. No files have been changed.\n' "$role"
  printf 'Manage it with the commands in docker/QUICKSTART.md. Stop transfers before updates/restarts.\n'
  exit 0
fi
ask public_ip 'Public IPv4 address advertised to FTP clients'
ask site_path 'Absolute host directory for FTP files' "$deploy/runtime/$role/site"
[[ $site_path == /* && $site_path != *$'\n'* && $site_path != *$'\r'* ]] || { echo 'An absolute path is required.' >&2; exit 1; }
ask timezone 'Timezone' UTC
ask control_port 'Master/slave control TCP port' 1099
ask pasv_min 'Passive data ports: first' 30000
ask pasv_max 'Passive data ports: last' 30100
printf '\nContainer filesystem identity (0:0 = root for storage compatibility).\nAn existing storage tree is never recursively chowned.\n'
ask uid 'Container UID' 0
ask gid 'Container GID' 0
sections= admin= password= admin_ip= ftp_port= irc_host= irc_port=6697 irc_nick=WeaveBot irc_channel= irc_password= fish_key= master_host= slave_name= bundle=
if [[ $role == master ]]; then
  ask ftp_port 'FTP control TCP port' 21212
  ask sections 'Sections (comma-separated, no spaces)' TEST
  ask admin 'New administrator username' admin
  ask admin_ip 'Trusted administrator source IP (as seen by this server)'
  secret password 'New administrator password (12..72 bytes)'
  secret confirm 'Confirm password'
  [[ $password == "$confirm" ]] || { echo 'Passwords do not match.' >&2; exit 1; }
  unset confirm
  ask enable_irc 'Configure and start IRC announcements? (yes/no)' no
  if yes "$enable_irc"; then
    ask irc_host 'IRC server (TLS with certificate verification)'
    [[ -n $irc_host ]] || { echo 'IRC server is required.' >&2; exit 1; }
    ask irc_port 'IRC TLS port' 6697
    ask irc_nick 'Bot nickname' WeaveBot
    ask irc_channel 'Main channel (also creates -chat and -staff routes)' '#weaveftpd'
    secret irc_password 'IRC server password (empty if none)'
    secret fish_key 'FiSH channel key (empty for unencrypted announcements)'
  fi
else
  ask master_host 'Master address (must match its TLS certificate; use its public IPv4)'
  ask slave_name 'Unique slave name (not LOCAL)' SLAVE1
  ask bundle 'Absolute path to certificate bundle containing ca.crt, client.crt, client.key'
  [[ $bundle == /* && -d $bundle ]] || { echo 'Certificate bundle directory is missing.' >&2; exit 1; }
fi
printf '\nRole: %s\nPublic IP: %s\nStorage: %s\nContainer identity: %s:%s\nPassive ports: %s-%s\n' "$role" "$public_ip" "$site_path" "$uid" "$gid" "$pasv_min" "$pasv_max"
printf 'Image: %s\nTLS: required for FTP; mutual TLS on the slave control link.\n' "$image"
ask proceed 'Create this NEW installation? (yes/no)' yes
yes "$proceed" || exit 0
pull_setup
# Keep the runtime parent owned by the host operator, not the setup container.
mkdir -p -- "$deploy/runtime"

mounts=(--mount "type=bind,src=$repo,dst=/source,readonly" --mount "type=bind,src=$deploy,dst=/output")
[[ $role != slave ]] || mounts+=(--mount "type=bind,src=$bundle,dst=/bundle,readonly")
# Passwords travel through stdin, never command arguments or environment.
{
  for key in role public_ip ftp_port control_port pasv_min pasv_max site_path admin password admin_ip timezone uid gid irc_host irc_port irc_nick irc_channel irc_password fish_key master_host slave_name sections; do
    printf '%s=%s\0' "$key" "${!key}"
  done
  printf 'image=%s\0sitebot_image=%s\0bundle=%s\0' "$image" "$sitebot_image" "${bundle:+/bundle}"
} | docker run --rm -i --network none --user 0:0 "${mounts[@]}" --entrypoint weaveftpd-setup "$image"
unset password irc_password fish_key

# Create/chown only a newly created site directory; existing storage is untouched.
if [[ ! -e $site_path ]]; then
  mkdir -p -- "$site_path"
  if ! chown "$uid:$gid" -- "$site_path"; then
    echo "Set the owner of $site_path to $uid:$gid before starting." >&2; exit 1
  fi
fi
[[ -d $site_path ]] || { echo 'Storage is not a directory.' >&2; exit 1; }
cd -- "$deploy"
file=master-sitebot.compose.yml
[[ $role == master ]] || file=slave.compose.yml
compose=(docker compose --env-file "$role.env" -f "$file")
"${compose[@]}" config --quiet
# This also catches read-only mounts / wrong ownership before starting services.
section_names=()
[[ -z $sections ]] || IFS=, read -r -a section_names <<< "$sections"
"${compose[@]}" run --rm --no-deps --entrypoint sh "$([[ $role == master ]] && echo local-slave || echo slave)" \
  -ec 'probe=$(mktemp /app/site/.weaveftpd-write-check.XXXXXX); rm -- "$probe"; for section; do mkdir -p -- "/app/site/$section"; done' -- "${section_names[@]}" >/dev/null
printf '\nSettings: %s/runtime/%s\n' "$deploy" "$role"
if [[ $role == master ]]; then
  printf 'Trust runtime/master/etc/certs/ca.crt in your FTPS client. Login: %s on port %s.\n' "$admin" "$ftp_port"
  printf 'Sections created: %s. Upload release directories underneath them.\n' "$sections"
fi
printf 'Open only the required FTP/passive ports in your firewall; restrict the control port to slave IPs.\n'
ask start 'Start the containers now? (yes/no)' yes
if yes "$start"; then
  "${compose[@]}" pull
  "${compose[@]}" up -d
  "${compose[@]}" ps
  printf '\nContainers started. Check logs and make a test transfer; startup is not a transfer health check.\n'
else
  printf 'Start later: cd %q && docker compose --env-file %q -f %q up -d\n' "$deploy" "$role.env" "$file"
fi
