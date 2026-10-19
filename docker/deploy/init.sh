#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  ./init.sh master
  MASTER_HOST=203.0.113.10 SLAVE_NAME=SLAVE1 ./init.sh slave

Run from docker/deploy in a WeaveFTPd checkout.
EOF
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

role="$1"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

copy_file_if_missing() {
  copy_src="$1"
  copy_dst="$2"
  if [ ! -e "$copy_dst" ]; then
    mkdir -p "$(dirname "$copy_dst")"
    cp "$copy_src" "$copy_dst"
  fi
}

seed_master_passwd() {
  file="$1"
  # Only seed a new runtime. Never replace existing accounts or passwords.
  [ ! -e "$file" ] || return 0
  mkdir -p "$(dirname "$file")"
  # The repository's passwd hash may have changed independently of the example
  # account. A fresh Docker runtime must match the documented bootstrap login.
  sed 's#^weaveftpd:[^:]*:#weaveftpd:$2a$10$j1eCJxNq56qpLSP3FQNvlOCYeM9s9L9I71qhhh1i/xzazV4Z4G8UK:#' \
    "$repo_root/etc/passwd" > "$file"
  chmod 600 "$file"
}

copy_dir_if_missing() {
  copy_src="$1"
  copy_dst="$2"
  if [ ! -e "$copy_dst" ]; then
    mkdir -p "$(dirname "$copy_dst")"
    cp -a "$copy_src" "$copy_dst"
  fi
}

copy_plugin_configs() {
  src_root="$1"
  dst_root="$2"
  mkdir -p "$dst_root"
  for dist in "$src_root"/*/config.yml.dist; do
    [ -e "$dist" ] || continue
    name=$(basename "$(dirname "$dist")")
    copy_file_if_missing "$dist" "$dst_root/$name/config.yml"
  done
}

patch_common_daemon_paths() {
  cfg="$1"
  sed -i \
    -e 's#^tls_cert:.*#tls_cert: "/app/etc/certs/server.crt"#' \
    -e 's#^tls_key:.*#tls_key: "/app/etc/certs/server.key"#' \
    -e 's#^log_file:.*#log_file: "/app/logs/weaveftpd.log"#' \
    "$cfg"
}

patch_master_config() {
  cfg="$1"
  patch_common_daemon_paths "$cfg"
  sed -i \
    -e 's#^mode:.*#mode:         master#' \
    -e 's#^storage_path:.*#storage_path:  "/app/site"#' \
    -e 's#^rootpath:.*#rootpath:      "/"#' \
    -e 's#^datapath:.*#datapath:      "/app/userdata"#' \
    -e 's#^acl_base_path:.*#acl_base_path: "/"#' \
    -e 's#^passwd_file:.*#passwd_file:   "/app/etc/passwd"#' \
    -e 's#^msg_path:.*#msg_path:      "/app/etc/msgs"#' \
    -e 's#^event_fifo:.*#event_fifo:     "/app/etc/weaveftpd.sitebot.fifo"#' \
    -e 's#^sitebot_config:.*#sitebot_config: "/app/sitebot/etc/config.yml"#' \
    "$cfg"
}

patch_slave_config() {
  cfg="$1"
  slave_name="${SLAVE_NAME:-LOCAL}"
  master_host="${MASTER_HOST:-127.0.0.1}"
  bind_ip="${SLAVE_BIND_IP:-}"
  patch_common_daemon_paths "$cfg"
  sed -i \
    -e 's#^mode:.*#mode: "slave"#' \
    -e 's#^log_file:.*#log_file: "/app/logs/weaveftpd-slave.log"#' \
    -e "s#  name: .*#  name: \"$slave_name\"#" \
    -e "s#  master_host: .*#  master_host: \"$master_host\"#" \
    -e 's#  master_ca_cert: .*#  master_ca_cert: ""#' \
    -e 's#  client_cert: .*#  client_cert: ""#' \
    -e 's#  client_key: .*#  client_key: ""#' \
    -e "s#  bind_ip: .*#  bind_ip: \"$bind_ip\"#" \
    -e 's#    - "\./site"#    - "/app/site"#' \
    -e 's#    - ./site#    - "/app/site"#' \
    "$cfg"
}

seed_slave_mask() {
  file="$1"
  name="$2"
  mask="$3"
  mkdir -p "$(dirname "$file")"
  if [ ! -f "$file" ]; then
    printf '%s\n' '# Per-slave IP mask allowlist: <slave name> <ip|cidr|wildcard>' > "$file"
  fi
  if ! grep -Fqx "$name $mask" "$file"; then
    printf '%s %s\n' "$name" "$mask" >> "$file"
  fi
}

patch_sitebot_config() {
  cfg="$1"
  sed -i \
    -e 's#^log_file:.*#log_file: "/app/sitebot/logs/sitebot.log"#' \
    -e 's#^event_fifo:.*#event_fifo: "/app/etc/weaveftpd.sitebot.fifo"#' \
    "$cfg"
}

make_cert_if_missing() {
  dir="$1"
  mkdir -p "$dir"
  if [ -f "$dir/server.crt" ] && [ -f "$dir/server.key" ]; then
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout "$dir/server.key" \
      -out "$dir/server.crt" \
      -subj "/CN=WeaveFTPd"
    chmod 600 "$dir/server.key"
    chmod 644 "$dir/server.crt"
  else
    echo "WARNING: openssl not found; create $dir/server.crt and $dir/server.key before starting TLS." >&2
  fi
}

init_master() {
  dst="$script_dir/runtime/master"
  mkdir -p "$dst/etc" "$dst/plugins" "$dst/sitebot/etc" "$dst/sitebot/plugins" "$dst/sitebot/logs" "$dst/logs" "$dst/logs-local-slave" "$dst/userdata" "$dst/site"

  copy_file_if_missing "$repo_root/etc/config-example.yml" "$dst/etc/config.yml"
  copy_file_if_missing "$repo_root/etc/config-slave-example.yml" "$dst/etc/config-slave-local.yml"
  copy_file_if_missing "$repo_root/etc/permissions.yml" "$dst/etc/permissions.yml"
  copy_file_if_missing "$repo_root/etc/affils.yml" "$dst/etc/affils.yml"
  seed_master_passwd "$dst/etc/passwd"
  copy_file_if_missing "$repo_root/etc/group" "$dst/etc/group"
  copy_file_if_missing "$repo_root/etc/version" "$dst/etc/version"
  copy_dir_if_missing "$repo_root/etc/users" "$dst/etc/users"
  copy_dir_if_missing "$repo_root/etc/groups" "$dst/etc/groups"
  copy_dir_if_missing "$repo_root/etc/msgs" "$dst/etc/msgs"

  copy_plugin_configs "$repo_root/plugins" "$dst/plugins"

  copy_file_if_missing "$repo_root/sitebot/etc/config.yml.example" "$dst/sitebot/etc/config.yml"
  copy_dir_if_missing "$repo_root/sitebot/etc/templates" "$dst/sitebot/etc/templates"
  copy_plugin_configs "$repo_root/sitebot/plugins" "$dst/sitebot/plugins"

  patch_master_config "$dst/etc/config.yml"
  MASTER_HOST=127.0.0.1 SLAVE_NAME=LOCAL patch_slave_config "$dst/etc/config-slave-local.yml"
  seed_slave_mask "$dst/etc/slave_masks.txt" LOCAL 127.0.0.1
  patch_sitebot_config "$dst/sitebot/etc/config.yml"
  make_cert_if_missing "$dst/etc/certs"

  copy_file_if_missing "$script_dir/master.env.example" "$script_dir/master.env"
  echo "Master runtime created at: $dst"
  echo "Edit $dst/etc/config.yml and $dst/sitebot/etc/config.yml before production use."
}

init_slave() {
  dst="$script_dir/runtime/slave"
  mkdir -p "$dst/etc" "$dst/logs" "$dst/site"

  copy_file_if_missing "$repo_root/etc/config-slave-example.yml" "$dst/etc/config.yml"
  copy_file_if_missing "$repo_root/etc/version" "$dst/etc/version"
  patch_slave_config "$dst/etc/config.yml"
  make_cert_if_missing "$dst/etc/certs"

  copy_file_if_missing "$script_dir/slave.env.example" "$script_dir/slave.env"
  echo "Slave runtime created at: $dst"
  echo "Edit $dst/etc/config.yml and set slave.master_host to the master address."
  echo "Before starting it, allow this slave on the master:"
  echo "  SITE SLAVE ${SLAVE_NAME:-LOCAL} ADDMASK <this slave's public IP/CIDR>"
}

case "$role" in
  master) init_master ;;
  slave) init_slave ;;
  *)
    usage
    exit 1
    ;;
esac
