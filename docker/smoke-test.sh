#!/usr/bin/env bash
# Run on a Linux Docker host. All mutable state is confined to a temp directory.
set -euo pipefail
image=${1:?Usage: bash docker/smoke-test.sh IMAGE}
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
project="weaveftpd-smoke-$$"
export WEAVEFTPD_IMAGE="$image"
export WEAVEFTPD_RUNTIME="$scratch/source/docker/deploy/runtime/master"
export WEAVEFTPD_SITE_PATH="$WEAVEFTPD_RUNTIME/site"
export WEAVEFTPD_UID=0 WEAVEFTPD_GID=0
compose=(docker compose -p "$project" -f "$repo/docker/deploy/master-sitebot.compose.yml" -f "$scratch/override.json")

cleanup() {
  result=$?
  if [ "$result" -ne 0 ] && [ -f "$scratch/override.json" ]; then
    "${compose[@]}" logs --no-color master local-slave || true
  fi
  if [ -f "$scratch/override.json" ]; then
    "${compose[@]}" down --remove-orphans || true
  fi
  rm -rf -- "$scratch"
  exit "$result"
}
trap cleanup EXIT

mkdir -p "$scratch/source"
git -C "$repo" archive HEAD etc plugins sitebot docker/deploy | tar -x -C "$scratch/source"
sh "$scratch/source/docker/deploy/init.sh" master
# Rerunning initialization must preserve existing authentication data.
printf '%s\n' '# CI: preserve existing authentication data' >> "$WEAVEFTPD_RUNTIME/etc/passwd"
cp "$WEAVEFTPD_RUNTIME/etc/passwd" "$scratch/passwd.expected"
sh "$scratch/source/docker/deploy/init.sh" master
cmp "$scratch/passwd.expected" "$WEAVEFTPD_RUNTIME/etc/passwd"

python3 - "$WEAVEFTPD_RUNTIME" "$scratch/override.json" "$project" <<'PY'
import json, sys
from pathlib import Path
runtime, override, project = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
common = dict(timezone='UTC', tls_enabled=True,
              tls_cert='/app/etc/certs/server.crt', tls_key='/app/etc/certs/server.key',
              log_console=True, debug=True, free_space_mb=0)
master = dict(common, mode='master', storage_path='/app/site', acl_base_path='/',
              rootpath='/', datapath='/app/userdata', passwd_file='/app/etc/passwd',
              msg_path='/app/etc/msgs', listen_port=22121, public_ip='127.0.0.1',
              pasv_min=42121, pasv_max=42129, passthrough=True,
              require_tls_control=True, require_tls_data=True,
              max_users=16, max_users_per_ip=16, max_connections=16,
              sections=['SMOKE'], master=dict(listen_host='127.0.0.1', control_port=21099,
              slave_masks_file='etc/slave_masks.txt', remerge_mode='off'))
slave = dict(common, mode='slave', slave=dict(name='LOCAL', master_host='127.0.0.1',
             master_port=21099, roots=['/app/site'], bind_ip='127.0.0.1',
             pasv_port_min=42130, pasv_port_max=42139))
# JSON is valid YAML; no Python YAML package is required on the runner.
(runtime/'etc/config.yml').write_text(json.dumps(master))
(runtime/'etc/config-slave-local.yml').write_text(json.dumps(slave))
(runtime/'site/SMOKE/Container.Test-GRP').mkdir(parents=True, exist_ok=True)
# The bundled siteop has flag 1 only. Give this isolated test fixture download
# access (flag 3) and ratio 0 so payload verification does not depend on credits.
userfile = runtime/'etc/users/weaveftpd'
record = userfile.read_text()
assert 'FLAGS 1\n' in record and 'RATIO 3\n' in record
userfile.write_text(record.replace('FLAGS 1\n', 'FLAGS 13\n').replace('RATIO 3\n', 'RATIO 0\n'))
override.write_text(json.dumps(dict(services={
    'master': dict(container_name=project+'-master'),
    'local-slave': dict(container_name=project+'-slave'),
    'sitebot': dict(container_name=project+'-sitebot')})))
PY

# The standard deploy must include its local slave without selecting a profile.
"${compose[@]}" config --format json > "$scratch/compose.json"
python3 - "$scratch/compose.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))['services']
assert not s['local-slave'].get('profiles'), 'local slave must start by default'
assert s['master']['image'] == s['local-slave']['image'], 'both roles must use the same image'
PY
"${compose[@]}" up -d master local-slave

python3 - "$WEAVEFTPD_RUNTIME" <<'PY'
import ftplib, io, ssl, sys, time, zlib
from pathlib import Path
runtime = Path(sys.argv[1])
context = ssl._create_unverified_context()  # Isolated loopback fixture certificate.
class WeaveFTP(ftplib.FTP_TLS):
    def ntransfercmd(self, cmd, rest=None):
        # Route the data command to a slave before opening its passive socket.
        self.voidcmd('PRET ' + cmd)
        return super().ntransfercmd(cmd, rest)

deadline = time.monotonic() + 90
last_error = None
while time.monotonic() < deadline:
    ftp = WeaveFTP(context=context, timeout=5)
    try:
        ftp.connect('127.0.0.1', 22121)
        ftp.login('weaveftpd', 'weaveftpd')
        ftp.prot_p()
        ftp.cwd('/SMOKE/Container.Test-GRP')
        ftp.nlst()  # Requires the storage slave to be connected and ready.
        break
    except (OSError, ftplib.Error) as exc:
        last_error = exc
        ftp.close()
        time.sleep(1)
else:
    raise RuntimeError(f'Master/slave did not become ready: {last_error}')

payload = b'WeaveFTPd container TLS transfer test\n' * 8192
sfv = f'container-smoke.bin {zlib.crc32(payload):08X}\n'.encode()
ftp.storbinary('STOR container-smoke.sfv', io.BytesIO(sfv))
ftp.storbinary('STOR container-smoke.bin', io.BytesIO(payload))
received = io.BytesIO()
ftp.retrbinary('RETR container-smoke.bin', received.write)
assert received.getvalue() == payload, 'download differs from upload'
assert (runtime/'site/SMOKE/Container.Test-GRP/container-smoke.bin').read_bytes() == payload
assert 'container-smoke.bin' in ftp.nlst()
ftp.delete('container-smoke.bin')
ftp.delete('container-smoke.sfv')
ftp.quit()
assert not (runtime/'site/SMOKE/Container.Test-GRP/container-smoke.bin').exists(), 'delete did not reach the slave'
print('PASS: shared image, default local slave, FTP TLS login/list/upload/download/delete')
PY
