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
    docker logs "$project-remote" 2>/dev/null || true
  fi
  if [ -f "$scratch/override.json" ]; then
    "${compose[@]}" down --remove-orphans || true
  fi
  docker rm -f "$project-remote" >/dev/null 2>&1 || true
  rm -rf -- "$scratch"
  exit "$result"
}
trap cleanup EXIT

mkdir -p "$scratch/source"
git -C "$repo" archive HEAD etc plugins sitebot docker | tar -x -C "$scratch/source"
export WEAVEFTPD_SETUP_IMAGE="$image"
export WEAVEFTPD_SETUP_PULL=never
export WEAVEFTPD_UID=$(id -u) WEAVEFTPD_GID=$(id -g)
# Exercise the actual interactive wizard with a custom account and non-root
# filesystem identity. No generated configs are replaced with test fixtures.
printf '%s\n' master 127.0.0.1 "$WEAVEFTPD_SITE_PATH" UTC 21099 42130 42139 \
  "$WEAVEFTPD_UID" "$WEAVEFTPD_GID" 22121 TEST SmokeAdmin 127.0.0.1 \
  'Smoke test password 42!' 'Smoke test password 42!' no yes no | \
  bash "$scratch/source/docker/setup.sh"
printf '%s\n' '# preserve custom settings on rerun' >> "$WEAVEFTPD_RUNTIME/etc/config.yml"
find "$WEAVEFTPD_RUNTIME" -type f -exec sha256sum {} + | sort > "$scratch/before.sha"
printf 'master\n' | bash "$scratch/source/docker/setup.sh"
find "$WEAVEFTPD_RUNTIME" -type f -exec sha256sum {} + | sort > "$scratch/after.sha"
cmp "$scratch/before.sha" "$scratch/after.sha"
test ! -f "$WEAVEFTPD_RUNTIME/etc/users/weaveftpd"

python3 - "$WEAVEFTPD_RUNTIME" "$scratch/override.json" "$project" <<'PY'
import json, sys
from pathlib import Path
runtime, override, project = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
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

cat > "$scratch/transfer.py" <<'PY'
import ftplib, io, ssl, sys, time, zlib
from pathlib import Path
runtime = Path(sys.argv[1])
context = ssl.create_default_context(cafile=str(runtime/'etc/certs/ca.crt'))
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
        ftp.login('SmokeAdmin', 'Smoke test password 42!')
        ftp.prot_p()
        ftp.cwd('/TEST')
        try:
            ftp.mkd('Container.Test-GRP')
        except ftplib.error_perm as exc:
            if not str(exc).startswith('550'):
                raise
        ftp.cwd('Container.Test-GRP')
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
assert (runtime/'site/TEST/Container.Test-GRP/container-smoke.bin').read_bytes() == payload
assert 'container-smoke.bin' in ftp.nlst()
ftp.delete('container-smoke.bin')
ftp.delete('container-smoke.sfv')
ftp.quit()
assert not (runtime/'site/TEST/Container.Test-GRP/container-smoke.bin').exists(), 'delete did not reach the slave'
print('PASS: interactive installer, preserved settings, custom admin, non-root containers, mutual TLS, FTP TLS login/list/upload/download/delete')
PY

python3 "$scratch/transfer.py" "$WEAVEFTPD_RUNTIME"

# Verify the remote-slave branch of the wizard and its issued certificate too.
printf '127.0.0.1\n' | bash "$scratch/source/docker/setup.sh" --slave-cert REMOTE1
remote="$scratch/source/docker/deploy/runtime/slave"
printf '%s\n' slave 127.0.0.1 "$remote/site" UTC 21099 42200 42209 \
  "$WEAVEFTPD_UID" "$WEAVEFTPD_GID" 127.0.0.1 REMOTE1 \
  "$WEAVEFTPD_RUNTIME/slave-certs/REMOTE1" yes no | \
  bash "$scratch/source/docker/setup.sh"
mkdir -p "$remote/site/TEST/Container.Test-GRP"
"${compose[@]}" stop local-slave
docker run -d --name "$project-remote" --network host \
  --user "$WEAVEFTPD_UID:$WEAVEFTPD_GID" \
  --mount "type=bind,src=$remote/etc,dst=/app/etc" \
  --mount "type=bind,src=$remote/site,dst=/app/site" \
  --mount "type=bind,src=$remote/logs,dst=/app/logs" "$image"
python3 "$scratch/transfer.py" "$remote"
echo 'PASS: remote slave wizard, issued certificate, TLS upload/download/delete'
