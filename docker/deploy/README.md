# Docker deployment

The standard installation runs a master, local storage slave, and IRC sitebot
on a Linux amd64 Docker host. Master and slave are separate containers made
from the **same** `ghcr.io/weaveftpd/weaveftpd` image; `mode` in each config
selects the role. The slave is started by Compose together with the master.

## First installation

From a checkout of this repository:

```bash
cd docker/deploy
sh init.sh master
```

The initializer creates `runtime/master/`, config copies, a TLS certificate
(requires `openssl` on the host), and the `LOCAL 127.0.0.1` slave mask. Review:

- `runtime/master/etc/config.yml`: public IP, FTP ports and master settings.
- `runtime/master/etc/config-slave-local.yml`: slave public IP and passive ports.
- `runtime/master/sitebot/etc/config.yml`: IRC server and announce channels.
- `master.env`: image tags, host storage path and container UID/GID.

Change the bundled `weaveftpd` / `weaveftpd` example login before public use.

Start all three services:

```bash
docker compose --env-file master.env -f master-sitebot.compose.yml up -d
docker compose --env-file master.env -f master-sitebot.compose.yml logs -f
```

To run just the master and local slave without IRC:

```bash
docker compose --env-file master.env -f master-sitebot.compose.yml up -d master local-slave
```

The slave connects to `127.0.0.1:1099`. Host networking preserves FTP passive
ports, advertised addresses and FXP peer addresses. Set the public addresses
in both daemon configs, and allow the configured FTP/passive ports through
the host firewall (and NAT where applicable).

## Images and automatic publishing

| Image | Role |
|-------|------|
| `ghcr.io/weaveftpd/weaveftpd` | Master or slave daemon |
| `ghcr.io/weaveftpd/weaveftpd-sitebot` | IRC sitebot |

The Docker images workflow runs on pushes to `main` / `dev`, version tags
starting with `v`, pull requests and manual dispatch. It builds both images,
tests a master/slave TLS upload/download and checks the sitebot executable.
Only successful builds on push or manual dispatch are published, using the
repository's `GITHUB_TOKEN`; no Docker Hub password or extra PAT is needed.

| Tag | Source |
|-----|--------|
| `latest`, `main` | Latest successful `main` build |
| `dev` | Latest successful `dev` build |
| `v1.3.0`, `1.3.0`, `1.3` | Example `v1.3.0` release tag |
| `sha-<full-commit>` | Specific source commit |

Both daemon roles should use the same image version. Use the tags in
`master.env` and `slave.env` to pin versions. For forks, the workflow publishes
under the fork owner's lowercase GHCR namespace; change the image names in
the env files accordingly. New GHCR packages initially follow GitHub's
package visibility settings; make both packages public in their package
settings for anonymous pulls, or authenticate with `docker login ghcr.io`.

Existing env files are never overwritten by `init.sh`. Change local image
names there to the GHCR names when adopting published images.

## Remote slave host

A remote slave uses the same daemon image, with only its slave config:

```bash
cd docker/deploy
MASTER_HOST="203.0.113.10" SLAVE_NAME="SLAVE1" sh init.sh slave
```

Edit `runtime/slave/etc/config.yml` and `slave.env`. Register its source
address on the master before starting:

```text
SITE SLAVE SLAVE1 ADDMASK 203.0.113.20/32
```

```bash
docker compose --env-file slave.env -f slave.compose.yml up -d
docker compose --env-file slave.env -f slave.compose.yml logs -f
```

For mTLS, follow [Master-Slave Authentication](../../docs/Master-Slave-TLS.md),
install the CA and slave certificate/key in the slave's `etc/certs`, and set
the three certificate paths. Enabling `master.slave_ca_cert` requires a valid
client certificate from every slave.

A master host backed entirely by remote slaves can start `master sitebot`
explicitly to omit the local slave. At least one storage slave is needed.

## Updating

Wait until transfers are idle before recreating containers:

```bash
docker compose --env-file master.env -f master-sitebot.compose.yml pull
docker compose --env-file master.env -f master-sitebot.compose.yml up -d
```

On a remote slave:

```bash
docker compose --env-file slave.env -f slave.compose.yml pull
docker compose --env-file slave.env -f slave.compose.yml up -d
```

Publishing new images does not automatically restart running servers. Runtime
data stays in the bind-mounted `runtime/` directories and configured site path.

## Local builds

From the repository root:

```bash
docker build --target daemon -t weaveftpd:local .
docker build --target sitebot -t weaveftpd-sitebot:local .
```

Set the corresponding image names in `master.env` / `slave.env`, then use the
same deploy commands. The root `docker-compose.yml` also supports local builds:
`docker compose up -d --build` starts master and slave; add `--profile sitebot`
before `up` for the bot. Configure root `etc/` paths and certificates first,
or use the initialized deploy pack above.

## FIFO and permissions

The sitebot runs on the master host and reads `/app/etc/weaveftpd.sitebot.fifo`.
Both containers mount the same host `etc` directory. A FIFO cannot connect
containers on different machines.

Compose defaults to UID/GID 0 for existing file ownership. To use another
UID/GID, set `WEAVEFTPD_UID` / `WEAVEFTPD_GID` and make all runtime mounts
writable by that identity. An individual image defaults to the unprivileged
`weaveftpd` user. Keep real credentials, certificates and data in runtime
mounts; the images contain binaries, CA certificates and timezone data.
