# Docker quickstart

Run this on a **Linux x86_64 server** with Docker Engine, the **Compose v2
plugin**, Bash and Git installed. No Go compiler, Python or host OpenSSL is
needed. Use an account allowed to run Docker and create/chown the chosen
storage directory (normally `root`, or `sudo bash docker/setup.sh`).

## 1. Install

```bash
git clone https://github.com/WeaveFTPd/WeaveFTPd.git
cd WeaveFTPd
bash docker/setup.sh
```

Choose **master** for a complete server. The wizard asks for:

- Public IPv4 address, FTP port, slave control port and passive port range.
- Absolute host path for FTP files and timezone.
- Container UID/GID. `0:0` runs as root for filesystem compatibility; choose a
  dedicated host UID/GID if you prefer. That identity must have read/write
  access to existing storage. Existing storage is never recursively chowned.
- Section names (comma-separated; default `TEST`). These directories are created in storage.
- Your own administrator username, password and trusted login source IP.
  Use the IP the server sees, usually your public IP. Passwords are entered
  invisibly. There is **no preset FTP login** in this installer.
- Optional IRC server, bot nickname, channel, server password and FiSH key.
  IRC uses TLS with certificate verification. For a private IRC CA, configure
  `tls_verify: custom` and `tls_ca_cert` before enabling the bot.

Review the choices, then choose whether to start immediately. The wizard runs
the setup helper from the published daemon image, generates new certificates,
and writes configuration under `docker/deploy/runtime/`. It refuses to replace
an existing runtime or env file. Rerunning it does not reset accounts, settings
or certificates and does not restart existing containers.

The default download is `:latest` (tested `main`). For development builds,
check out `dev` and run:

```bash
WEAVEFTPD_SETUP_IMAGE=ghcr.io/weaveftpd/weaveftpd:dev \
WEAVEFTPD_SETUP_SITEBOT_IMAGE=ghcr.io/weaveftpd/weaveftpd-sitebot:dev \
  bash docker/setup.sh
```

Both images are public; no registry token is needed. Publishing a new image
does not update or restart your running installation.

## 2. What starts?

| Container | Image | Purpose |
|---|---|---|
| `weaveftpd-master` | `ghcr.io/weaveftpd/weaveftpd:latest` | FTP login, metadata, users and rules |
| `weaveftpd-local-slave` | Same daemon image | Storage and data transfers |
| `weaveftpd-sitebot` | `ghcr.io/weaveftpd/weaveftpd-sitebot:latest` | Optional IRC announcements |

Master and slave are **separate processes/containers** started together by
Compose. The master does not start a slave internally. One daemon image serves
both roles. Downloading an image with `docker pull` alone does not configure
or start the service; use this checkout's installer and Compose files.

The image has an unprivileged OS service account, but Compose uses the UID/GID
you selected. There is no SSH server, Docker socket mount or privileged mode.
The runtime contains only the administrator you chose and a template for future
users. The FTP administrator has siteop, download, nuke/unnuke flags and ratio 0;
this is a virtual FTP account, not a new Linux login.

## 3. Firewall and first connection

This pack uses **host networking**. There are no Docker port mappings:

- Allow your chosen FTP control port (default TCP **21212**) to FTP clients.
- Allow the passive TCP range (default **30000–30100**) to FTP/FXP peers on
  each storage slave. Behind NAT, forward these ports and advertise the public
  IPv4 address; adjust `slave.local_bind_ip` if you need a specific LAN interface.
- Restrict the slave control port (default TCP **1099**) to your slave IPs.
  Master/slave control uses mutual TLS; each slave gets its own certificate.
- Outbound IRC access is needed only when the bot is enabled.

In an FTPS client, select **explicit TLS**, your server IP, FTP port and chosen
administrator login. TLS is required for control and data. Trust
`docker/deploy/runtime/master/etc/certs/ca.crt` in the client, or verify the
certificate fingerprint through a trusted channel. The generated server
certificate covers the public IPv4 address and localhost; using another DNS
name requires a matching replacement certificate. Certificates expire after
five years; replace/renew them before expiry.

Upload releases underneath a section selected during setup, such as
`/TEST/Example.Release-GRP`. To add sections later, configure them in
`etc/config.yml` and reload the master (or create directories and run SITE REMERGE). FXP clients should use PRET to select a slave
before the passive data connection.

Check startup and make an upload/download test:

```bash
cd docker/deploy
docker compose --env-file master.env -f master-sitebot.compose.yml ps
docker compose --env-file master.env -f master-sitebot.compose.yml logs --tail=100 master local-slave
```

If login is rejected, check the account's source IP in
`runtime/master/etc/users/<username>`. If data transfers fail, check the passive
range, public IP, firewall and slave logs. A running container alone does not
prove that external FTP/FXP networking works.

## 4. Settings and persistent data

All paths below are relative to `docker/deploy/`:

| Path | Edit / back up |
|---|---|
| `master.env` | Image versions, runtime path, storage path, UID/GID, optional `COMPOSE_PROFILES=sitebot` |
| `runtime/master/etc/config.yml` | Master settings, sections, zipscript and plugins |
| `runtime/master/etc/config-slave-local.yml` | Local slave IP, passive ports, TLS and storage |
| `runtime/master/etc/permissions.yml` | FTP access rules |
| `runtime/master/etc/passwd`, `users/`, `group`, `groups/` | FTP accounts, password hashes, groups |
| `runtime/master/etc/certs/` | Private CA, TLS keys and certificates; protect and back up securely |
| `runtime/master/userdata/` | Persistent databases/state |
| `runtime/master/sitebot/etc/config.yml` | IRC connection, channels and FiSH |
| `runtime/master/sitebot/plugins/announce/config.yml` | Announce routing; speedtests go to `-chat` |
| Selected storage path | Actual FTP files |

Generated YAML contains effective defaults; consult
[`etc/config-example.yml`](../etc/config-example.yml) for annotated options.
The wizard initially enables the daemon speedtest plugin and the optional
bot's announce plugin. Automatic deletion, slow-transfer kicks, external
metadata lookups and IRC administration plugins require deliberate setup.
Bot FTP command plugins do not receive a preset privileged account.

Manage FTP users through SITE commands after logging in. Edit advanced YAML
on the host, then reload/restart as appropriate. Wait for transfers to finish
before restarting. Container replacement preserves bind-mounted state.
`docker compose down` stops containers; do not delete runtime/storage folders.

## 5. Add a slave on a second machine

On the **master machine**, issue a unique client certificate:

```bash
cd /path/to/WeaveFTPd
bash docker/setup.sh --slave-cert REMOTE1
```

Enter the remote slave's public IPv4 when prompted (included in its data-TLS certificate).
Securely copy **only** the generated
`docker/deploy/runtime/master/slave-certs/REMOTE1/` directory to the remote
machine, for example `/root/REMOTE1/`. It contains `ca.crt`, `client.crt` and
`client.key`. **Never copy the master CA private key (`ca.key`).** Restrict
the bundle's permissions and treat it as a credential.

Clone this repository on the slave and run `bash docker/setup.sh`. Choose
**slave**, enter its public IP/storage/ports, the master's public IPv4 and
control port, the name `REMOTE1`, and the bundle path. The name must match the
certificate. Open the master's control firewall to that slave and the slave's
passive ports to FTP clients. This machine runs only the slave container.
For existing masters, configure mTLS first as described in the annotated
config; the wizard's certificate command requires its generated master CA.

Remote slave management:

```bash
cd docker/deploy
docker compose --env-file slave.env -f slave.compose.yml logs --tail=100
```

## 6. Update safely

First wait until uploads/downloads are idle. Back up runtime directories and
storage. From the checkout, fetch updated Compose/scripts, then pull and
recreate containers:

```bash
git pull --ff-only
cd docker/deploy
docker compose --env-file master.env -f master-sitebot.compose.yml pull
docker compose --env-file master.env -f master-sitebot.compose.yml up -d
docker compose --env-file master.env -f master-sitebot.compose.yml logs --tail=100
```

On remote slaves use `--env-file slave.env -f slave.compose.yml` instead.
Pin `WEAVEFTPD_IMAGE` and `WEAVEFTPD_SITEBOT_IMAGE` in the env file to a
`sha-<full-commit>` tag or digest for a fixed version and rollback.
Keep both roles on the same daemon version. Do not rerun an initialization
script to update an existing installation.

If setup stopped after writing a runtime (for example due to storage
permissions), correct that issue and use the Compose commands above; the
wizard intentionally refuses to overwrite that runtime. An interrupted setup
may leave `.setup.lock`; inspect that no installer is running before removing
only that lock. See the [manual deploy guide](deploy/README.md) for advanced
layouts and local image builds.
