# Master-Slave Authentication

WeaveFTPd authenticates every slave control connection. Choose one of these
methods before starting or upgrading a master/slave deployment:

1. mTLS (recommended): the master verifies a CA-signed client certificate and
   requires its Common Name to match `slave.name` exactly.
2. Per-slave IP masks: when mTLS is disabled, the connecting address must match
   a mask registered for the claimed slave name.

A slave with neither a valid client certificate nor a matching mask is refused.
The global `master.slave_allowlist` and denylist remain additional network
filters; they do not replace per-slave authentication.

## mTLS Setup

On the master, generate a CA and a server certificate. Include every hostname
or IP address that slaves use for `slave.master_host` when prompted:

```bash
./setup.sh certs "My Site"
./setup.sh slavecert SLAVE1
./setup.sh slavecert SLAVE2
```

Configure the master:

```yaml
master:
  slave_ca_cert: "./etc/certs/ca.crt"
```

For each slave, securely copy the master's `ca.crt` as `master-ca.crt`, plus
only that slave's certificate and private key. Using a separate filename avoids
overwriting a CA that the slave may use for its own client-facing data TLS
certificate. Configure paths under its `slave:` block:

```yaml
slave:
  name: "SLAVE1"
  master_host: "master.example.net"
  master_ca_cert: "./etc/certs/master-ca.crt"
  client_cert: "./etc/certs/slave-SLAVE1.crt"
  client_key: "./etc/certs/slave-SLAVE1.key"
```

The server certificate must contain `master.example.net` in its Subject
Alternative Name. The client certificate CN must equal `SLAVE1`. Do not share
one client certificate between slaves.

Changing `master.slave_ca_cert` or replacing its CA file requires a master restart. `SITE REHASH` can
reload mask files and other slave policy, but cannot replace authentication on
an already-running TLS listener.

## IP Mask Setup

Leave `master.slave_ca_cert`, `slave.master_ca_cert`, `slave.client_cert`, and
`slave.client_key` empty. Then register every slave on the master:

```text
SITE SLAVE SLAVE1 ADDMASK 203.0.113.10/32
SITE SLAVE SLAVE2 ADDMASK 2001:db8:10::/64
SITE SLAVE SLAVE1 MASKS
SITE SLAVE MASKS
```

Bare IPv4/IPv6 addresses, CIDR blocks, and IPv4 wildcard masks such as
`203.0.113.*` are accepted. Masks are persisted in
`master.slave_masks_file`, defaulting to `etc/slave_masks.txt`.

You can seed masks in the master config on first startup:

```yaml
slaves:
  - name: "SLAVE1"
    masks: ["203.0.113.10/32"]
```

After that slave name has persisted masks, `SITE SLAVE ... ADDMASK/DELMASK` is
authoritative and later config changes do not overwrite them.

## TLS Verification Boundaries

TLS encryption and certificate verification are separate protections. An
`insecure` setting still encrypts traffic, but it accepts any certificate and
therefore does not authenticate the remote peer.

- Sitebot defaults to `irc.tls_verify: strict`. Use `custom` and
  `irc.tls_ca_cert` for a private IRC CA. `insecure` remains available as an
  explicit compatibility setting, with a startup warning.
- A slave with `slave.master_ca_cert` verifies the master's certificate. If it
  is empty, the legacy IP-mask setup still encrypts the control connection but
  does not authenticate the master. An IP mask only authenticates the slave to
  the master; it is not a replacement for master certificate verification.
- Active/passive SSCN and CPSV `PROT P` FXP and slave-to-slave outbound data connections use a
  compatibility TLS client that does not verify a peer certificate. Those data
  channels are encrypted but not certificate-authenticated. Keep FXP peers
  trusted and use mTLS for the independent master/slave control link.

WeaveFTPd intentionally keeps these compatibility modes for existing sites.
New deployments should use strict/custom verification for IRC and mTLS for
master/slave control connections.

## Secure FXP data-channel roles

With `PROT P`, `SSCN ON` makes STOR/RETR use the TLS client role for both
PASV and PORT. `SSCN OFF` restores the TLS server role. The peer must use the
opposite role. SSCN remains set until changed by the client; CPSV selects
TLS client mode for its next passive connection without changing SSCN.
Directory listings retain their normal TLS behavior after an FXP transfer.
Completed TLS-client downloads send close_notify and briefly drain pending
TLS 1.3 session tickets before closing TCP, so the final file bytes are retained.
This applies to direct slave transfers and file transfers through the proxy backend.

Run `tests/fxp_tls_roles.py STAGE` in an isolated Linux network namespace
(the same setup as `tests/live_downloads.py`). It covers TLS 1.2 and 1.3,
PASV/PORT/CPSV uploads and downloads, live uploads, persistent SSCN, REST, listings, and
clear data after PROT C. STAGE must contain the built `weaveftpd.candidate`.

## Upgrade Checklist

Before restarting an existing deployment with this version:

- configure mTLS on the master and every slave, or add a mask for every slave;
- add `SLAVE` to the siteop `sitecmd` allow rule in an existing custom
  `etc/permissions.yml` before using the new SITE commands;
- make sure mTLS server certificate SANs match each `slave.master_host` value;
- restart the master after changing `master.slave_ca_cert`;
- set sitebot `irc.tls_verify` to `strict`, `custom`, or explicitly `insecure`.

You can seed masks before the new daemon is running by creating
`etc/slave_masks.txt` manually:

```text
SLAVE1 203.0.113.10/32
SLAVE2 2001:db8:10::/64
```

Sitebot now verifies IRC TLS certificates by default. Use `custom` plus
`irc.tls_ca_cert` for a private IRC CA. `insecure` preserves the old behavior
but does not authenticate the IRC server; it still encrypts the IRC connection.
