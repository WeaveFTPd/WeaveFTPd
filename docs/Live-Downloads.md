# Downloads during uploads

`dl_incomplete: true` lets RETR follow an upload of the same file. It defaults
to true when omitted; set it to false to reject downloads until STOR finishes.
SITE REHASH reloads this setting. Download permissions, credits and slot limits
still apply.

This follows DrFTPD's growing-file transfer behavior. DrFTPD can separately
deny live downloads with a `denydownload` permission rule; WeaveFTPd uses the
existing global `dl_incomplete` setting.

The slave waits when a downloader reaches the current end of a live upload,
then sends newly written bytes. A follower with no source progress fails after
20 seconds (30 seconds for the local-file backend). The downloader must wait
for the source upload to finish and pass synchronous upload verification before
receiving a final 226. An upload error, abort, deleted source or failed SFV
verification fails the follower too. Bytes already transmitted cannot be
recalled; clients must honor the final FTP result and retry failed transfers.

Pending uploads are exposed for FTP routing/listings without becoming completed
VFS or race-database records. Their initial listing size is a nonzero placeholder,
not the final length; downloads stream to EOF. Successful live downloads account
the completed byte count, including REST offsets. A second writer remains blocked
until all readers release the path.

## Validation

The regression tests cover concurrent readers, upload abort/error propagation,
final-byte delivery in both slave send paths, download policy and SITE REHASH,
and routing pending payloads without completing their release.

On a Linux host with Go and a C compiler:

```sh
go test -race ./internal/core ./internal/master ./internal/slave \
  -run 'Test(LiveDownload|GrowingUpload|DLIncomplete|SendFileFollows|Pending.*Upload)'
```

For the real FTP matrix, build a separate binary and run the harness inside a
network namespace. It creates a private test directory, CA, accounts, master and
slave, and never uses production settings or accounts. Requirements: Python 3,
OpenSSL, iproute2 and util-linux; root is needed for `unshare`.

```sh
stage=$(mktemp -d)
go build -o "$stage/weaveftpd.candidate" ./cmd/weaveftpd
sudo unshare -n sh -c 'ip link set lo up; exec python3 "$1" "$2"' sh \
  "$PWD/tests/live_downloads.py" "$stage"
```

The matrix checks clear/TLS data, active/passive connections, slave passthrough
and master proxy, two simultaneous live readers, live and completed REST,
resumed source uploads, TCP-reset source failures, bad CRC rejection, deletion
protection, final byte accounting and disabling/re-enabling the policy. Results
are written to `integration-result.json` in the test directory.

## Implementation reference

- [DrFTPD optional live-download denial](https://github.com/drftpd-ng/drftpd/blob/master/src/core/master/src/main/java/org/drftpd/master/permissions/denydownload/DenyDownload.java)
- [DrFTPD growing-file sender](https://github.com/drftpd-ng/drftpd/blob/master/src/core/slave/src/main/java/org/drftpd/slave/network/Transfer.java)
