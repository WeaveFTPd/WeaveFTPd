# Private user mail

Authenticated FTP users can send persistent private messages, including to
offline users. This is a mailbox, not live chat or an IRC broadcast.

| Command | Action |
| --- | --- |
| `SITE MSG <username> <message>` | Send a message to an existing user |
| `SITE MAIL [page]` | List your messages, 20 per page |
| `SITE READ <id>` | Read a message and mark it read |
| `SITE DELMSG <id>` | Delete one message |
| `SITE DELMSG ALL` | Delete all messages in your mailbox |

Logins display an unread count.
Only the recipient can list, read or delete their messages through these
commands. Operators do not get a command to read someone else's mailbox.

Limits: 100 stored messages per recipient, 1024 UTF-8 bytes per message,
and 5 successful sends per sender per minute. The rate limit resets on master
restart. Control characters are rejected; command whitespace is normalized.
Messages remain until explicitly deleted. Message bodies are redacted from
command debug logs.

## Existing installations

The shipped permissions allow these commands for `$anyone`. Add `MSG`, `MAIL`,
`READ` and `DELMSG` to the corresponding `sitecmd` allow list in your existing
`etc/permissions.yml`, then run `SITE REHASH`. Existing custom permissions are
not automatically overwritten. Install the updated master binary as usual.

## Storage and backups

Mail is stored outside the FTP tree in `userdata/mail`, relative to the daemon's
working directory. Mailbox files are written atomically with mode 0600 in a
directory created with mode 0700. One master process must own this directory.
The operating system's directory permissions still matter, especially on Windows.

Back up `userdata/mail` together with `etc/users`: each userfile contains its
opaque `MAILBOX` identity. Renaming or restoring that userfile retains its mail;
creating a fresh account under an old username does not inherit the old mailbox.
Never copy a `MAILBOX` line between accounts. Deleted accounts' mailbox files
are retained for account recovery and can be removed by an operator when no
longer needed.

Mail is not encrypted at rest: filesystem administrators and backups can read
it. Use a TLS-protected FTP control connection for messages in transit.
