# Slow upload protection

Existing configurations keep the legacy session kick and login ban. To test
release-scoped protection, use these settings in `plugins/slowkick/config.yml`:

```yaml
monitor_uploads: true
monitor_downloads: false
min_upload_speed_kbps: 3000
verify_upload_seconds: 2
upload_window_seconds: 10
ban_scope: release
tempban_after_kick: true
tempban_seconds: 30
```

The 30-second ban is an example, not a required value. Keep your existing
exclusions and minimum-user setting. Enable the plugin through
`plugins.slowkick.enabled` in the daemon configuration after installing a build
that supports these options.

`upload_window_seconds` measures byte progress over a complete rolling window,
not a single speed reading after a delay. A short dip is tolerated when the
window average stays at or above the configured minimum. The grace period and
full window must both have elapsed. Uploads finishing before the window is full
are not aborted. Slave timing starts at the first byte; local transfers start
sampling at their first observed progress. Missing telemetry restarts sampling.
Setting the window to zero preserves legacy speed checks.

With `ban_scope: release`, only the slow upload is aborted. The control
connection, other transfers, downloads, and other releases remain available.
New `PRET STOR` and `STOR` requests from the same user to that release are denied
until the ban expires, including requests in other sessions or subdirectories.
Already-running uploads are not mass-aborted; each is assessed independently.
The FTP denial is a temporary-policy explanation, not an X-DUPE response.

Release roots follow the configured zipscript release patterns, including dated
and nested sections. If a root cannot be identified, release mode does not abort
the transfer rather than accidentally blocking an entire section. Bans are
in-memory and expire automatically; restarting the daemon clears them.

`ban_scope: site` preserves the old disconnect/login-ban behavior. Release mode
only changes the upload action; disable download monitoring for upload-only
protection. Disabling the plugin bypasses both monitoring and upload bans.

Before production use, test a slow upload for at least ten seconds, a fast upload
with a short dip, a retry in the same release from another session, and an upload
to a different release. Confirm that the control session and downloads stay
usable and that a retry works after the release ban expires.
