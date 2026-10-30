# Using a portal

A pydebuprep portal keeps the reports of many hosts in one place and serves the
configs they run with. pydebuprep works without one; everything on this page is
opt-in, and with none of it configured pydebuprep makes no network connection.

A host needs two things: a **token** from the portal, and either an **upload URL**
in its config file or a **config URL** to fetch its config from (a config served by
the portal already contains the upload URL).

## The token

The portal shows a token once, when it is created. Store it on the host so only root
can read it:

```sh
sudo install -d -m 0700 /etc/pydebuprep
sudo install -m 0600 /dev/stdin /etc/pydebuprep/token   # paste the token, then Ctrl-D
```

pydebuprep refuses a token file that other users can read. The `PYDEBUPREP_TOKEN`
environment variable takes precedence over the file, and `--token-file` (or
`upload: token_file:` in the config file) names another file. The token is sent only
to the portal, as an `Authorization: Bearer` header, and never appears in a report,
a config file or a message.

## Uploading reports

Set the portal in the [configuration file](../configuration/index.md):

```yaml
upload:
  url: https://portal.example.com
```

After each `report`, pydebuprep uploads the report as JSON — the full report, even
when `--min-severity` hides findings locally — and prints where it went. `snapshot`
and `convert` never upload.

**A failed upload never fails the report.** The report is printed or written as
usual, the exit code is unchanged, and the JSON is kept in
`/var/lib/pydebuprep/pending/` (`upload: pending_dir:`; `null` keeps nothing). Send
what was kept later with:

```sh
sudo pydebuprep upload                 # everything pending; each accepted one is removed
sudo pydebuprep upload report.json     # reports you saved with --format json or yaml
```

The portal recognises a report it already has, so sending one twice is harmless.

## Running with a config from the portal

```sh
sudo pydebuprep --config https://portal.example.com/api/v1/configs/web/default
```

pydebuprep fetches the config with the token, checks it like a local config file, and
saves a copy in `/var/lib/pydebuprep/configs/`. `PYDEBUPREP_CONFIG` may hold the URL
instead, and `snapshot`, `configtest` and `upload` accept it too.

If the portal can't be reached:

- with a saved copy, pydebuprep uses it and says so in the report's header — *"Config
  from URL could not be fetched; used the copy fetched on DATE — it may not be the
  latest"* — and in the JSON report (`config.stale`), so the portal can mark it;
- without one, the run stops with an error (exit code 3).

### What a config from a URL may not do

A config from a URL is written by someone other than the host's root, so it may
only steer the read-only checks:

- it can't set a path pydebuprep writes to or reads credentials from:
  `report.output_dir`, `report.snapshot_dir`, `upload.token_file`, `upload.ca_file`
  and `upload.pending_dir` are refused;
- its `upload.url` must be on the same server as the config, so the token can't be
  sent anywhere else;
- a `report.baseline` must be `auto`, `none` or an absolute path.

## HTTPS and certificates

Uploads and configs use HTTPS, with certificates checked against the system's CAs.
For a portal with a certificate from an internal CA, add that CA — the system's CAs
still apply:

```sh
sudo pydebuprep --ca-file /etc/ssl/certs/internal-ca.pem ...
```

or set `PYDEBUPREP_CA_FILE`, or `upload: ca_file:` in the config file. Redirects are
never followed. `http://` URLs work only with `--allow-http`, which sends the token
unencrypted: for test setups only.

## What it writes

Everything pydebuprep keeps for the portal is in its own directory,
`/var/lib/pydebuprep` (mode `0700`, created by the package): `pending/` and
`configs/`, files mode `0600`. See [Read-only by design](../about/read-only.md#what-it-does-write).
The formats are published as JSON Schemas: [report](../reference/report-format.md)
and config.
