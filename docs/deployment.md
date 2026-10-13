# Deployment — sad.shivang.me

Live at **https://sad.shivang.me** (HTTP redirects to HTTPS).

## What runs where

| Component | Where | Notes |
|---|---|---|
| Dashboard (FastAPI + uvicorn) | `127.0.0.1:8100` on the host | systemd unit `ftisp.service`, runs as user `ftisp` |
| Reverse proxy + TLS | nginx on `:80`/`:443` | Let's Encrypt cert, auto-renewing |
| Dataset | `/srv/ftisp/data/unsw-nb15` | fetched on the host, not committed |
| Code | `/srv/ftisp/app` | a git clone of this repository |
| Virtualenv | `/srv/ftisp/venv` | outside the checkout, so redeploys don't touch it |

The host is `gr19-remote` (see `~/.ssh/config`). `shebang-ParentHost` is configured as an
alternative via `FTISP_HOST`; the same scripts work there unchanged.

## Access

The whole site is behind HTTP Basic auth, because the dashboard lets any visitor start a
CPU-bound simulation on the host.

```
username: ftisp
password: (set at provision time — see below to rotate)
```

Rotate it with:

```bash
ssh gr19-remote "htpasswd -bc /etc/nginx/.htpasswd-ftisp ftisp 'NEWPASSWORD'"
```

## Deploying a change

```bash
./deploy/deploy.sh              # pull latest main, reinstall deps, restart
./deploy/deploy.sh --nginx      # also reinstall the nginx site and ensure TLS
./deploy/deploy.sh --first-time # provision a bare host (packages, user, dirs)
```

The script is idempotent. It is safe to re-run for routine updates.

## Design decisions worth knowing

**The nginx site file is not overwritten by default.** `certbot --nginx` rewrites
`/etc/nginx/sites-available/ftisp` to add the certificate and the redirect. Re-copying the template
on every deploy would silently drop the TLS block, so `deploy.sh` only installs it under `--nginx`,
and picks the pre-TLS template when no certificate exists yet (the post-TLS template references
certificate paths, which makes `nginx -t` fail before issuance).

**`requirements.txt` is installed explicitly.** `pip install -e .` installs the package only —
`pyproject.toml` declares no dependencies — so without the explicit requirements install the venv
has no `uvicorn` and the unit fails with `203/EXEC`. This was the first deployment failure.

**One uvicorn worker.** A simulation is CPU-bound and the app already serialises runs with a
semaphore, so extra workers would compete for cores rather than add capacity. Raise `--workers` if
concurrent *viewing* becomes the bottleneck.

**The dataset lives outside the checkout**, pointed at by `FTISP_DATA_DIR`. It is 48 MB and
`scripts/fetch_data.py` verifies a SHA-256 for each file, so a fresh host is reproducible.

**WebSocket timeouts are raised to 600 s** in the nginx config. A 30-round run can take minutes and
the default 60 s proxy read timeout would cut the stream mid-run.

## Operating

```bash
ssh gr19-remote 'systemctl status ftisp'          # is it up
ssh gr19-remote 'journalctl -u ftisp -n 50'       # recent logs
ssh gr19-remote 'journalctl -u ftisp -f'          # follow
ssh gr19-remote 'systemctl restart ftisp'         # restart
ssh gr19-remote 'certbot certificates'            # cert expiry
ssh gr19-remote 'nginx -t'                        # config check
```

Certificates renew automatically via a certbot systemd timer. Verify with
`systemctl list-timers | grep certbot`.

## Security posture

Present and verified:

- TLS (Let's Encrypt, auto-renewing), HTTP redirected to HTTPS.
- HTTP Basic auth on the entire site.
- `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `ProtectKernelTunables`, `RestrictSUIDSGID`, `LockPersonality`, and a 12 GB `MemoryMax`.
- The app binds `127.0.0.1` only; nginx is the sole exposed service.
- Request bodies capped at 64 KB — the dashboard takes small JSON, never uploads.

Not done, and worth stating rather than implying otherwise:

- **No rate limiting.** Anyone with the password can start runs back-to-back. Add
  `limit_req` in nginx if the link is shared widely.
- **Basic auth is not TLS client auth.** The credentials are a shared secret; there is no
  per-user identity. Fine for a project demo, not for multi-tenant use.
- **The app-level identity layer is not enforced in the web path.** Ed25519 signing exists in the
  simulation and in tests; the dashboard's WebSocket does not yet require a signed client.
- **No firewall rules.** `ufw` is inactive on the host; only 22, 80 and 443 are exposed, but that
  is a consequence of what is listening rather than a policy.
