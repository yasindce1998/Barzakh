# Barzakh Deployment Guide

Production deployment notes for `barzakh-server` and `barzakh-agent`,
covering API authentication, TLS termination, and webhook integrity.

---

## 🔑 API Authentication (barzakh-server)

Every `/api/*` endpoint (except `/api/health`) requires an API key in a normal
deployment. See [HARDENING.md](HARDENING.md) for input roots and queue limits:

```bash
# Via flag:
barzakh-server --api-key "$(cat /etc/barzakh/api-key)"

# Via environment:
export BARZAKH_API_KEY="$(cat /etc/barzakh/api-key)"
barzakh-server
```

Authenticated requests present the key either way:

```bash
curl -H "X-API-Key: $BARZAKH_API_KEY" http://server:8420/api/scans
curl -H "Authorization: Bearer $BARZAKH_API_KEY" http://server:8420/api/trends
```

Behavior:

| Configuration | Behavior |
|---------------|----------|
| Key set | All `/api/*` (except `/api/health`) require the key; comparisons are constant-time |
| Key unset | Startup is refused unless `--insecure-dev` is explicitly selected on loopback |

Unauthenticated development is loopback-only. Non-loopback binding always
requires a key. Approved scan roots must be controlled by the operator.

Generate a key with: `openssl rand -hex 32`.

---

## 🔒 TLS Termination

`barzakh-server` defaults to plain HTTP on `127.0.0.1:8420`. For anything beyond
localhost, terminate TLS with a reverse proxy. The server itself never
handles certificates — no private key material in the scanning process.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name barzakh.example.com;

    ssl_certificate     /etc/letsencrypt/live/barzakh.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/barzakh.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8420;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Optional: inject the API key at the proxy so dashboard clients
        # never hold it (defense in depth for read-only dashboards):
        # proxy_set_header X-API-Key "internal-key";
    }
}

# Redirect plain HTTP
server {
    listen 80;
    server_name barzakh.example.com;
    return 301 https://$host$request_uri;
}
```

Certificates via [certbot](https://certbot.eff.org/):
`certbot --nginx -d barzakh.example.com`.

### Caddy

```caddy
barzakh.example.com {
    reverse_proxy 127.0.0.1:8420
}
```

(Automatic Let's Encrypt certificates; zero configuration.)

### Firewall rules

Bind the server to localhost when only the proxy needs it:

```bash
# If barzakh-server supported bind addresses, prefer 127.0.0.1; otherwise:
sudo ufw deny 8420/tcp          # external access blocked
sudo ufw allow from 10.0.0.0/8 to any port 8420 proto tcp   # LAN only, if needed
```

---

## 🪝 Webhook Integrity (barzakh-agent)

Set `webhook_secret` in `agent.toml` (see [AGENT.md](AGENT.md)) so SIEM
webhook deliveries carry an HMAC-SHA256 signature the receiver can
verify (`X-Barzakh-Timestamp` + `X-Barzakh-Signature: sha256=<hex>` over
`<timestamp>.<body>`). Receivers should reject stale timestamps
(replay protection).

The signing and a verifying test receiver are exercised in CI
(`barzakh-agent` tests, `tests/webhook.rs`).

---

## 🖥️ systemd Units

```ini
# /etc/systemd/system/barzakh-server.service
[Unit]
Description=Barzakh firmware scanning server
After=network.target

[Service]
User=barzakh
Environment=BARZAKH_API_KEY=/etc/barzakh/api-key-content
ExecStart=/usr/local/bin/barzakh-server --db /var/lib/barzakh/barzakh.db
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

(Note: `BARZAKH_API_KEY` must contain the key itself, not a path — use
`EnvironmentFile=/etc/barzakh/api-key.env` with `BARZAKH_API_KEY=...`
inside for secret-file handling.)
