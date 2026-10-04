# Contabo Deployment (Ubuntu)

This guide runs the application on a Contabo VPS with Ubuntu, systemd, Nginx, HTTPS, and persistent local SQLite storage. It does not require publishing a database or `.env` file.

## Requirements

- Ubuntu 22.04 or 24.04 VPS
- A domain with an A/AAAA record pointing to the VPS
- Node.js 22.13.0 or newer and npm
- SSH access with sudo privileges

Install the base tools and Node.js 22.x from a trusted source, then verify `node --version` is at least `v22.13.0`:

```bash
sudo apt update
sudo apt install -y ca-certificates curl git nginx certbot python3-certbot-nginx
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node --version
```

Keep the Node port private; only Nginx should accept public web traffic.

## Install the Application

Create a dedicated unprivileged account and persistent data directory:

```bash
sudo adduser --system --group --home /var/lib/ticket-system/home ticket-system
sudo mkdir -p /opt/ticket-system /var/lib/ticket-system/home /var/lib/ticket-system/data
sudo chown -R ticket-system:ticket-system /opt/ticket-system /var/lib/ticket-system
```

Clone the public repository and build as the service account:

```bash
sudo -u ticket-system git clone https://github.com/j4yac3/Ticket-System.git /opt/ticket-system
cd /opt/ticket-system
sudo -u ticket-system npm ci
sudo -u ticket-system npm test
sudo -u ticket-system npm run build
```

## Configure Secrets

Create a root-readable environment file. Do not commit or publish this file:

```bash
sudo install -o root -g root -m 600 /dev/null /etc/ticket-system.env
sudoedit /etc/ticket-system.env
```

Set at least:

```env
NODE_ENV=production
HOST=127.0.0.1
PORT=3000
DATA_DIR=/var/lib/ticket-system/data
ADMIN_EMAIL=your-admin@example.com
ADMIN_PASSWORD=use-a-unique-random-password-of-at-least-16-characters
```

The production bootstrap rejects missing, short, or documented example passwords. The administrator must change the bootstrap password at first login. The database is created under `DATA_DIR`; uploads are stored in `DATA_DIR/uploads/`.

If SMTP notifications are required, add `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM` to the root-owned environment file. Keep these values out of Git and support requests.

## Run with systemd

Find the Node executable path with `command -v node`, then create `/etc/systemd/system/ticket-system.service` (adjust `ExecStart` if Node is not at `/usr/bin/node`):

```ini
[Unit]
Description=Self-hosted Ticket System
After=network.target

[Service]
Type=simple
User=ticket-system
Group=ticket-system
WorkingDirectory=/opt/ticket-system
EnvironmentFile=/etc/ticket-system.env
ExecStart=/usr/bin/node /opt/ticket-system/server.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ticket-system

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ticket-system
sudo systemctl status ticket-system
sudo journalctl -u ticket-system -f
```

The app listens only on `127.0.0.1:3000`; it should not be exposed directly to the internet.

## Nginx and HTTPS

Create a site for your domain. Replace `tickets.example.com` with your domain:

```nginx
server {
    listen 80;
    server_name tickets.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

Enable the site, test Nginx, and obtain a certificate with Certbot:

```bash
sudo ln -s /etc/nginx/sites-available/ticket-system /etc/nginx/sites-enabled/ticket-system
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d tickets.example.com
```

Confirm the final TLS server block forwards `X-Forwarded-Proto` as `https`; production mode rejects HTTP at the application layer. At the Contabo firewall and host firewall, allow only SSH (restrict its source where possible), HTTP, and HTTPS. Do not open port 3000 publicly.

The `proxy_buffering off` and long read timeout keep the ticket system's Server-Sent Events live updates working. When the UI and API share this domain, leave `CORS_ORIGINS` unset.

## Data, Backups, and Updates

- Persist `/var/lib/ticket-system/` across deployments. It contains the SQLite database and private uploads.
- Back up the database and uploads regularly, encrypt backups, and test restoring them. Do not put backups in the Git checkout or a public web directory.
- Automatic deletion of resolved tickets is disabled by default. Set `RESOLVED_TICKET_RETENTION_DAYS` only after defining a retention policy; matching tickets and attachments are permanently deleted.
- To update, fetch the intended branch, run `npm ci`, `npm test`, and `npm run build`, then restart the service. Keep the data directory intact.
- Use one application instance with SQLite on local persistent storage. Do not place the live SQLite database on a shared network filesystem or run multiple writers against it.

For security assumptions, vulnerability reporting, and remaining limitations, see [SECURITY.md](SECURITY.md). This project does not provision a VPS, domain, DNS, TLS certificate, or backups for you.
