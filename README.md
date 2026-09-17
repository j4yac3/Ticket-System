# Ticket System

A simple, self-hosted ticket system for small teams, families, or personal use. Built with React, Node.js, and SQLite — no cloud, no subscription, no data leaving your network.

> **This project is a template.** Clone it, tweak it, make it yours.

---

## What it does

- Users submit support tickets (hardware issues, software questions, general requests)
- Staff can respond, set priority, add internal notes and close tickets
- Admins manage users, view the audit log and see stats
- Sessions stay alive until you log out
- Optional email notifications via SMTP
- Optional OAuth

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 19 + Vite |
| Backend | Node.js + Express 5 |
| Database | SQLite (`node:sqlite`, built into Node 22+) |
| Auth | Session cookies, scrypt hashing, optional TOTP (2FA) |
| Validation | Zod |
| Security | Helmet, rate limiting, CSRF tokens |

---

## Getting started

You need **Node.js 22 or newer**. Nothing else.

```bash
git clone https://github.com/j4yac3/Ticket-System.git
cd Ticket-System
npm install
```

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Open `.env` and at minimum set a strong `ADMIN_BOOTSTRAP_PASSWORD`. Everything else is optional for local use.

### Run locally (development)

```bash
# Terminal 1 — backend API
node server.js

# Terminal 2 — frontend dev server
npm run dev
```

Frontend runs on `http://localhost:5173`, backend on `http://localhost:3000`.

The first time the server starts it creates the SQLite database at `data/werkraum.sqlite` and seeds an admin account using the password from your `.env`.

### Run in production

```bash
npm run build
node server.js
```

The server will serve the built frontend from `dist/` and the API from the same process. Point a reverse proxy (nginx, Caddy, etc.) at port 3000.

---

## Default login

| Field | Value |
|---|---|
| Email | `admin@example.com` |
| Password | Whatever you set in `ADMIN_BOOTSTRAP_PASSWORD` |

Change the email and password immediately after first login.

---

## Roles

| Role | Can do |
|---|---|
| **Kunde** (Customer) | Submit tickets, see own tickets, reply when allowed |
| **Mitarbeiter** (Staff) | Everything above + respond to all tickets, set priority, write internal notes |
| **Administrator** | Everything above + manage users, view audit log, see stats |

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `ADMIN_BOOTSTRAP_PASSWORD` | ✅ | Password for the initial admin account |
| `PORT` | — | Port the server listens on (default: `3000`) |
| `NODE_ENV` | — | Set to `production` for production deployments |
| `ALLOW_SELF_REGISTRATION` | — | Set to `true` to let anyone create an account |
| `SUPPORT_EMAIL` | — | Where staff reply notifications get sent |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | — | SMTP credentials for outgoing mail |
| `APP_URL` | — | Public URL of the frontend (for OAuth callbacks) |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | — | Discord OAuth (optional) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | — | GitHub OAuth (optional) |

---

## Customisation

- **Name / branding** — search for `Ticket System` in `src/App.jsx` and `index.html`
- **Categories** — edit the `category` enum in the `tickets` table schema in `server.js` and update the dropdown in `src/App.jsx`
- **Colours** — CSS variables live at the top of `src/App.css` (look for `--teal`, `--teal-dark`)
- **Knowledge base articles** — hardcoded array in the `SimpleWorkspace` component in `src/App.jsx`

---

## Disclaimer

This project is provided **as-is**, for private and personal use only (e.g. home networks, families, friend groups).

- No warranties of any kind, express or implied
- The author takes **no responsibility** for data loss, security issues, or any damage arising from use of this software
- Not intended for production environments handling sensitive or regulated data
- You are responsible for securing your own deployment

Use at your own risk.

---

## License

[MIT](https://opensource.org/licenses/MIT) — free to use, modify, and share. Attribution appreciated but not required.
