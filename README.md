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
<<<<<<< master
- Built-in Wissensdatenbank (Knowledge Base) managed via UI
- MFA / TOTP (2FA) support
=======
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

Copy the example environment file and fill in your values (mainly for email notifications):

```bash
cp .env.example .env
```

### Run locally (development)

```bash
# Terminal 1 — backend API
node server.js

# Terminal 2 — frontend dev server
npm run dev
```

Frontend runs on `http://localhost:5173`, backend on `http://localhost:3000`.

The first time the server starts it creates the SQLite database at `data/werkraum.sqlite` and seeds an initial admin account.

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
| Email | `niroxbbx2020@gmail.com` |
| Password | `Jayace!2026#ServiceDesk` |

**Change the email and password immediately after first login.**

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
| `PORT` | — | Port the server listens on (default: `3000`) |
| `NODE_ENV` | — | Set to `production` for production deployments |
| `SUPPORT_EMAIL` | — | Where staff reply notifications get sent |
| `MAIL_FROM` | — | Sender email address for outgoing mail |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | — | SMTP credentials for outgoing mail |

---

## Customisation

- **Name / branding** — search for `Ticket System` in `src/App.jsx` and `index.html`
- **Categories** — edit the `category` enum in the `tickets` table schema in `server.js` and update the dropdown in `src/App.jsx`
- **Colours** — CSS variables live at the top of `src/App.css` (look for `--teal`, `--teal-dark`)
- **Knowledge base articles** — can be managed directly via the application UI by administrators

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
