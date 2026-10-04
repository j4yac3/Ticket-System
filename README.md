# Ticket System — Self-Hosted IT Support Portal

A self-hosted support desk for teams that want to run their own ticket system. The React/Vite frontend and Node.js/Express API are served by one process; SQLite stores tickets, users, comments, and audit events locally.

Ticket data stays on the server you operate. This repository does not provide a hosted service or external database.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Ticket Management** | Create, assign, claim, lock, resolve, and delete tickets with role checks |
| **Internal Notes** | Staff can leave notes hidden from customers |
| **Image Attachments** | PNG, JPEG, GIF, and WebP files with ticket-level access checks |
| **Knowledge Base** | Built-in articles for recurring support questions |
| **Team Management** | Admin-managed users with individually delegated staff permissions |
| **Audit Log** | Records selected ticket, account, and administration events |
| **Two-Factor Auth** | TOTP-based MFA support |
| **Retention** | Automatic cleanup of resolved tickets is disabled by default |

---

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v22.13.0 or higher
- npm (comes with Node.js)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/j4yac3/Ticket-System.git
cd Ticket-System

# 2. Install the exact locked dependencies
npm ci

# 3. Create a local environment file
# PowerShell equivalent: Copy-Item .env.example .env
cp .env.example .env
# Edit .env and set a unique ADMIN_PASSWORD before the first start

# 4. Test and build
npm test
npm run build

# 5. Start the application
npm start
```

The application is available at **http://localhost:3000**. On first startup, the administrator must change the bootstrap password before accessing protected features.

### Development Mode

To run the frontend with hot-reloading during development:

```bash
# Terminal 1 — Start the backend
node server.js

# Terminal 2 — Start the Vite dev server
npm run dev
```

---

## 🔑 Admin Account

On first startup, an administrator is created using `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Set a unique password in `.env` or your deployment's secret store. The password must be changed at first login. In production, startup is refused if the first administrator's password is missing, is a known template value, or is shorter than 16 characters. Public self-registration is not available.

| Field | Default |
|---|---|
| Email | `admin@example.com` *(set via `ADMIN_EMAIL` env var)* |
| Password | Set a unique value via `ADMIN_PASSWORD` |

Never expose an installation that still uses development defaults to the internet.

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Admin account bootstrap (only used when no admin exists yet)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=replace-this-with-a-unique-long-password

# Only if the frontend is hosted on a different origin; comma-separated exact origins
# CORS_ORIGINS=https://tickets.example.com

# Optional: SMTP for email notifications
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=no-reply@example.com
SMTP_PASSWORD=your_smtp_password
SMTP_FROM=no-reply@example.com

```

For internet access, deploy behind an HTTPS reverse proxy and keep the Node port private. Set `NODE_ENV=production`, `HOST`, and `PORT`; put `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and SMTP credentials in your host's secret store. Build with `npm ci && npm run build`, then run `npm start`. Persist and back up both `data/` and `data/uploads/`. If the frontend and API share an origin, leave `CORS_ORIGINS` unset; otherwise list only exact trusted origins, separated by commas. Never expose the Vite development server to the internet.

For a step-by-step Ubuntu VPS setup, see [DEPLOYMENT.md](DEPLOYMENT.md).

Resolved-ticket cleanup is disabled by default. Set `RESOLVED_TICKET_RETENTION_DAYS` to a positive number only after choosing and documenting your retention policy. This permanently deletes matching tickets and their attachments.

For a production VPS setup, follow the [Contabo deployment guide](DEPLOYMENT.md).

---

## 🎨 How to Customize / Theming

### Change the Brand Colors

All colors are defined as CSS variables in [`src/App.css`](src/App.css). Find the `:root` block at the top:

```css
:root {
  --teal:       #8a0b0b;  /* Primary brand color — buttons, active nav, highlights */
  --teal-dark:  #520605;  /* Darker shade — hovers, sidebar header */
  --soft-teal:  #f5e8e7;  /* Light background tint — cards, stat icons */
  --coral:      #ee7a69;  /* Accent color — badges, priority indicators */
}
```

**Example: Switch to a blue theme:**
```css
:root {
  --teal:      #1a56db;
  --teal-dark: #1e429f;
  --soft-teal: #e1effe;
  --coral:     #f59e0b;
}
```

### Change the App Name / Logo

The logo component is rendered inline in [`src/App.jsx`](src/App.jsx). Search for this comment:

```jsx
{/* [TEMPLATE CUSTOMIZATION] Change "Ticket" and "System" to your own app name */}
<span className="brand-logo">
  <span className="brand-ticket">Ticket</span>
  <span className="brand-system">System</span>
</span>
```

Replace `"Ticket"` and `"System"` with your own company/product name.

### Change the MFA Issuer Name

In [`server.js`](server.js), find `buildTOTPUri` and update the issuer:

```js
// Change "Ticket%20System" to your company name (URL-encoded)
return `otpauth://totp/Your%20Company:${encodeURIComponent(email)}?...&issuer=Your%20Company&...`
```

---

## 🗂️ Project Structure

```
Ticket-System/
├── src/
│   ├── App.jsx          # React application
│   ├── App.css          # Application styles
│   └── index.css        # Global styles
├── server.js            # Express API, authentication, and SQLite storage
├── data/                # Private database and ticket uploads; created at runtime
├── test/                # Isolated API/security integration tests
├── public/              # Public static assets
├── dist/                # Generated by `npm run build`
├── .env.example         # Example environment configuration
├── package.json
└── package-lock.json
```

---

## 🔐 Security Notes

- All passwords are hashed with **scrypt** (memory-hard, salted).
- Sessions use **secure, HTTP-only cookies** with CSRF protection.
- Rate limiting is applied to authentication and API endpoints.
- The admin account is **forced to change password** on first login.
- PNG, JPEG, GIF, and WebP ticket images are size-limited and served only to users with access to the ticket.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite |
| Backend | Node.js + Express |
| Database | SQLite (via Node built-in `node:sqlite`) |
| Styling | Vanilla CSS with CSS custom properties |
| Auth | Session cookies + CSRF tokens + TOTP MFA |
| Uploads | Multer |

---

## 📄 License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

*Built with ❤️ — Open-source and self-hostable.*
