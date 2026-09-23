# Security and Data Protection Baseline

This application is implemented as a secure local baseline, not as certified legal or compliance advice.

## Protection Mechanisms

* Passwords are hashed using Node.js `crypto.scryptSync` with an individual salt.
* Sessions are stored server-side in SQLite; the browser only receives a random HttpOnly, Secure, and SameSite cookie.
* Write requests require a double-submit CSRF token.
* `helmet` sets security headers; API responses are not cached.
* Login and registration are rate-limited.
* Inputs are validated server-side using Zod and subjected to size limits.
* Customers only see their own tickets. Only admins are allowed to change statuses.
* Database files are located under `data/` and excluded via `.gitignore`.

## Production Operation

1. Place TLS/HTTPS in front of the Node process. In production, the application requires `Secure` cookies and rejects HTTP.
2. The reverse proxy must set `X-Forwarded-Proto` itself, overwrite external client headers of the same name, and keep the Node port publicly inaccessible.
3. Copy `.env.example` to `.env` and set a long, random `ADMIN_BOOTSTRAP_PASSWORD`.
4. Keep `ALLOW_SELF_REGISTRATION=false` and create customers via a controlled invitation process.
5. Restrict access to the server, backups, and the SQLite file to essential personnel only.
6. Encrypt backups, define retention and deletion schedules, and audit access.
7. For genuine enterprise use, additionally implement SSO/MFA, email verification, audit logs, backup testing, monitoring, data protection impact assessments, and a legal review.

## Getting Started

* Development: `npm run server` and, in a second terminal, `npm run dev`
* Production: `npm run build` followed by `NODE_ENV=production npm start`

## Discord and GitHub Login

OAuth is optional and only becomes active once the provider values are configured in `.env`.

* Discord Callback: `http://localhost:3000/api/auth/discord/callback`
* GitHub Callback: `http://localhost:3000/api/auth/github/callback`
* `APP_URL` must point to the publicly accessible frontend URL.
* `OAUTH_CALLBACK_BASE_URL` must point to the publicly accessible backend URL.

The application verifies the OAuth state, only uses verified email addresses, and creates OAuth accounts without a usable plaintext password.
