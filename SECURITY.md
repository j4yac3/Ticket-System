# Security and Data Protection Baseline

This project is self-hosted software, not a managed service or certified security/compliance product. Operators are responsible for deployment, access control, backups, retention, and applicable legal requirements.

## Protection Mechanisms

* Passwords are hashed using Node.js `crypto.scryptSync` with an individual salt.
* Sessions are stored server-side in SQLite; the browser only receives a random HttpOnly, Secure, and SameSite cookie.
* Write requests require a double-submit CSRF token.
* `helmet` sets security headers; API responses are not cached.
* Authentication and API requests are rate-limited. Public self-registration is not provided.
* Inputs are validated server-side using Zod and subjected to size limits.
* Customers only see their own tickets and attachments. Staff can change statuses; customers can only resolve their own tickets.
* Uploaded files are served only after checking the user's access to the related ticket.
* Database files are located under `data/` and excluded via `.gitignore`.

## Production Operation

1. Use Node.js 22.13.0 or newer and place TLS/HTTPS in front of the Node process. In production, the application requires secure cookies and rejects HTTP.
2. The reverse proxy must set `X-Forwarded-Proto` itself, overwrite external client headers of the same name, and keep the Node port publicly inaccessible.
3. Set `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` of at least 16 characters in the hosting provider's secret settings before the first production start. Template values are rejected. The application requires the administrator to change this password after login.
4. Create customer and staff accounts through the controlled user-management interface; public self-registration is not available.
5. Restrict access to the server, backups, and the SQLite file to essential personnel only. Persist both `data/` and `data/uploads/` across deployments.
6. Encrypt backups, define retention and deletion schedules, and audit access. Automatic resolved-ticket deletion is disabled unless `RESOLVED_TICKET_RETENTION_DAYS` is explicitly set.
7. For public deployments, configure monitoring, restore-test backups, and review applicable data-protection requirements. MFA and audit logging are available in the application.

## Getting Started

* Development: `npm run server` and, in a second terminal, `npm run dev`
* Production: `npm run build` followed by `NODE_ENV=production npm start` behind an HTTPS reverse proxy
* `CORS_ORIGINS` is only needed when the frontend and API are hosted on different origins; use exact origins, separated by commas.

## Reporting a Vulnerability

Do not disclose exploitable security issues in a public issue. Use GitHub's private Security Advisory reporting for this repository when available. Include affected versions, impact, and reproduction steps, but do not include real customer data or credentials. There is no guaranteed response-time or support commitment.

## Scope

The integration suite (`npm test`) runs against a temporary database and checks important authorization and input-handling paths. It is not a penetration test or a guarantee that a deployment is secure. Operators should review reverse-proxy settings, secrets, network exposure, and backup/restore procedures before going live.
