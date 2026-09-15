# Sicherheits- und Datenschutzbasis

Diese Anwendung ist als sichere lokale Basis umgesetzt, nicht als zertifizierte Rechts- oder Compliance-Beratung.

## Schutzmechanismen

- Passwörter werden mit Node.js `crypto.scryptSync` und individuellem Salt gehasht.
- Sitzungen liegen serverseitig in SQLite; der Browser erhält nur ein zufälliges HttpOnly-, Secure- und SameSite-Cookie.
- Schreibende Requests benötigen ein Double-Submit-CSRF-Token.
- `helmet` setzt Security-Header; API-Antworten werden nicht gecacht.
- Login und Registrierung sind rate-limitiert.
- Eingaben werden serverseitig mit Zod validiert und Größenlimits unterworfen.
- Kunden sehen nur ihre eigenen Tickets. Nur Admins dürfen Status ändern.
- Datenbankdateien liegen unter `data/` und sind per `.gitignore` ausgeschlossen.

## Produktionsbetrieb

1. TLS/HTTPS vor den Node-Prozess setzen. In Produktion setzt die Anwendung `Secure`-Cookies voraus und lehnt HTTP ab.
2. Der Reverse Proxy muss `X-Forwarded-Proto` selbst setzen, externe gleichnamige Client-Header überschreiben und den Node-Port nicht öffentlich zugänglich machen.
3. `.env.example` nach `.env` kopieren und ein langes, zufälliges `ADMIN_BOOTSTRAP_PASSWORD` setzen.
4. `ALLOW_SELF_REGISTRATION=false` beibehalten und Kunden über einen kontrollierten Einladungsprozess anlegen.
5. Zugriff auf den Server, Backups und die SQLite-Datei auf das notwendige Personal begrenzen.
6. Backups verschlüsseln, Löschfristen und Aufbewahrung definieren und Zugriffe auditieren.
7. Für echten Unternehmenseinsatz zusätzlich SSO/MFA, E-Mail-Verifikation, Audit-Logs, Backup-Tests, Monitoring, Datenschutz-Folgenabschätzung und eine rechtliche Prüfung ergänzen.

## Start

- Entwicklung: `npm run server` und in einem zweiten Terminal `npm run dev`
- Produktion: `npm run build` und danach `NODE_ENV=production npm start`

## Discord und GitHub Login

OAuth ist optional und wird erst aktiv, wenn die Providerwerte in `.env` gesetzt sind.

- Discord Callback: `http://localhost:3000/api/auth/discord/callback`
- GitHub Callback: `http://localhost:3000/api/auth/github/callback`
- `APP_URL` muss auf die öffentlich erreichbare Frontend-URL zeigen.
- `OAUTH_CALLBACK_BASE_URL` muss auf die öffentlich erreichbare Backend-URL zeigen.

Die Anwendung prüft den OAuth-State, nutzt nur verifizierte E-Mail-Adressen und erstellt OAuth-Konten ohne verwendbares Klartextpasswort.
