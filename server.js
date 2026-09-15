import crypto from 'node:crypto'
import 'dotenv/config'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { DatabaseSync } from 'node:sqlite'
import { z } from 'zod'
import nodemailer from 'nodemailer'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isProduction = process.env.NODE_ENV === 'production'
const allowSelfRegistration = process.env.ALLOW_SELF_REGISTRATION === 'true' || !isProduction
const port = Number(process.env.PORT || 3000)
const frontendUrl = process.env.APP_URL || 'http://localhost:5174'
const callbackBaseUrl = process.env.OAUTH_CALLBACK_BASE_URL || `http://localhost:${port}`
const dataDir = path.join(__dirname, 'data')
fs.mkdirSync(dataDir, { recursive: true })
const db = new DatabaseSync(path.join(dataDir, 'werkraum.sqlite'))
const SESSION_TTL_MS = 8 * 60 * 60 * 1000
const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: isProduction, path: '/' }
const mailTransporter = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } }) : null
const mailFrom = process.env.MAIL_FROM || process.env.SMTP_USER

function hash(value) { return crypto.createHash('sha256').update(value).digest('hex') }
function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString('base64url') }
function passwordHash(password) {
  const salt = crypto.randomBytes(16)
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 })
  return `scrypt$${salt.toString('base64url')}$${derived.toString('base64url')}`
}
function verifyPassword(password, stored) {
  const [, saltValue, hashValue] = stored.split('$')
  if (!saltValue || !hashValue) return false
  const derived = crypto.scryptSync(password, Buffer.from(saltValue, 'base64url'), 64, { N: 16384, r: 8, p: 1 })
  const expected = Buffer.from(hashValue, 'base64url')
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived)
}
function cookieValue(request, name) {
  return request.headers.cookie?.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${name}=`))?.slice(name.length + 1)
}

 db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    requester_id INTEGER NOT NULL REFERENCES users(id),
    category TEXT NOT NULL CHECK (category IN ('Hardware', 'Ausleihe', 'Software')),
    priority TEXT NOT NULL CHECK (priority IN ('Niedrig', 'Mittel', 'Hoch')),
    status TEXT NOT NULL CHECK (status IN ('Offen', 'In Bearbeitung', 'Wartet auf Rückmeldung', 'Gelöst')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_tag TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('Laptop', 'Monitor', 'Beamer', 'Zubehör', 'Software-Lizenz')),
    status TEXT NOT NULL CHECK (status IN ('Verfügbar', 'Ausgeliehen', 'Wartung')) DEFAULT 'Verfügbar',
    condition TEXT NOT NULL CHECK (condition IN ('Neu', 'Gut', 'Prüfung nötig')) DEFAULT 'Gut',
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    due_date TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`)

const ticketColumns = db.prepare('PRAGMA table_info(tickets)').all().map((column) => column.name)
if (!ticketColumns.includes('customer_can_reply')) db.exec('ALTER TABLE tickets ADD COLUMN customer_can_reply INTEGER NOT NULL DEFAULT 0')
const userColumns = db.prepare('PRAGMA table_info(users)').all().map((column) => column.name)
if (!userColumns.includes('auth_provider')) db.exec('ALTER TABLE users ADD COLUMN auth_provider TEXT')
if (!userColumns.includes('auth_subject')) db.exec('ALTER TABLE users ADD COLUMN auth_subject TEXT')
if (!userColumns.includes('must_change_password')) db.exec('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_provider_subject ON users(auth_provider, auth_subject) WHERE auth_provider IS NOT NULL AND auth_subject IS NOT NULL')

const adminEmail = 'niroxbbx2020@gmail.com'
const adminBootstrapPassword = 'Jayace!2026#ServiceDesk'
if (!db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail)) {
  db.prepare('INSERT INTO users (email, name, role, password_hash, must_change_password) VALUES (?, ?, ?, ?, ?)').run(adminEmail, 'Administrator', 'admin', passwordHash(adminBootstrapPassword), 1)
  console.log(`Admin account created: ${adminEmail} — password must be changed on first login.`)
}

const app = express()
app.disable('x-powered-by')
if (isProduction) app.set('trust proxy', 1)
app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  } : false,
  strictTransportSecurity: isProduction ? undefined : false,
  crossOriginEmbedderPolicy: false,
}))
if (isProduction) app.use((request, response, next) => {
  if (!request.secure) return response.status(400).json({ error: 'HTTPS ist für diese Anwendung erforderlich.' })
  next()
})
app.use(express.json({ limit: '32kb' }))
app.use((request, response, next) => { response.setHeader('Cache-Control', 'no-store'); next() })
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false })
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false })
app.use('/api', apiLimiter)

function requireCsrf(request, response, next) {
  const sessionId = cookieValue(request, 'session')
  const csrfCookie = cookieValue(request, 'csrf_token')
  if (!csrfCookie || request.get('x-csrf-token') !== csrfCookie) return response.status(403).json({ error: 'Ungültige Anfrage.' })
  if (!sessionId) return next()
  const session = db.prepare('SELECT csrf_token FROM sessions WHERE id_hash = ? AND expires_at > ?').get(hash(sessionId), Date.now())
  if (!session || session.csrf_token.length !== csrfCookie.length || !crypto.timingSafeEqual(Buffer.from(session.csrf_token), Buffer.from(csrfCookie))) return response.status(403).json({ error: 'Ungültige Anfrage.' })
  next()
}
function currentUser(request, response, next) {
  const sessionId = cookieValue(request, 'session')
  const session = sessionId && db.prepare('SELECT s.*, u.email, u.name, u.role, u.must_change_password FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND s.expires_at > ?').get(hash(sessionId), Date.now())
  if (!session) return response.status(401).json({ error: 'Nicht angemeldet.' })
  request.auth = session
  next()
}
function publicUser(user) { return { email: user.email, name: user.name, role: user.role === 'admin' ? 'Administrator' : 'Kunde', mustChangePassword: Boolean(user.must_change_password), initials: user.name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase() } }
function ticketView(ticket) { return { id: ticket.public_id, title: ticket.title, description: ticket.description, requester: ticket.requester_name, team: ticket.requester_role === 'admin' ? 'IT-Support' : 'Kundenanfrage', category: ticket.category, priority: ticket.priority, status: ticket.status, updated: ticket.updated_at, customerCanReply: Boolean(ticket.customer_can_reply), initials: ticket.requester_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), tone: ticket.requester_role === 'admin' ? 'teal' : 'coral' } }
function findTicketForUser(publicId, user) {
  const ticket = db.prepare('SELECT * FROM tickets WHERE public_id = ?').get(publicId)
  if (!ticket || (user.role !== 'admin' && ticket.requester_id !== user.user_id)) return null
  return ticket
}
const oauthProviders = {
  discord: {
    clientId: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    authorize: 'https://discord.com/oauth2/authorize',
    token: 'https://discord.com/api/oauth2/token',
    scopes: 'identify email',
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    scopes: 'read:user user:email',
  },
}
function providerConfig(provider) { return oauthProviders[provider] && oauthProviders[provider].clientId && oauthProviders[provider].clientSecret ? oauthProviders[provider] : null }
function oauthCookieOptions() { return { ...cookieOptions, sameSite: 'lax', maxAge: 10 * 60 * 1000 } }
async function exchangeOAuthCode(provider, code, redirectUri) {
  const config = oauthProviders[provider]
  const tokenResponse = await fetch(config.token, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', ...(provider === 'github' ? { 'User-Agent': 'Werkraum-IT-Service-Desk' } : {}) }, body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, code, redirect_uri: redirectUri }) })
  if (!tokenResponse.ok) throw new Error('OAuth token exchange failed')
  const token = await tokenResponse.json()
  if (!token.access_token) throw new Error('OAuth provider returned no access token')
  if (provider === 'discord') {
    const profileResponse = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${token.access_token}` } })
    const profile = await profileResponse.json()
    if (!profileResponse.ok || !profile.id || !profile.email || profile.verified !== true) throw new Error('Discord account email is not verified')
    return { subject: String(profile.id), email: profile.email.toLowerCase(), name: profile.global_name || profile.username || profile.email.split('@')[0] }
  }
  const profileResponse = await fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${token.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'Werkraum-IT-Service-Desk' } })
  const profile = await profileResponse.json()
  const emailsResponse = await fetch('https://api.github.com/user/emails', { headers: { Authorization: `Bearer ${token.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'Werkraum-IT-Service-Desk' } })
  const emails = await emailsResponse.json()
  const email = Array.isArray(emails) ? emails.find((item) => item.primary && item.verified)?.email : null
  if (!profileResponse.ok || !emailsResponse.ok || !profile.id || !email) throw new Error('GitHub account has no verified primary email')
  return { subject: String(profile.id), email: email.toLowerCase(), name: profile.name || profile.login || email.split('@')[0] }
}
function createSession(response, user) {
  const sessionId = randomToken(); const csrfToken = randomToken(24)
  db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)').run(hash(sessionId), user.id, csrfToken, Date.now() + SESSION_TTL_MS)
  response.cookie('session', sessionId, { ...cookieOptions, maxAge: SESSION_TTL_MS }); response.cookie('csrf_token', csrfToken, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS })
}
function sendNotification(to, subject, text) {
  if (!mailTransporter || !to || !mailFrom) return
  mailTransporter.sendMail({ from: mailFrom, to, subject: `Jayace IT Service: ${subject}`, text }).catch((error) => console.error('Notification email failed:', error.message))
}
const credentials = z.object({ email: z.string().trim().email().max(254), password: z.string().min(8).max(128) })
const registration = credentials.extend({ name: z.string().trim().min(2).max(100) })
const ticketInput = z.object({ title: z.string().trim().min(3).max(160), description: z.string().trim().min(15).max(5000), category: z.enum(['Hardware', 'Ausleihe', 'Software']), priority: z.enum(['Niedrig', 'Mittel', 'Hoch']) })
const ticketStatus = z.enum(['Offen', 'In Bearbeitung', 'Wartet auf Rückmeldung', 'Gelöst'])
const commentInput = z.object({ body: z.string().trim().min(2).max(5000) })
const assetInput = z.object({ assetTag: z.string().trim().min(3).max(30), name: z.string().trim().min(2).max(120), assetType: z.enum(['Laptop', 'Monitor', 'Beamer', 'Zubehör', 'Software-Lizenz']), condition: z.enum(['Neu', 'Gut', 'Prüfung nötig']) })
const loanInput = z.object({ userId: z.number().int().positive().nullable(), dueDate: z.string().date().nullable() })

app.get('/api/csrf', (request, response) => { let token = cookieValue(request, 'csrf_token'); if (!token) { token = randomToken(24); response.cookie('csrf_token', token, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS }) } response.json({ ok: true }) })
app.get('/api/auth/:provider', (request, response, next) => {
  const provider = request.params.provider.toLowerCase()
  if (!Object.hasOwn(oauthProviders, provider)) return next()
  const config = providerConfig(provider)
  if (!config) return response.redirect(`${frontendUrl}/?auth_error=${encodeURIComponent(`${provider} Login ist noch nicht konfiguriert.`)}`)
  const state = randomToken(24)
  const redirectUri = `${callbackBaseUrl}/api/auth/${provider}/callback`
  response.cookie('oauth_state', state, oauthCookieOptions())
  const authorizationUrl = new URL(config.authorize)
  authorizationUrl.search = new URLSearchParams({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: config.scopes, state }).toString()
  response.redirect(authorizationUrl.toString())
})
app.get('/api/auth/:provider/callback', async (request, response) => {
  const provider = request.params.provider.toLowerCase()
  const config = providerConfig(provider)
  const stateCookie = cookieValue(request, 'oauth_state')
  response.clearCookie('oauth_state', oauthCookieOptions())
  if (!config || !request.query.code || !request.query.state || !stateCookie || stateCookie.length !== request.query.state.length || !crypto.timingSafeEqual(Buffer.from(stateCookie), Buffer.from(request.query.state))) return response.redirect(`${frontendUrl}/?auth_error=${encodeURIComponent('Die Anmeldung konnte nicht verifiziert werden.')}`)
  try {
    const redirectUri = `${callbackBaseUrl}/api/auth/${provider}/callback`
    const profile = await exchangeOAuthCode(provider, request.query.code, redirectUri)
    let user = db.prepare('SELECT * FROM users WHERE auth_provider = ? AND auth_subject = ?').get(provider, profile.subject)
    if (!user) {
      user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(profile.email)
      if (user) {
        db.prepare('UPDATE users SET auth_provider = ?, auth_subject = ? WHERE id = ?').run(provider, profile.subject, user.id)
      } else {
        if (!allowSelfRegistration) return response.redirect(`${frontendUrl}/?auth_error=${encodeURIComponent('Neue Konten sind derzeit deaktiviert.')}`)
        const result = db.prepare('INSERT INTO users (email, name, role, password_hash, auth_provider, auth_subject) VALUES (?, ?, ?, ?, ?, ?)').run(profile.email, profile.name, 'customer', passwordHash(randomToken()), provider, profile.subject)
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid)
      }
    }
    createSession(response, user)
    response.redirect(frontendUrl)
  } catch (error) {
    console.error('OAuth callback failed:', error.message)
    response.redirect(`${frontendUrl}/?auth_error=${encodeURIComponent('Die Anmeldung beim Anbieter ist fehlgeschlagen.')}`)
  }
})
app.post('/api/auth/login', authLimiter, requireCsrf, (request, response) => {
  const parsed = credentials.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte gültige Zugangsdaten eingeben.' })
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(parsed.data.email)
  if (!user || !verifyPassword(parsed.data.password, user.password_hash)) return response.status(401).json({ error: 'E-Mail oder Passwort ist nicht korrekt.' })
  const sessionId = randomToken(); const csrfToken = randomToken(24)
  db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)').run(hash(sessionId), user.id, csrfToken, Date.now() + SESSION_TTL_MS)
  response.cookie('session', sessionId, { ...cookieOptions, maxAge: SESSION_TTL_MS }); response.cookie('csrf_token', csrfToken, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS }); response.json({ user: publicUser(user) })
})
app.post('/api/auth/register', authLimiter, requireCsrf, (request, response) => {
  if (!allowSelfRegistration) return response.status(404).json({ error: 'Registrierung ist deaktiviert.' })
  const parsed = registration.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte Name, E-Mail und ein Passwort mit mindestens 8 Zeichen angeben.' })
  try {
    const result = db.prepare('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)').run(parsed.data.email.toLowerCase(), parsed.data.name, 'customer', passwordHash(parsed.data.password))
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid)
    const sessionId = randomToken(); const csrfToken = randomToken(24)
    db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)').run(hash(sessionId), user.id, csrfToken, Date.now() + SESSION_TTL_MS)
    response.cookie('session', sessionId, { ...cookieOptions, maxAge: SESSION_TTL_MS }); response.cookie('csrf_token', csrfToken, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS }); response.status(201).json({ user: publicUser(user) })
  } catch { response.status(409).json({ error: 'Diese E-Mail-Adresse ist bereits registriert.' }) }
})
app.post('/api/auth/logout', currentUser, requireCsrf, (request, response) => { db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(hash(cookieValue(request, 'session'))); response.clearCookie('session', cookieOptions); response.json({ ok: true }) })
app.get('/api/auth/me', currentUser, (request, response) => response.json({ user: publicUser(request.auth) }))
app.post('/api/auth/change-password', currentUser, requireCsrf, (request, response) => {
  const schema = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(8).max(128) })
  const parsed = schema.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte aktuelles und neues Passwort angeben (mind. 8 Zeichen).' })
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  if (!user || !verifyPassword(parsed.data.currentPassword, user.password_hash)) return response.status(401).json({ error: 'Das aktuelle Passwort ist nicht korrekt.' })
  if (parsed.data.currentPassword === parsed.data.newPassword) return response.status(400).json({ error: 'Das neue Passwort muss sich vom aktuellen unterscheiden.' })
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(passwordHash(parsed.data.newPassword), user.id)
  response.json({ ok: true, user: publicUser({ ...user, must_change_password: 0 }) })
})

app.get('/api/stats', currentUser, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const now = new Date()
  const thisMonthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()
  const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString()
  const lastMonthEnd = thisMonthStart
  const openCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Offen'").get().c
  const inProgressCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'In Bearbeitung'").get().c
  const loanCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE category = 'Ausleihe' AND status != 'Gelöst'").get().c
  const solvedThisMonth = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Gelöst' AND updated_at >= ?").get(thisMonthStart).c
  const solvedLastMonth = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Gelöst' AND updated_at >= ? AND updated_at < ?").get(lastMonthStart, lastMonthEnd).c
  const openThisMonth = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Offen' AND created_at >= ?").get(thisMonthStart).c
  const openLastMonth = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Offen' AND created_at >= ? AND created_at < ?").get(lastMonthStart, lastMonthEnd).c
  const totalTickets = db.prepare('SELECT COUNT(*) AS c FROM tickets').get().c
  const resolvedTickets = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Gelöst'").get().c
  const avgResolutionResult = db.prepare("SELECT AVG((julianday(updated_at) - julianday(created_at)) * 24) AS avg_hours FROM tickets WHERE status = 'Gelöst'").get()
  const avgResolutionHours = avgResolutionResult?.avg_hours ? Math.round(avgResolutionResult.avg_hours * 10) / 10 : 0
  response.json({ openCount, inProgressCount, loanCount, solvedThisMonth, solvedLastMonth, openThisMonth, openLastMonth, totalTickets, resolvedTickets, avgResolutionHours })
})

app.get('/api/users', currentUser, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const users = db.prepare('SELECT id, email, name, role, created_at FROM users ORDER BY name').all()
  response.json({ users: users.map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role === 'admin' ? 'Administrator' : 'Kunde', initials: u.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase(), tone: u.role === 'admin' ? 'teal' : 'coral', createdAt: u.created_at })) })
})
app.get('/api/assets', currentUser, (request, response) => {
  const assets = db.prepare('SELECT a.*, u.name assigned_name FROM assets a LEFT JOIN users u ON u.id = a.assigned_to ORDER BY a.status, a.name').all()
  response.json({ assets: assets.map((asset) => ({ id: asset.id, assetTag: asset.asset_tag, name: asset.name, assetType: asset.asset_type, status: asset.status, condition: asset.condition, assignedTo: asset.assigned_name || null, dueDate: asset.due_date })) })
})
app.post('/api/assets', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Nur Mitarbeitende dürfen Geräte anlegen.' })
  const parsed = assetInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte alle Gerätedaten korrekt ausfüllen.' })
  try {
    const result = db.prepare('INSERT INTO assets (asset_tag, name, asset_type, condition) VALUES (?, ?, ?, ?)').run(parsed.data.assetTag, parsed.data.name, parsed.data.assetType, parsed.data.condition)
    const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(result.lastInsertRowid)
    response.status(201).json({ asset: { id: asset.id, assetTag: asset.asset_tag, name: asset.name, assetType: asset.asset_type, status: asset.status, condition: asset.condition, assignedTo: null, dueDate: null } })
  } catch { response.status(409).json({ error: 'Dieses Inventarzeichen ist bereits vergeben.' }) }
})
app.patch('/api/assets/:id/loan', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Nur Mitarbeitende dürfen Ausleihen verwalten.' })
  const parsed = loanInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Ungültige Ausleihdaten.' })
  const asset = db.prepare('SELECT id FROM assets WHERE id = ?').get(request.params.id)
  if (!asset) return response.status(404).json({ error: 'Gerät nicht gefunden.' })
  const isLoaned = parsed.data.userId !== null
  db.prepare("UPDATE assets SET assigned_to = ?, due_date = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(parsed.data.userId, parsed.data.dueDate, isLoaned ? 'Ausgeliehen' : 'Verfügbar', asset.id)
  response.json({ ok: true })
})

app.get('/api/tickets', currentUser, (request, response) => {
  const query = request.auth.role === 'admin' ? 'SELECT t.*, u.name requester_name, u.role requester_role FROM tickets t JOIN users u ON u.id = t.requester_id ORDER BY t.updated_at DESC' : 'SELECT t.*, u.name requester_name, u.role requester_role FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.requester_id = ? ORDER BY t.updated_at DESC'
  const tickets = request.auth.role === 'admin' ? db.prepare(query).all() : db.prepare(query).all(request.auth.user_id)
  response.json({ tickets: tickets.map(ticketView) })
})
app.post('/api/tickets', currentUser, requireCsrf, (request, response) => {
  const parsed = ticketInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Betreff und eine Beschreibung mit mindestens 15 Zeichen sind erforderlich.' })
  const nextId = Number(db.prepare("SELECT COALESCE(MAX(id), 1049) + 1 AS next_id FROM tickets").get().next_id)
  const publicId = `TK-${nextId}`
  db.prepare('INSERT INTO tickets (public_id, title, description, requester_id, category, priority, status) VALUES (?, ?, ?, ?, ?, ?, ?)').run(publicId, parsed.data.title, parsed.data.description, request.auth.user_id, parsed.data.category, parsed.data.priority, 'Offen')
  const ticket = db.prepare('SELECT t.*, u.name requester_name, u.role requester_role FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.public_id = ?').get(publicId)
  const requester = db.prepare('SELECT email FROM users WHERE id = ?').get(request.auth.user_id)
  sendNotification(requester?.email, `Ticket ${publicId} erstellt`, `Dein Ticket „${ticket.title}“ wurde erstellt. Status: ${ticket.status}.`)
  if (request.auth.role !== 'admin') sendNotification(process.env.SUPPORT_EMAIL || adminEmail, `Neue Anfrage ${publicId}`, `${request.auth.name} hat „${ticket.title}“ erstellt.`)
  response.status(201).json({ ticket: ticketView(ticket) })
})
app.get('/api/tickets/:id/comments', currentUser, (request, response) => {
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  const comments = db.prepare('SELECT c.id, c.body, c.created_at, u.name author_name, u.role author_role FROM comments c JOIN users u ON u.id = c.author_id WHERE c.ticket_id = ? ORDER BY c.created_at ASC, c.id ASC').all(ticket.id)
  response.json({ comments: comments.map((comment) => ({ id: comment.id, body: comment.body, author: comment.author_name, role: comment.author_role === 'admin' ? 'Mitarbeiter' : 'Kunde', initials: comment.author_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), createdAt: comment.created_at })) })
})
app.post('/api/tickets/:id/comments', currentUser, requireCsrf, (request, response) => {
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  const isStaff = request.auth.role === 'admin'
  if (!isStaff && !ticket.customer_can_reply) return response.status(403).json({ error: 'Antworten sind für dieses Ticket noch nicht freigegeben.' })
  const parsed = commentInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Die Antwort muss zwischen 2 und 5000 Zeichen enthalten.' })
  const result = db.prepare('INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)').run(ticket.id, request.auth.user_id, parsed.data.body)
  db.prepare("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP, status = CASE WHEN status = 'Offen' THEN 'In Bearbeitung' ELSE status END WHERE id = ?").run(ticket.id)
  const comment = db.prepare('SELECT c.id, c.body, c.created_at, u.name author_name, u.role author_role FROM comments c JOIN users u ON u.id = c.author_id WHERE c.id = ?').get(result.lastInsertRowid)
  const recipient = db.prepare('SELECT u.email, t.title FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.id = ?').get(ticket.id)
  if (isStaff) sendNotification(recipient?.email, `Neue Antwort zu ${request.params.id}`, `${comment.author_name} hat auf dein Ticket „${recipient?.title}“ geantwortet.`)
  else sendNotification(process.env.SUPPORT_EMAIL || adminEmail, `Kundenantwort zu ${request.params.id}`, `${comment.author_name} hat auf ein Ticket geantwortet.`)
  response.status(201).json({ comment: { id: comment.id, body: comment.body, author: comment.author_name, role: isStaff ? 'Mitarbeiter' : 'Kunde', initials: comment.author_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), createdAt: comment.created_at } })
})
app.patch('/api/tickets/:id/reply-permission', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Nur Mitarbeitende dürfen Antwortfreigaben ändern.' })
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  const allowed = z.boolean().safeParse(request.body?.customerCanReply)
  if (!allowed.success) return response.status(400).json({ error: 'Ungültige Antwortfreigabe.' })
  db.prepare('UPDATE tickets SET customer_can_reply = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(allowed.data ? 1 : 0, ticket.id)
  response.json({ customerCanReply: allowed.data })
})
app.patch('/api/tickets/:id/status', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'admin') return response.status(403).json({ error: 'Nur Mitarbeitende dürfen Ticketstatus ändern.' })
  const status = ticketStatus.safeParse(request.body?.status)
  if (!status.success) return response.status(400).json({ error: 'Ungültiger Status.' })
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  db.prepare("UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE public_id = ?").run(status.data, request.params.id)
  const requester = db.prepare('SELECT u.email, t.title FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.id = ?').get(ticket.id)
  sendNotification(requester?.email, `Status von ${request.params.id} geändert`, `Der Status von „${requester?.title}“ wurde auf „${status.data}“ gesetzt.`)
  response.json({ ok: true })
})

app.use('/api', (request, response) => response.status(404).json({ error: 'API-Endpunkt nicht gefunden.' }))
app.use(express.static(path.join(__dirname, 'dist')))
app.use((request, response) => response.sendFile(path.join(__dirname, 'dist', 'index.html')))
app.use((error, request, response, next) => {
  if (response.headersSent) return next(error)
  if (error instanceof SyntaxError && error.status === 400 && error.type === 'entity.parse.failed') return response.status(400).json({ error: 'Ungültiges JSON.' })
  if (error.type === 'entity.too.large') return response.status(413).json({ error: 'Anfrage ist zu groß.' })
  console.error('Unhandled server error:', error.message)
  response.status(500).json({ error: 'Interner Serverfehler.' })
})
app.listen(port, () => console.log(`Jayace IT Service server listening on http://localhost:${port}`))
