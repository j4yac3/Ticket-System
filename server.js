import crypto from 'node:crypto'
import 'dotenv/config'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import cors from 'cors'
import { DatabaseSync } from 'node:sqlite'
import { z } from 'zod'
import nodemailer from 'nodemailer'
import multer from 'multer'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isProduction = process.env.NODE_ENV === 'production'
const port = Number(process.env.PORT || 3000)
const dataDir = path.join(__dirname, 'data')
const uploadDir = path.join(dataDir, 'uploads')
fs.mkdirSync(dataDir, { recursive: true })
fs.mkdirSync(uploadDir, { recursive: true })

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  }
})
const upload = multer({ 
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true)
    else cb(new Error('Nur Bilder sind erlaubt.'))
  }
})
const db = new DatabaseSync(path.join(dataDir, 'werkraum.sqlite'))
const SESSION_TTL_MS = 8 * 60 * 60 * 1000
const IDLE_TIMEOUT_MS = 30 * 24 * 60 * 60 * 1000
const cookieOptions = { httpOnly: true, sameSite: 'strict', secure: isProduction, path: '/' }
const mailTransporter = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } }) : null
const mailFrom = process.env.MAIL_FROM || process.env.SMTP_USER

// ─── Crypto Helpers ──────────────────────────────────────────────────
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

// ─── TOTP (RFC 6238) ────────────────────────────────────────────────
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32Encode(buffer) {
  let bits = ''
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0')
  let result = ''
  for (let i = 0; i < bits.length; i += 5) result += BASE32_CHARS[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]
  return result
}
function base32Decode(str) {
  let bits = ''
  for (const char of str.toUpperCase()) { const idx = BASE32_CHARS.indexOf(char); if (idx >= 0) bits += idx.toString(2).padStart(5, '0') }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}
function totpCode(secretBase32, offset = 0) {
  const key = base32Decode(secretBase32)
  const time = Math.floor(Date.now() / 1000 / 30) + offset
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(time))
  const hmac = crypto.createHmac('sha1', key).update(buf).digest()
  const off = hmac[hmac.length - 1] & 0x0f
  const code = ((hmac[off] & 0x7f) << 24 | hmac[off + 1] << 16 | hmac[off + 2] << 8 | hmac[off + 3]) % 1000000
  return String(code).padStart(6, '0')
}
function verifyTOTP(secret, token, window = 1) {
  for (let i = -window; i <= window; i++) { if (totpCode(secret, i) === token) return true }
  return false
}
function generateTOTPSecret() { return base32Encode(crypto.randomBytes(20)) }
function buildTOTPUri(secret, email) {
  return `otpauth://totp/Ticket%20System:${encodeURIComponent(email)}?secret=${secret}&issuer=Ticket%20System&algorithm=SHA1&digits=6&period=30`
}

// ─── Audit Logging ───────────────────────────────────────────────────
function auditLog(request, action, targetType, targetId, details) {
  try {
    db.prepare('INSERT INTO audit_log (user_id, user_email, action, target_type, target_id, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      request?.auth?.user_id ?? null, request?.auth?.email ?? null, action,
      targetType ?? null, targetId ?? null, details ?? null,
      request?.ip ?? request?.socket?.remoteAddress ?? null,
      request?.get?.('user-agent') ?? null
    )
  } catch (err) { console.error('Audit log failed:', err.message) }
}

// ─── Database Schema ─────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  
  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Administrator', 'Mitarbeiter', 'Kunde')),
    password_hash TEXT NOT NULL,
    avatar TEXT,
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
    category TEXT NOT NULL CHECK (category IN ('Hardware', 'Software', 'Sonstiges')),
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
    is_internal INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS ticket_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    user_email TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
`)

// ─── Column Migrations ──────────────────────────────────────────────
const ticketColumns = db.prepare('PRAGMA table_info(tickets)').all().map((c) => c.name)
if (!ticketColumns.includes('customer_can_reply')) db.exec('ALTER TABLE tickets ADD COLUMN customer_can_reply INTEGER NOT NULL DEFAULT 0')
const userColumns = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name)
if (!userColumns.includes('must_change_password')) db.exec('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
if (!userColumns.includes('totp_secret')) db.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT')
if (!userColumns.includes('totp_enabled')) db.exec('ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0')
const sessionColumns = db.prepare('PRAGMA table_info(sessions)').all().map((c) => c.name)
if (!sessionColumns.includes('last_activity')) db.exec('ALTER TABLE sessions ADD COLUMN last_activity INTEGER')
if (!sessionColumns.includes('mfa_verified')) db.exec('ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 1')

// ─── Admin Bootstrap ─────────────────────────────────────────────────
// [TEMPLATE CUSTOMIZATION] Change this to your admin email address
const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com'
// [TEMPLATE CUSTOMIZATION] Change this or set ADMIN_PASSWORD env var. User is forced to change on first login.
const adminBootstrapPassword = process.env.ADMIN_PASSWORD || 'ChangeMe!2024#Admin'
if (!db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail)) {
  db.prepare('INSERT INTO users (email, name, role, password_hash, must_change_password) VALUES (?, ?, ?, ?, ?)').run(adminEmail, 'Administrator', 'Administrator', passwordHash(adminBootstrapPassword), 1)
  console.log(`Admin account created: ${adminEmail} — password must be changed on first login.`)
}

// ─── Express Setup ───────────────────────────────────────────────────
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
      styleSrc: ["'self'"],
    },
  } : false,
  strictTransportSecurity: isProduction ? { maxAge: 31536000, includeSubDomains } : false,
  crossOriginEmbedderPolicy: false,
}))
app.use(cors({
  origin: isProduction ? 'https://yourdomain.com' : 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
}))
if (isProduction) app.use((request, response, next) => {
  if (!request.secure) return response.status(400).json({ error: 'HTTPS ist für diese Anwendung erforderlich.' })
  next()
})
app.use(express.json({ limit: '32kb' }))
app.use('/uploads', express.static(uploadDir))
app.use((request, response, next) => { response.setHeader('Cache-Control', 'no-store'); next() })
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Zu viele Anfragen. Bitte in 15 Minuten erneut versuchen.' } })
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Rate-Limit erreicht.' } })
app.use('/api', apiLimiter)

// ─── Middleware ──────────────────────────────────────────────────────
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
  const now = Date.now()
  const session = sessionId && db.prepare('SELECT s.*, u.email, u.name, u.role, u.must_change_password, u.totp_enabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND s.expires_at > ?').get(hash(sessionId), now)
  if (!session) return response.status(401).json({ error: 'Nicht angemeldet.' })
  if (!session.mfa_verified) return response.status(401).json({ error: 'MFA-Verifizierung erforderlich.', mfaRequired: true })
  if (session.last_activity && (now - session.last_activity > IDLE_TIMEOUT_MS)) {
    db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(hash(sessionId))
    response.clearCookie('session', cookieOptions)
    return response.status(401).json({ error: 'Sitzung wegen Inaktivität abgelaufen. Bitte erneut anmelden.' })
  }
  db.prepare('UPDATE sessions SET last_activity = ? WHERE id_hash = ?').run(now, hash(sessionId))
  request.auth = session
  next()
}
function pendingMfaUser(request, response, next) {
  const sessionId = cookieValue(request, 'session')
  const session = sessionId && db.prepare('SELECT s.*, u.email, u.name, u.role, u.must_change_password, u.totp_enabled, u.totp_secret FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND s.expires_at > ?').get(hash(sessionId), Date.now())
  if (!session) return response.status(401).json({ error: 'Nicht angemeldet.' })
  request.auth = session
  next()
}

// ─── View Helpers ────────────────────────────────────────────────────
function publicUser(user) { return { email: user.email, name: user.name, role: user.role, avatar: user.avatar || null, mustChangePassword: Boolean(user.must_change_password), totpEnabled: Boolean(user.totp_enabled), mustSetupMfa: false, initials: user.name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase() } }
function ticketView(ticket) {
  const attachments = db.prepare('SELECT filename, original_name FROM ticket_attachments WHERE ticket_id = ?').all(ticket.id) || [];
  return { id: ticket.public_id, title: ticket.title, description: ticket.description, requester: ticket.requester_name, team: ['Administrator', 'Mitarbeiter'].includes(ticket.requester_role) ? 'IT-Support' : 'Kundenanfrage', category: ticket.category, priority: ticket.priority, status: ticket.status, updated: ticket.updated_at, customerCanReply: Boolean(ticket.customer_can_reply), initials: ticket.requester_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), tone: ['Administrator', 'Mitarbeiter'].includes(ticket.requester_role) ? 'teal' : 'coral' , attachments };
}
function findTicketForUser(publicId, user) {
  const ticket = db.prepare('SELECT * FROM tickets WHERE public_id = ?').get(publicId)
  if (!ticket) return null
  if (['Administrator', 'Mitarbeiter'].includes(user.role)) return ticket
  if (ticket.requester_id === user.user_id) return ticket
  const commented = db.prepare('SELECT 1 FROM comments WHERE ticket_id = ? AND author_id = ?').get(ticket.id, user.user_id)
  if (commented) return ticket
  return null
}

// ─── Session Management ──────────────────────────────────────────────
function createSession(response, user, mfaVerified = true) {
  const sessionId = randomToken(); const csrfToken = randomToken(24); const now = Date.now()
  db.prepare('INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at, last_activity, mfa_verified) VALUES (?, ?, ?, ?, ?, ?)').run(hash(sessionId), user.id, csrfToken, now + SESSION_TTL_MS, now, mfaVerified ? 1 : 0)
  response.cookie('session', sessionId, { ...cookieOptions, maxAge: SESSION_TTL_MS }); response.cookie('csrf_token', csrfToken, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS })
}
function sendNotification(to, subject, text) {
  if (!mailTransporter || !to || !mailFrom) return
  mailTransporter.sendMail({ from: mailFrom, to, subject: `Ticket Support: ${subject}`, text }).catch((error) => console.error('Notification email failed:', error.message))
}

// ─── Validation Schemas ─────────────────────────────────────────────
const credentials = z.object({ email: z.string().trim().email().max(254), password: z.string().min(8).max(128) })
const ticketInput = z.object({ title: z.string().trim().min(3).max(160), description: z.string().trim().min(15).max(5000), category: z.enum(['Hardware', 'Software', 'Sonstiges']), priority: z.enum(['Niedrig', 'Mittel', 'Hoch']) })
const ticketStatus = z.enum(['Offen', 'In Bearbeitung', 'Wartet auf Rückmeldung', 'Gelöst'])
const commentInput = z.object({ body: z.string().trim().min(2).max(5000), internal: z.boolean().optional() })
const articleInput = z.object({ title: z.string().trim().min(3).max(100), category: z.string().trim().min(2).max(50), content: z.string().trim().min(10).max(5000) })

// ─── CSRF Endpoint ──────────────────────────────────────────────────
app.get('/api/csrf', (request, response) => { let token = cookieValue(request, 'csrf_token'); if (!token) { token = randomToken(24); response.cookie('csrf_token', token, { ...cookieOptions, httpOnly: false, maxAge: SESSION_TTL_MS }) } response.json({ ok: true }) })

// ─── Auth Routes ─────────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, requireCsrf, (request, response) => {
  const parsed = credentials.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte gültige Zugangsdaten eingeben.' })
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(parsed.data.email)
  if (!user || !verifyPassword(parsed.data.password, user.password_hash)) {
    auditLog(request, 'auth.login.failed', 'user', parsed.data.email, 'Ungültige Zugangsdaten')
    return response.status(401).json({ error: 'E-Mail oder Passwort ist nicht korrekt.' })
  }
  if (user.totp_enabled) {
    createSession(response, user, false)
    auditLog(request, 'auth.login.mfa_pending', 'user', String(user.id), user.email)
    return response.json({ mfaRequired: true })
  }
  createSession(response, user, true)
  auditLog(request, 'auth.login', 'user', String(user.id), user.email)
  response.json({ user: publicUser(user) })
})

app.post('/api/auth/logout', currentUser, requireCsrf, (request, response) => {
  auditLog(request, 'auth.logout', 'user', String(request.auth.user_id), request.auth.email)
  db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(hash(cookieValue(request, 'session'))); response.clearCookie('session', cookieOptions); response.json({ ok: true })
})
app.get('/api/auth/me', currentUser, (request, response) => response.json({ user: publicUser(request.auth) }))
app.post('/api/auth/change-password', currentUser, requireCsrf, (request, response) => {
  const schema = z.object({ currentPassword: z.string().min(1), newPassword: z.string().min(8).max(128) })
  const parsed = schema.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte aktuelles und neues Passwort angeben (mind. 8 Zeichen).' })
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  if (!user || !verifyPassword(parsed.data.currentPassword, user.password_hash)) return response.status(401).json({ error: 'Das aktuelle Passwort ist nicht korrekt.' })
  if (parsed.data.currentPassword === parsed.data.newPassword) return response.status(400).json({ error: 'Das neue Passwort muss sich vom aktuellen unterscheiden.' })
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(passwordHash(parsed.data.newPassword), user.id)
  auditLog(request, 'auth.password.changed', 'user', String(user.id), user.email)
  response.json({ ok: true, user: publicUser({ ...user, must_change_password: 0 }) })
})

// ─── TOTP / MFA Routes ──────────────────────────────────────────────
app.post('/api/auth/totp/validate', authLimiter, pendingMfaUser, requireCsrf, (request, response) => {
  const parsed = z.object({ code: z.string().length(6) }).safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte einen 6-stelligen Code eingeben.' })
  if (!request.auth.totp_enabled || !request.auth.totp_secret) return response.status(400).json({ error: 'MFA ist nicht aktiviert.' })
  if (!verifyTOTP(request.auth.totp_secret, parsed.data.code)) {
    auditLog(request, 'auth.mfa.failed', 'user', String(request.auth.user_id), request.auth.email)
    return response.status(401).json({ error: 'Ungültiger Code. Bitte erneut versuchen.' })
  }
  const sessionId = cookieValue(request, 'session')
  db.prepare('UPDATE sessions SET mfa_verified = 1, last_activity = ? WHERE id_hash = ?').run(Date.now(), hash(sessionId))
  auditLog(request, 'auth.login', 'user', String(request.auth.user_id), `MFA-verifiziert: ${request.auth.email}`)
  response.json({ user: publicUser(request.auth) })
})
app.post('/api/auth/totp/setup', currentUser, requireCsrf, (request, response) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  if (user.totp_enabled) return response.status(400).json({ error: 'MFA ist bereits aktiviert.' })
  const secret = generateTOTPSecret()
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret, user.id)
  response.json({ secret, uri: buildTOTPUri(secret, user.email) })
})
app.post('/api/auth/totp/verify', currentUser, requireCsrf, (request, response) => {
  const parsed = z.object({ code: z.string().length(6) }).safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte einen 6-stelligen Code eingeben.' })
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  if (!user.totp_secret) return response.status(400).json({ error: 'Bitte zuerst MFA-Setup starten.' })
  if (user.totp_enabled) return response.status(400).json({ error: 'MFA ist bereits aktiviert.' })
  if (!verifyTOTP(user.totp_secret, parsed.data.code)) return response.status(401).json({ error: 'Ungültiger Code. Stelle sicher, dass die Zeit auf deinem Gerät korrekt ist.' })
  db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').run(user.id)
  auditLog(request, 'auth.mfa.enabled', 'user', String(user.id), user.email)
  response.json({ ok: true, user: publicUser({ ...user, totp_enabled: 1 }) })
})
app.post('/api/auth/totp/disable', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const parsed = z.object({ userId: z.number().int().positive() }).safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Ungültige Benutzer-ID.' })
  if (parsed.data.userId === request.auth.user_id) return response.status(400).json({ error: 'Du kannst deine eigene MFA nicht deaktivieren.' })
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(parsed.data.userId)
  if (!target) return response.status(404).json({ error: 'Benutzer nicht gefunden.' })
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(parsed.data.userId)
  auditLog(request, 'auth.mfa.disabled', 'user', String(parsed.data.userId), `Deaktiviert durch ${request.auth.email} für ${target.email}`)
  response.json({ ok: true })
})
app.delete('/api/auth/totp', currentUser, requireCsrf, (request, response) => {
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(request.auth.user_id)
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  auditLog(request, 'auth.mfa.disabled', 'user', String(user.id), `Selbst deaktiviert durch ${user.email}`)
  response.json({ ok: true, user: publicUser(user) })
})

// ─── Stats & Users ──────────────────────────────────────────────────
app.get('/api/stats', currentUser, (request, response) => {
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const now = new Date()
  const thisMonthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()
  const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString()
  const lastMonthEnd = thisMonthStart
  const openCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'Offen'").get().c
  const inProgressCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE status = 'In Bearbeitung'").get().c
  const loanCount = db.prepare("SELECT COUNT(*) AS c FROM tickets WHERE category = 'Sonstiges' AND status != 'Gelöst'").get().c
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
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Keine Berechtigung.' })
  auditLog(request, 'users.listed', null, null, 'Benutzerliste abgerufen')
  const users = db.prepare('SELECT id, email, name, role, avatar, totp_enabled, created_at FROM users ORDER BY name').all()
  response.json({ users: users.map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, avatar: u.avatar || null, totpEnabled: Boolean(u.totp_enabled), initials: u.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase(), tone: u.role === 'Administrator' ? 'teal' : u.role === 'Mitarbeiter' ? 'blue' : 'coral', createdAt: u.created_at })) })
})

app.get('/api/tickets', currentUser, (request, response) => {
  const isStaffUser = ['Administrator', 'Mitarbeiter'].includes(request.auth.role)
  const { category, priority, status } = request.query
  const page = Math.max(1, Number(request.query.page) || 1)
  const limit = Math.min(100, Math.max(10, Number(request.query.limit) || 20))
  const offset = (page - 1) * limit
  
  let whereStaff = ''
  let whereCustomer = ''
  let params = []
  
  if (isStaffUser) {
    whereStaff = 'WHERE 1=1'
    if (category) { whereStaff += ' AND t.category = ?'; params.push(category) }
    if (priority) { whereStaff += ' AND t.priority = ?'; params.push(priority) }
    if (status) { whereStaff += ' AND t.status = ?'; params.push(status) }
    const countQ = `SELECT COUNT(*) AS c FROM tickets t JOIN users u ON u.id = t.requester_id ${whereStaff}`
    const dataQ = `SELECT t.*, u.name requester_name, u.role requester_role, au.name assignee_name FROM tickets t JOIN users u ON u.id = t.requester_id LEFT JOIN users au ON au.id = t.assigned_to ORDER BY t.updated_at DESC LIMIT ? OFFSET ?`
    params.push(limit, offset)
    const total = db.prepare(countQ).get().c
    const tickets = db.prepare(dataQ).all(...params)
    response.json({ tickets: tickets.map(ticketView), total })
  } else {
    whereCustomer = 'WHERE 1=1'
    if (category) { whereCustomer += ' AND t.category = ?'; params.push(category) }
    if (priority) { whereCustomer += ' AND t.priority = ?'; params.push(priority) }
    if (status) { whereCustomer += ' AND t.status = ?'; params.push(status) }
    const countQ = `SELECT COUNT(*) AS c FROM tickets t JOIN users u ON u.id = t.requester_id LEFT JOIN comments c ON c.ticket_id = t.id ${whereCustomer} AND (t.requester_id = ? OR c.author_id = ?)`
    params.push(request.auth.user_id, request.auth.user_id)
    const dataQ = `SELECT DISTINCT t.*, u.name requester_name, u.role requester_role, au.name assignee_name FROM tickets t JOIN users u ON u.id = t.requester_id LEFT JOIN users au ON au.id = t.assigned_to LEFT JOIN comments c ON c.ticket_id = t.id ${whereCustomer} AND (t.requester_id = ? OR c.author_id = ?) ORDER BY t.updated_at DESC LIMIT ? OFFSET ?`
    params.push(request.auth.user_id, request.auth.user_id, limit, offset)
    const total = db.prepare(countQ).get(...params.slice(0, -2)).c
    const tickets = db.prepare(dataQ).all(...params)
    response.json({ tickets: tickets.map(ticketView) })
  }
})
app.post('/api/tickets', currentUser, requireCsrf, upload.array('attachments', 5), (request, response) => {
  const parsed = ticketInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Betreff und eine Beschreibung mit mindestens 15 Zeichen sind erforderlich.' })
  
  const existing = db.prepare('SELECT * FROM tickets WHERE category = ? AND title = ? AND status IN (?, ?)').get(parsed.data.category, parsed.data.title, 'Offen', 'In Bearbeitung')
  if (existing) {
    db.prepare('INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)').run(existing.id, request.auth.user_id, `Ich habe dasselbe Problem: ${parsed.data.description}`)
    db.prepare('UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(existing.id)
    if (request.files && request.files.length > 0) {
      const insertAttachment = db.prepare('INSERT INTO ticket_attachments (ticket_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)');
      for (const file of request.files) insertAttachment.run(existing.id, file.filename, file.originalname, file.mimetype, file.size);
    }
    auditLog(request, 'ticket.commented', 'ticket', existing.public_id, 'Sammelticket aktualisiert.')
    const ticket = db.prepare('SELECT t.*, u.name requester_name, u.role requester_role FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.id = ?').get(existing.id)
    return response.status(201).json({ ticket: ticketView(ticket), message: 'Ein Sammelticket für dieses Problem existiert bereits. Deine Anfrage wurde als Kommentar hinzugefügt.' })
  }

  const nextId = Number(db.prepare("SELECT COALESCE(MAX(id), 1049) + 1 AS next_id FROM tickets").get().next_id)
  const publicId = `TK-${nextId}`
  db.prepare('INSERT INTO tickets (public_id, title, description, requester_id, category, priority, status) VALUES (?, ?, ?, ?, ?, ?, ?)').run(publicId, parsed.data.title, parsed.data.description, request.auth.user_id, parsed.data.category, parsed.data.priority, 'Offen')
  
  const internalTicketIdResult = db.prepare('SELECT id FROM tickets WHERE public_id = ?').get(publicId);
  if (request.files && request.files.length > 0 && internalTicketIdResult) {
    const insertAttachment = db.prepare('INSERT INTO ticket_attachments (ticket_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)');
    for (const file of request.files) insertAttachment.run(internalTicketIdResult.id, file.filename, file.originalname, file.mimetype, file.size);
  }

  const ticket = db.prepare('SELECT t.*, u.name requester_name, u.role requester_role FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.public_id = ?').get(publicId)
  auditLog(request, 'ticket.created', 'ticket', publicId, `${parsed.data.title} (${parsed.data.category}, ${parsed.data.priority})`)
  const requester = db.prepare('SELECT email FROM users WHERE id = ?').get(request.auth.user_id)
  
  if (typeof sendNotification === 'function') {
    sendNotification(requester?.email, `Ticket ${publicId} erstellt`, `Dein Ticket "${ticket.title}" wurde erstellt. Status: ${ticket.status}.`)
    if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) sendNotification(process.env.SUPPORT_EMAIL || adminEmail, `Neue Anfrage ${publicId}`, `${request.auth.name} hat "${ticket.title}" erstellt.`)
  }
  response.status(201).json({ ticket: ticketView(ticket) })
})
app.get('/api/tickets/:id/comments', currentUser, (request, response) => {
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  auditLog(request, 'ticket.viewed', 'ticket', request.params.id, null)
  const comments = db.prepare('SELECT c.id, c.body, c.created_at, c.is_internal, u.name author_name, u.role author_role FROM comments c JOIN users u ON u.id = c.author_id WHERE c.ticket_id = ? ORDER BY c.created_at ASC, c.id ASC').all(ticket.id)
  const isCustomer = request.auth.role === 'Kunde';
  response.json({ comments: comments.filter(c => !isCustomer || !c.is_internal).map((comment) => ({ id: comment.id, body: comment.body, author: comment.author_name, role: ['Administrator', 'Mitarbeiter'].includes(comment.author_role) ? 'Mitarbeiter' : 'Kunde', isInternal: Boolean(comment.is_internal), initials: comment.author_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), createdAt: comment.created_at })) })
})
app.post('/api/tickets/:id/comments', currentUser, requireCsrf, (request, response) => {
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  const isStaff = ['Administrator', 'Mitarbeiter'].includes(request.auth.role)
  if (!isStaff && !ticket.customer_can_reply) return response.status(403).json({ error: 'Antworten sind für dieses Ticket noch nicht freigegeben.' })
  const parsed = commentInput.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Die Antwort muss zwischen 2 und 5000 Zeichen enthalten.' })
  const isInternal = parsed.data.internal ? 1 : 0;
  const result = db.prepare('INSERT INTO comments (ticket_id, author_id, body, is_internal) VALUES (?, ?, ?, ?)').run(ticket.id, request.auth.user_id, parsed.data.body, isInternal)
  db.prepare("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP, status = CASE WHEN status = 'Offen' THEN 'In Bearbeitung' ELSE status END WHERE id = ?").run(ticket.id)
  const comment = db.prepare('SELECT c.id, c.body, c.created_at, c.is_internal, u.name author_name, u.role author_role FROM comments c JOIN users u ON u.id = c.author_id WHERE c.id = ?').get(result.lastInsertRowid)
  auditLog(request, 'ticket.comment.added', 'ticket', request.params.id, `Kommentar von ${comment.author_name}`)
  const recipient = db.prepare('SELECT u.email, t.title FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.id = ?').get(ticket.id)
  if (isStaff) sendNotification(recipient?.email, `Neue Antwort zu ${request.params.id}`, `${comment.author_name} hat auf dein Ticket „${recipient?.title}" geantwortet.`)
  else sendNotification(process.env.SUPPORT_EMAIL || adminEmail, `Kundenantwort zu ${request.params.id}`, `${comment.author_name} hat auf ein Ticket geantwortet.`)
  response.status(201).json({ comment: { id: comment.id, body: comment.body, author: comment.author_name, role: isStaff ? 'Mitarbeiter' : 'Kunde', isInternal: Boolean(comment.is_internal), initials: comment.author_name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase(), createdAt: comment.created_at } })
})
app.patch('/api/tickets/:id/reply-permission', currentUser, requireCsrf, (request, response) => {
  if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) return response.status(403).json({ error: 'Nur Mitarbeitende dürfen Antwortfreigaben ändern.' })
  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  const allowed = z.boolean().safeParse(request.body?.customerCanReply)
  if (!allowed.success) return response.status(400).json({ error: 'Ungültige Antwortfreigabe.' })
  db.prepare('UPDATE tickets SET customer_can_reply = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(allowed.data ? 1 : 0, ticket.id)
  auditLog(request, 'ticket.reply_permission.changed', 'ticket', request.params.id, `Kundenantwort ${allowed.data ? 'erlaubt' : 'gesperrt'}`)
  response.json({ customerCanReply: allowed.data })
})

app.patch('/api/tickets/:id/priority', currentUser, (request, response) => {
  if (request.auth.role === 'Kunde') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const parsed = z.object({ priority: z.enum(['Niedrig', 'Mittel', 'Hoch']) }).safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Ungültige Priorität.' })
  try {
    const ticket = findTicketForUser(request.params.id, request.auth)
    if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
    db.prepare('UPDATE tickets SET priority = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(parsed.data.priority, ticket.id)
    auditLog(request, 'ticket.priority_updated', 'ticket', ticket.public_id, `Priorität geändert auf ${parsed.data.priority}`)
    response.json({ success: true })
  } catch (err) {
    response.status(500).json({ error: 'Fehler beim Aktualisieren der Priorität.' })
  }
})

app.patch('/api/tickets/:id/status', currentUser, requireCsrf, (request, response) => {
  const status = ticketStatus.safeParse(request.body?.status)
  if (!status.success) return response.status(400).json({ error: 'Ungültiger Status.' })
  
  if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) {
    if (status.data !== 'Gelöst') {
      return response.status(403).json({ error: 'Kunden können Tickets nur als gelöst markieren.' })
    }
  }

  const ticket = findTicketForUser(request.params.id, request.auth)
  if (!ticket) return response.status(404).json({ error: 'Ticket nicht gefunden.' })
  db.prepare("UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE public_id = ?").run(status.data, request.params.id)
  auditLog(request, 'ticket.status.changed', 'ticket', request.params.id, `Status → ${status.data}`)
  const requester = db.prepare('SELECT u.email, t.title FROM tickets t JOIN users u ON u.id = t.requester_id WHERE t.id = ?').get(ticket.id)
  sendNotification(requester?.email, `Status von ${request.params.id} geändert`, `Der Status von „${requester?.title}" wurde auf „${status.data}" gesetzt.`)
  response.json({ ok: true })
})

// ─── Audit Log ──────────────────────────────────────────────────────
app.get('/api/audit-log', currentUser, (request, response) => {
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Keine Berechtigung.' })
  const page = Math.max(1, Number(request.query.page) || 1)
  const limit = Math.min(100, Math.max(10, Number(request.query.limit) || 50))
  const offset = (page - 1) * limit
  const total = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c
  const entries = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?').all(limit, offset)
  response.json({ entries, total, page, totalPages: Math.ceil(total / limit) })
})

// ─── Admin: Create User ─────────────────────────────────────────────
app.post('/api/users', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Nur Administratoren dürfen Benutzer anlegen.' })
  const schema = z.object({ email: z.string().trim().email().max(254), name: z.string().trim().min(2).max(100), password: z.string().min(8).max(128), role: z.enum(['Kunde', 'Mitarbeiter']) })
  const parsed = schema.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Bitte Name, E-Mail, Passwort (mind. 8 Zeichen) und Rolle angeben.' })
  try {
    const result = db.prepare('INSERT INTO users (email, name, role, password_hash, must_change_password) VALUES (?, ?, ?, ?, ?)').run(parsed.data.email.toLowerCase(), parsed.data.name, parsed.data.role, passwordHash(parsed.data.password), 1)
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid)
    auditLog(request, 'user.created', 'user', String(user.id), `${user.name} (${user.role}) angelegt durch ${request.auth.email}`)
    response.status(201).json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, initials: user.name.split(' ').map((p) => p[0]).join('').slice(0, 2).toUpperCase(), tone: user.role === 'Mitarbeiter' ? 'blue' : 'coral', createdAt: user.created_at } })
  } catch { response.status(409).json({ error: 'Diese E-Mail-Adresse ist bereits vergeben.' }) }
})

// ─── Admin: Change User Role ────────────────────────────────────────
app.patch('/api/users/:id/role', currentUser, requireCsrf, (request, response) => {
  if (request.auth.role !== 'Administrator') return response.status(403).json({ error: 'Nur Administratoren dürfen Rollen ändern.' })
  const parsed = z.object({ role: z.enum(['Kunde', 'Mitarbeiter']) }).safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Ungültige Rolle.' })
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(request.params.id))
  if (!target) return response.status(404).json({ error: 'Benutzer nicht gefunden.' })
  if (target.role === 'Administrator') return response.status(403).json({ error: 'Administrator-Rolle kann nicht geändert werden.' })
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(parsed.data.role, target.id)
  auditLog(request, 'user.role.changed', 'user', String(target.id), `${target.email}: ${target.role} → ${parsed.data.role}`)
  response.json({ ok: true })
})

// ─── Profile Update ─────────────────────────────────────────────────
app.patch('/api/profile', currentUser, requireCsrf, (request, response) => {
  const schema = z.object({ name: z.string().trim().min(2).max(100).optional(), avatar: z.string().max(500000).optional(), password: z.string().min(8).optional() })
  const parsed = schema.safeParse(request.body)
  if (!parsed.success) return response.status(400).json({ error: 'Ungültige Profildaten.' })
  const updates = []
  const values = []
  if (parsed.data.name) { updates.push('name = ?'); values.push(parsed.data.name) }
  if (parsed.data.avatar !== undefined) { updates.push('avatar = ?'); values.push(parsed.data.avatar || null) }
  if (parsed.data.password) { updates.push('password_hash = ?'); values.push(hashPassword(parsed.data.password)) }
  if (updates.length === 0) return response.status(400).json({ error: 'Keine Änderungen angegeben.' })
  values.push(request.auth.user_id)
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values)
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.auth.user_id)
  auditLog(request, 'profile.updated', 'user', String(user.id), `Profil aktualisiert: ${updates.join(', ')}`)
  response.json({ user: publicUser(user) })
})

// ─── Article Routes ──────────────────────────────────────────────────
app.get('/api/articles', currentUser, (request, response) => {
  const articles = db.prepare('SELECT * FROM articles ORDER BY title ASC').all();
  response.json({ articles });
});

app.post('/api/articles', currentUser, requireCsrf, (request, response) => {
  if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) return response.status(403).json({ error: 'Fehlende Berechtigung.' });
  const parsed = articleInput.safeParse(request.body);
  if (!parsed.success) return response.status(400).json({ error: parsed.error.errors[0].message });
  
  const result = db.prepare('INSERT INTO articles (title, category, content) VALUES (?, ?, ?)').run(parsed.data.title, parsed.data.category, parsed.data.content);
  const newArticle = db.prepare('SELECT * FROM articles WHERE id = ?').get(result.lastInsertRowid);
  
  auditLog(request, 'article.created', 'article', String(newArticle.id), `Artikel "${newArticle.title}" erstellt`);
  response.json({ article: newArticle });
});

app.put('/api/articles/:id', currentUser, requireCsrf, (request, response) => {
  if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) return response.status(403).json({ error: 'Fehlende Berechtigung.' });
  const parsed = articleInput.safeParse(request.body);
  if (!parsed.success) return response.status(400).json({ error: parsed.error.errors[0].message });
  
  const existing = db.prepare('SELECT * FROM articles WHERE id = ?').get(request.params.id);
  if (!existing) return response.status(404).json({ error: 'Artikel nicht gefunden.' });
  
  db.prepare('UPDATE articles SET title = ?, category = ?, content = ? WHERE id = ?').run(parsed.data.title, parsed.data.category, parsed.data.content, request.params.id);
  const updated = db.prepare('SELECT * FROM articles WHERE id = ?').get(request.params.id);
  
  auditLog(request, 'article.updated', 'article', String(updated.id), `Artikel "${updated.title}" bearbeitet`);
  response.json({ article: updated });
});

app.delete('/api/articles/:id', currentUser, requireCsrf, (request, response) => {
  if (!['Administrator', 'Mitarbeiter'].includes(request.auth.role)) return response.status(403).json({ error: 'Fehlende Berechtigung.' });
  const existing = db.prepare('SELECT * FROM articles WHERE id = ?').get(request.params.id);
  if (!existing) return response.status(404).json({ error: 'Artikel nicht gefunden.' });
  
  db.prepare('DELETE FROM articles WHERE id = ?').run(request.params.id);
  
  auditLog(request, 'article.deleted', 'article', request.params.id, `Artikel "${existing.title}" gelöscht`);
  response.json({ ok: true });
});



// ─── Static & Error Handling ─────────────────────────────────────────
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
app.listen(port, () => console.log(`Ticket System server listening on http://localhost:${port}`))
// Seed articles if empty
const articleCount = db.prepare('SELECT COUNT(*) AS count FROM articles').get().count;
if (articleCount === 0) {
  const insertArticle = db.prepare('INSERT INTO articles (title, category, content) VALUES (?, ?, ?)');
  insertArticle.run('Passwort zurücksetzen', 'Passwort', 'Falls du dein Passwort vergessen hast, kannst du es in den Einstellungen selbst ändern. Ein Admin kann es zur Not auch zurücksetzen.');
  insertArticle.run('Drucker druckt nicht', 'Hardware', 'Überprüfe zuerst, ob der Drucker eingeschaltet ist und Papier hat. Starte ihn neu. Hilft das nicht, erstelle ein Ticket.');
  insertArticle.run('WLAN-Verbindung', 'Netzwerk', 'Das Gast-WLAN ist für alle offenen Geräte. Für das interne Netz benötigst du das Passwort aus dem Passwort-Safe.');
  insertArticle.run('VPN Zugang', 'VPN', 'VPN-Zugänge werden nur von Admins eingerichtet. Du erhältst dann eine Konfigurationsdatei per sicherer Nachricht.');
}


// ─── Cleanup Old Tickets ─────────────────────────────────────────────
function cleanupOldTickets() {
  const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  const oldTickets = db.prepare("SELECT id FROM tickets WHERE status = 'Gelöst' AND updated_at < ?").all(fiveDaysAgo);
  if (oldTickets.length === 0) return;
  const ticketIds = oldTickets.map(t => t.id);
  const placeholders = ticketIds.map(() => '?').join(',');
  const attachments = db.prepare(`SELECT filename FROM ticket_attachments WHERE ticket_id IN (${placeholders})`).all(...ticketIds);
  
  for (const att of attachments) {
    try { fs.unlinkSync(path.join(uploadDir, att.filename)); } 
    catch (err) { console.error('Konnte Datei nicht löschen:', att.filename, err.message); }
  }
  db.prepare(`DELETE FROM tickets WHERE id IN (${placeholders})`).run(...ticketIds);
  console.log(`${ticketIds.length} alte Tickets (älter als 5 Tage) gelöscht.`);
}
setInterval(cleanupOldTickets, 12 * 60 * 60 * 1000); // 12 Stunden
setTimeout(cleanupOldTickets, 5000);

