import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import path from 'node:path'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

async function availablePort() {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address()
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  return port
}

function storeCookies(jar, response) {
  const cookies = response.headers.getSetCookie?.() || [response.headers.get('set-cookie')].filter(Boolean)
  for (const cookie of cookies) {
    const pair = cookie.split(';', 1)[0]
    const separator = pair.indexOf('=')
    if (separator > 0) jar[pair.slice(0, separator)] = pair.slice(separator + 1)
  }
}

function cookieHeaders(jar, includeCsrf = true) {
  const headers = { cookie: Object.entries(jar).map(([name, value]) => `${name}=${value}`).join('; ') }
  if (includeCsrf && jar.csrf_token) headers['x-csrf-token'] = jar.csrf_token
  return headers
}

async function jsonRequest(baseUrl, route, jar, { method = 'GET', body, csrf = true } = {}) {
  const headers = cookieHeaders(jar, csrf)
  if (body !== undefined) headers['content-type'] = 'application/json'
  return fetch(`${baseUrl}${route}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}

async function login(baseUrl, email, password) {
  const jar = {}
  const csrfResponse = await fetch(`${baseUrl}/api/csrf`)
  assert.equal(csrfResponse.status, 200)
  storeCookies(jar, csrfResponse)
  const response = await jsonRequest(baseUrl, '/api/auth/login', jar, {
    method: 'POST',
    body: { email, password },
  })
  storeCookies(jar, response)
  assert.equal(response.status, 200)
  return { jar, ...(await response.json()) }
}

async function changePassword(baseUrl, client, currentPassword, newPassword) {
  const response = await jsonRequest(baseUrl, '/api/auth/change-password', client.jar, {
    method: 'POST',
    body: { currentPassword, newPassword },
  })
  assert.equal(response.status, 200)
  const result = await response.json()
  assert.equal(result.user.mustChangePassword, false)
  return result.user
}

async function createTicket(baseUrl, client, title, attachments = []) {
  const form = new FormData()
  form.set('title', title)
  form.set('description', `Integrationstest für ${title}; ausreichend lange Beschreibung.`)
  form.set('category', 'Hardware')
  form.set('priority', 'Mittel')
  for (const attachment of attachments) {
    form.append('attachments', new Blob([attachment.data], { type: attachment.type }), attachment.name)
  }
  return fetch(`${baseUrl}/api/tickets`, {
    method: 'POST',
    headers: cookieHeaders(client.jar),
    body: form,
  })
}

async function waitForServer(baseUrl, child, getOutput) {
  const deadline = Date.now() + 10000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Testserver beendet: ${getOutput()}`)
    try {
      const response = await fetch(`${baseUrl}/api/csrf`)
      if (response.ok) return
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`Testserver startet nicht: ${getOutput()}`)
}

test('auth, ticket authorization, uploads, CSRF and deletion', { timeout: 30000 }, async () => {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'ticket-system-test-'))
  const port = await availablePort()
  const baseUrl = `http://127.0.0.1:${port}`
  const initialPassword = 'Initial-Test-Password-581!'
  const changedPassword = 'Changed-Test-Password-394!'
  const child = spawn(process.execPath, ['server.js'], {
    cwd: projectRoot,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      HOST: '127.0.0.1',
      PORT: String(port),
      DATA_DIR: dataDir,
      ADMIN_EMAIL: 'admin@test.invalid',
      ADMIN_PASSWORD: initialPassword,
      RESOLVED_TICKET_RETENTION_DAYS: '0',
      SMTP_HOST: '',
      SMTP_USER: '',
      SMTP_PASSWORD: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  child.stdout.setEncoding('utf8').on('data', (chunk) => { output += chunk })
  child.stderr.setEncoding('utf8').on('data', (chunk) => { output += chunk })

  try {
    await waitForServer(baseUrl, child, () => output)
    assert.equal((await fetch(`${baseUrl}/api/tickets`)).status, 401)

    const admin = await login(baseUrl, 'admin@test.invalid', initialPassword)
    assert.equal(admin.user.mustChangePassword, true)
    const blockedUntilPasswordChange = await jsonRequest(baseUrl, '/api/tickets', admin.jar)
    assert.equal(blockedUntilPasswordChange.status, 403)
    assert.equal((await blockedUntilPasswordChange.json()).passwordChangeRequired, true)
    await changePassword(baseUrl, admin, initialPassword, changedPassword)

    const avatar = `data:image/png;base64,${Buffer.alloc(40000).toString('base64')}`
    const profileUpdate = await jsonRequest(baseUrl, '/api/profile', admin.jar, {
      method: 'PATCH',
      body: { avatar },
    })
    assert.equal(profileUpdate.status, 200)
    assert.equal((await profileUpdate.json()).user.avatar, avatar)

    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/kGQAAAAASUVORK5CYII=', 'base64')
    const created = await createTicket(baseUrl, admin, 'Upload access test', [
      { name: 'tiny.png', type: 'image/png', data: png },
    ])
    assert.equal(created.status, 201)
    const firstTicket = (await created.json()).ticket
    assert.equal(firstTicket.id, 'TK-1050')
    const filename = firstTicket.attachments[0].filename

    const publicUpload = await fetch(`${baseUrl}/uploads/${filename}`)
    assert.equal(publicUpload.status, 401)
    const authenticatedUpload = await fetch(`${baseUrl}/uploads/${filename}`, {
      headers: cookieHeaders(admin.jar, false),
    })
    assert.equal(authenticatedUpload.status, 200)
    assert.equal(authenticatedUpload.headers.get('x-content-type-options'), 'nosniff')

    const badPriorityCsrf = await jsonRequest(baseUrl, `/api/tickets/${firstTicket.id}/priority`, admin.jar, {
      method: 'PATCH',
      body: { priority: 'Hoch' },
      csrf: false,
    })
    assert.equal(badPriorityCsrf.status, 403)
    const priorityUpdate = await jsonRequest(baseUrl, `/api/tickets/${firstTicket.id}/priority`, admin.jar, {
      method: 'PATCH',
      body: { priority: 'Hoch' },
    })
    assert.equal(priorityUpdate.status, 200)

    const claim = await jsonRequest(baseUrl, `/api/tickets/${firstTicket.id}/claim`, admin.jar, { method: 'PATCH' })
    assert.equal(claim.status, 200)
    assert.equal((await claim.json()).ticket.status, 'In Bearbeitung')

    const secondCreated = await createTicket(baseUrl, admin, 'Ticket numbering test')
    assert.equal(secondCreated.status, 201)
    const secondTicket = (await secondCreated.json()).ticket
    assert.equal(secondTicket.id, 'TK-1051')

    const articleResponse = await jsonRequest(baseUrl, '/api/articles', admin.jar, {
      method: 'POST',
      body: { title: 'Delete test article', category: 'Test', content: 'Temporary article for integration testing.' },
    })
    assert.equal(articleResponse.status, 200)
    const article = (await articleResponse.json()).article

    const staffCreate = await jsonRequest(baseUrl, '/api/users', admin.jar, {
      method: 'POST',
      body: { email: 'staff@test.invalid', name: 'Test Staff', password: initialPassword, role: 'Mitarbeiter' },
    })
    assert.equal(staffCreate.status, 201)
    const staffUser = (await staffCreate.json()).user

    const staff = await login(baseUrl, 'staff@test.invalid', initialPassword)
    assert.equal(staff.user.mustChangePassword, true)
    await changePassword(baseUrl, staff, initialPassword, changedPassword)
    const staffTicketDelete = await jsonRequest(baseUrl, `/api/tickets/${firstTicket.id}`, staff.jar, { method: 'DELETE' })
    assert.equal(staffTicketDelete.status, 403)

    const staffCannotGrantRights = await jsonRequest(baseUrl, `/api/users/${staffUser.id}`, staff.jar, {
      method: 'PATCH',
      body: { permissions: ['deleteTickets'] },
    })
    assert.equal(staffCannotGrantRights.status, 403)

    const delegateCreate = await jsonRequest(baseUrl, '/api/users', admin.jar, {
      method: 'POST',
      body: { email: 'delegate@test.invalid', name: 'Ticket Delegate', password: initialPassword, role: 'Mitarbeiter' },
    })
    assert.equal(delegateCreate.status, 201)
    const delegateUser = (await delegateCreate.json()).user
    const grantDelete = await jsonRequest(baseUrl, `/api/users/${delegateUser.id}`, admin.jar, {
      method: 'PATCH',
      body: { permissions: ['deleteTickets'] },
    })
    assert.equal(grantDelete.status, 200)
    assert.deepEqual((await grantDelete.json()).user.permissions, ['deleteTickets'])

    const delegate = await login(baseUrl, 'delegate@test.invalid', initialPassword)
    assert.deepEqual(delegate.user.permissions, ['deleteTickets'])
    await changePassword(baseUrl, delegate, initialPassword, changedPassword)
    const delegatedDelete = await jsonRequest(baseUrl, `/api/tickets/${secondTicket.id}`, delegate.jar, { method: 'DELETE' })
    assert.equal(delegatedDelete.status, 200)
    const delegatedUserList = await jsonRequest(baseUrl, '/api/users', delegate.jar)
    assert.equal(delegatedUserList.status, 403)

    const customerCreate = await jsonRequest(baseUrl, '/api/users', admin.jar, {
      method: 'POST',
      body: { email: 'customer@test.invalid', name: 'Test Customer', password: initialPassword, role: 'Kunde' },
    })
    assert.equal(customerCreate.status, 201)
    const customer = await login(baseUrl, 'customer@test.invalid', initialPassword)
    assert.equal(customer.user.mustChangePassword, true)
    await changePassword(baseUrl, customer, initialPassword, changedPassword)
    const customerUpload = await fetch(`${baseUrl}/uploads/${filename}`, {
      headers: cookieHeaders(customer.jar, false),
    })
    assert.equal(customerUpload.status, 404)
    const customerArticleDelete = await jsonRequest(baseUrl, `/api/articles/${article.id}`, customer.jar, { method: 'DELETE' })
    assert.equal(customerArticleDelete.status, 403)

    const articleDelete = await jsonRequest(baseUrl, `/api/articles/${article.id}`, admin.jar, { method: 'DELETE' })
    assert.equal(articleDelete.status, 200)

    const ticketDelete = await jsonRequest(baseUrl, `/api/tickets/${firstTicket.id}`, admin.jar, { method: 'DELETE' })
    assert.equal(ticketDelete.status, 200)
    const removedUpload = await fetch(`${baseUrl}/uploads/${filename}`, {
      headers: cookieHeaders(admin.jar, false),
    })
    assert.equal(removedUpload.status, 404)
    const tickets = await jsonRequest(baseUrl, '/api/tickets', admin.jar)
    assert.equal((await tickets.json()).tickets.some((ticket) => ticket.id === firstTicket.id), false)
  } finally {
    if (child.exitCode === null) {
      child.kill()
      await Promise.race([
        new Promise((resolve) => child.once('exit', resolve)),
        new Promise((resolve) => setTimeout(resolve, 3000)),
      ])
    }
    await rm(dataDir, { recursive: true, force: true })
  }
})

test('production bootstrap rejects template and short admin passwords', { timeout: 15000 }, async () => {
  for (const password of ['replace-with-a-unique-long-password', 'TooShort!']) {
    const dataDir = await mkdtemp(path.join(tmpdir(), 'ticket-system-bootstrap-test-'))
    const child = spawn(process.execPath, ['server.js'], {
      cwd: projectRoot,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        HOST: '127.0.0.1',
        PORT: '0',
        DATA_DIR: dataDir,
        ADMIN_EMAIL: 'bootstrap@test.invalid',
        ADMIN_PASSWORD: password,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let output = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => { output += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { output += chunk })

    try {
      const exitCode = await new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(null), 5000)
        child.once('exit', (code) => {
          clearTimeout(timeout)
          resolve(code)
        })
      })
      if (exitCode === null) child.kill()
      assert.notEqual(exitCode, null, 'server must refuse unsafe bootstrap credentials')
      assert.notEqual(exitCode, 0, 'server must exit instead of starting with unsafe bootstrap credentials')
      assert.match(output, /ADMIN_PASSWORD/)
    } finally {
      if (child.exitCode === null) child.kill()
      await rm(dataDir, { recursive: true, force: true })
    }
  }
})