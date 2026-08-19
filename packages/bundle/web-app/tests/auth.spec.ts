/**
 * Auth plugin behavior over the real HTTP surface: the transport guard (the
 * login-bypass fix), the login/me/menus/password API, the admin user/role/
 * permission API, role enforcement, the admin-console gate, static dist
 * serving, and the bootstrap index tap. The plugin is applied to a fake
 * webServer that records registrations, and a real node:http server replays
 * the webserver's dispatch (guards → route match → fallback) so requests
 * exercise the same ordering an attacker would hit.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { connect } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { WebGuard, WebServer, WebRoute } from '@deepseek-ai/dsh-host-webserver'
import { apply, Config, type AuthUser } from '../src/auth.ts'

interface Captured {
  routes: WebRoute[]
  guards: WebGuard[]
  fallback: WebRoute['handler'] | undefined
  taps: Array<(html: string) => string>
  server: WebServer
}

/** Fake webServer capturing every registration the plugin makes. */
function fakeWebServer(): Captured {
  const captured: Captured = {
    routes: [],
    guards: [],
    fallback: undefined,
    taps: [],
    server: {
      host: '127.0.0.1',
      port: 4567,
      register: (route: WebRoute) => {
        captured.routes.push(route)
        return () => {
          const at = captured.routes.indexOf(route)
          if (at !== -1) captured.routes.splice(at, 1)
        }
      },
      registerGuard: (guard: WebGuard) => {
        captured.guards.push(guard)
        return () => {
          const at = captured.guards.indexOf(guard)
          if (at !== -1) captured.guards.splice(at, 1)
        }
      },
      registerFallback: (handler: WebRoute['handler']) => {
        captured.fallback = handler
        return () => { captured.fallback = undefined }
      },
      tapIndex: (transform: (html: string) => string) => {
        captured.taps.push(transform)
        return () => {
          const at = captured.taps.indexOf(transform)
          if (at !== -1) captured.taps.splice(at, 1)
        }
      },
      applyIndexTaps: (html: string) => captured.taps.reduce((out, tap) => tap(out), html),
    } as unknown as WebServer,
  }
  return captured
}

/** Longest-prefix-wins route match, mirroring the webserver's `match()`. */
function match(routes: WebRoute[], pathname: string): WebRoute | undefined {
  const exact = routes.find(r => r.kind === 'exact' && r.path === pathname)
  if (exact !== undefined) return exact
  let best: WebRoute | undefined
  for (const route of routes) {
    if (route.kind !== 'prefix') continue
    if (pathname !== route.path && !pathname.startsWith(`${route.path}/`)) continue
    if (best === undefined || route.path.length > best.path.length) best = route
  }
  return best
}

/** One harness instance: temp dist + db, the applied plugin, and a live HTTP server. */
class Harness {
  readonly root: string
  readonly distIndex: string
  readonly dbPath: string
  private readonly captured: Captured
  private readonly ctx: Context
  private readonly http: ReturnType<typeof createServer>
  readonly port: number
  private cookie = ''

  private constructor(    root: string,
    distIndex: string,
    dbPath: string,
    captured: Captured,
    ctx: Context,
    http: ReturnType<typeof createServer>,
    port: number,
  ) {
    this.root = root
    this.distIndex = distIndex
    this.dbPath = dbPath
    this.captured = captured
    this.ctx = ctx
    this.http = http
    this.port = port
  }

  static async start(): Promise<Harness> {
    const root = mkdtempSync(join(tmpdir(), 'dsh-auth-'))
    mkdirSync(join(root, 'dist'))
    const distIndex = join(root, 'dist', 'index.html')
    writeFileSync(distIndex, '<head></head><body>shell</body>')
    const dbPath = join(root, 'auth.db')

    const captured = fakeWebServer()
    const ctx = new Context()
    ctx.provide('webServer', captured.server)
    apply(ctx, new Config({ distIndex, dbPath, sessionExpireHours: 24 }))

    const http = createServer((req, res) => {
      void handleRequest(captured, req, res)
    })
    await new Promise<void>(resolve => http.listen(0, '127.0.0.1', () => { resolve() }))
    const address = http.address()
    const port = typeof address === 'object' && address !== null ? address.port : 0
    return new Harness(root, distIndex, dbPath, captured, ctx, http, port)
  }

  async close(): Promise<void> {
    await new Promise<void>(resolve => this.http.close(() => { resolve() }))
    await this.ctx.fiber.dispose()
    rmSync(this.root, { recursive: true, force: true })
  }

  get taps(): Array<(html: string) => string> { return this.captured.taps }

  /** Record a Set-Cookie response header into the jar. */
  private adoptCookie(res: Response): void {
    const setCookie = res.headers.get('set-cookie')
    if (setCookie === null) return
    const m = setCookie.match(/dsh_token=([^;]*)/)
    this.cookie = m !== null ? `dsh_token=${m[1]}` : ''
  }

  async request(path: string, init: RequestInit = {}): Promise<{    status: number
    body: string
    json: unknown
    location: string | null
    setCookie: string | null
  }> {
    const headers = new Headers(init.headers)
    if (this.cookie !== '') headers.set('cookie', this.cookie)
    const res = await fetch(`http://127.0.0.1:${String(this.port)}${path}`, { ...init, headers, redirect: 'manual' })
    const body = await res.text()
    this.adoptCookie(res)
    let json: unknown
    try { json = JSON.parse(body) } catch { json = undefined }
    return { status: res.status, body, json, location: res.headers.get('location'), setCookie: res.headers.get('set-cookie') }
  }

  async login(username: string, password: string): Promise<number> {
    const res = await this.request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    return res.status
  }

  async api(path: string, method = 'GET', body?: unknown): Promise<{ status: number; data: Record<string, unknown> }> {
    const res = await this.request(path, {
      method,
      ...(body !== undefined ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}),
    })
    return { status: res.status, data: (res.json ?? {}) as Record<string, unknown> }
  }

  async me(): Promise<AuthUser> {
    const res = await this.api('/api/auth/me')
    expect(res.status).toBe(200)
    return res.data as unknown as AuthUser
  }

  /** Log out (clears the jar). */
  async logout(): Promise<void> {
    await this.request('/api/auth/logout', { method: 'POST' })
    this.cookie = ''
  }
}

/** Replay the webserver's dispatch order against the captured registrations. */
async function handleRequest(captured: Captured, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const runGuards = async (index: number): Promise<boolean> => {
    if (index >= captured.guards.length) return true
    let delegated = false
    await captured.guards[index]!({ req, res }, () => { delegated = true })
    if (!delegated) return false
    return runGuards(index + 1)
  }
  if (!(await runGuards(0))) return
  const pathname = new URL(req.url ?? '/', 'http://x').pathname
  const route = match(captured.routes, pathname)
  if (route !== undefined) { await route.handler(req, res); return }
  if (captured.fallback !== undefined) { await captured.fallback(req, res); return }
  res.writeHead(404)
  res.end()
}

const harnesses: Harness[] = []
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(h => h.close()))
})

async function startHarness(): Promise<Harness> {
  const h = await Harness.start()
  harnesses.push(h)
  return h
}

describe('auth transport guard (login bypass fix)', () => {
  it('refuses every unauthenticated surface except the public auth routes', async () => {
    const h = await startHarness()

    // HTML navigation redirects to /login.
    const root = await h.request('/', { headers: { accept: 'text/html' } })
    expect(root.status).toBe(302)
    expect(root.location).toBe('/login')

    // The /api RPC prefix returns 401 JSON without a session — the critical
    // surface that previously bypassed the fallback-only auth check.
    const api = await h.request('/api/sessions.create', { method: 'POST' })
    expect(api.status).toBe(401)
    expect(api.json).toEqual({ error: '未登录' })

    // The plugin bundle prefix is equally gated.
    const plugin = await h.request('/plugins/web/client.js', { headers: { accept: 'text/html' } })
    expect(plugin.status).toBe(302)
    expect(plugin.location).toBe('/login')

    // The admin console requires login first.
    const admin = await h.request('/admin', { headers: { accept: 'text/html' } })
    expect(admin.status).toBe(302)
    expect(admin.location).toBe('/login')

    // Public auth surface stays reachable without a session.
    const loginPage = await h.request('/login')
    expect(loginPage.status).toBe(200)
    expect(loginPage.body).toContain('登录')
    const logout = await h.request('/api/auth/logout', { method: 'POST' })
    expect(logout.status).toBe(200)
  })

  it('admits the SPA and API after login and revokes on logout', async () => {
    const h = await startHarness()

    const bad = await h.login('admin', 'wrong')
    expect(bad).toBe(401)

    expect(await h.login('admin', 'admin123')).toBe(200)
    const root = await h.request('/', { headers: { accept: 'text/html' } })
    expect(root.status).toBe(200)
    expect(root.body).toContain('shell')

    const me = await h.me()
    expect(me.username).toBe('admin')
    expect(me.role.name).toBe('admin')
    expect(me.permissions).toContain('api:admin')
    expect(me.permissions).toContain('page:admin')

    // An authenticated API call passes the guard and reaches the dispatch
    // surface (here the static fallback, which answers non-GET with 405 — the
    // point is it is no longer a 401).
    const sessions = await h.api('/api/sessions.create', 'POST', {})
    expect(sessions.status).toBe(405)

    // Logout invalidates the session server-side.
    await h.logout()
    const after = await h.request('/api/auth/me')
    expect(after.status).toBe(401)
  })

  it('serves static dist through the fallback only for authenticated users', async () => {
    const h = await startHarness()
    // Without a session the dist is not reachable (already covered), and an
    // authenticated session renders the index through the fallback with the
    // bootstrap tap applied.
    await h.login('admin', 'admin123')
    const res = await h.request('/no/such/route', { headers: { accept: 'text/html' } })
    expect(res.status).toBe(200)
    expect(res.body).toContain('shell')
  })
})

describe('roles, pages, and the admin console gate', () => {
  it('returns page menus from role permissions and hides admin-only entries for users', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    const adminMenus = await h.api('/api/auth/menus')
    expect(adminMenus.status).toBe(200)
    const adminKeys = (adminMenus.data.menus as Array<{ key: string }>).map(m => m.key)
    expect(adminKeys).toEqual(expect.arrayContaining(['chat', 'history', 'settings', 'tools', 'admin']))

    // Create a plain user and log in as them.
    await h.api('/api/auth/users', 'POST', { username: 'alice', password: 'alice123', roleId: 2 })
    await h.logout()
    await h.login('alice', 'alice123')
    const me = await h.me()
    expect(me.permissions).toEqual(['page:chat', 'page:history', 'page:tools'])
    const userMenus = await h.api('/api/auth/menus')
    const userKeys = (userMenus.data.menus as Array<{ key: string }>).map(m => m.key)
    expect(userKeys).not.toContain('settings')
    expect(userKeys).not.toContain('admin')
  })

  it('denies the admin API and the console to users without the admin permissions', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    await h.api('/api/auth/users', 'POST', { username: 'bob', password: 'bob123', roleId: 2 })
    await h.logout()
    await h.login('bob', 'bob123')

    const list = await h.api('/api/auth/users')
    expect(list.status).toBe(403)
    const roles = await h.api('/api/auth/roles')
    expect(roles.status).toBe(403)
    const consolePage = await h.request('/admin', { headers: { accept: 'text/html' } })
    expect(consolePage.status).toBe(403)
  })

  it('serves the admin console to an admin', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    const res = await h.request('/admin', { headers: { accept: 'text/html' } })
    expect(res.status).toBe(200)
    expect(res.body).toContain('管理控制台')
    expect(res.body).toContain('用户管理')
  })
})

describe('admin user/role/permission management', () => {
  it('creates, lists, updates, resets, and deletes users', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')

    const created = await h.api('/api/auth/users', 'POST', { username: 'carol', password: 'carol123', displayName: 'Carol', roleId: 2 })
    expect(created.status).toBe(201)
    const createdUser = created.data.user as { id: number; roleId: number; status: number }
    expect(createdUser.roleId).toBe(2)

    const list = await h.api('/api/auth/users')
    const users = list.data.users as Array<{ username: string; roleLabel: string; status: number }>
    expect(users.map(u => u.username)).toContain('carol')

    const updated = await h.api(`/api/auth/users/${String(createdUser.id)}`, 'PATCH', { status: 0, displayName: 'Carol2' })
    expect(updated.status).toBe(200)

    // A disabled user cannot log in.
    await h.logout()
    expect(await h.login('carol', 'carol123')).toBe(401)

    // Re-enable + reset the password, then log in with the new password.
    await h.login('admin', 'admin123')
    await h.api(`/api/auth/users/${String(createdUser.id)}`, 'PATCH', { status: 1, password: 'fresh123' })
    await h.logout()
    expect(await h.login('carol', 'fresh123')).toBe(200)
    await h.logout()

    await h.login('admin', 'admin123')
    const removed = await h.api(`/api/auth/users/${String(createdUser.id)}`, 'DELETE')
    expect(removed.status).toBe(200)
    const after = await h.api('/api/auth/users')
    expect((after.data.users as Array<{ id: number }>).some(u => u.id === createdUser.id)).toBe(false)
  })

  it('creates, configures, and deletes custom roles with permission sets', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')

    const perms = await h.api('/api/auth/permissions')
    const keys = (perms.data.permissions as Array<{ key: string }>).map(p => p.key)
    expect(keys).toEqual(expect.arrayContaining(['page:chat', 'page:admin', 'api:admin']))

    const created = await h.api('/api/auth/roles', 'POST', { name: 'reviewer', label: '审查员', description: '只读审查' })
    expect(created.status).toBe(201)
    const roleId = (created.data.role as { id: number }).id
    expect((created.data.role as { permissions: string[] }).permissions).toEqual([])

    const patched = await h.api(`/api/auth/roles/${String(roleId)}`, 'PATCH', { label: '审查员', permissions: ['page:chat', 'page:history'] })
    expect(patched.status).toBe(200)
    expect((patched.data.role as { permissions: string[] }).permissions).toEqual(['page:chat', 'page:history'])

    // Deleting a system role and an in-use role both fail loudly.
    const sysDel = await h.api('/api/auth/roles/1', 'DELETE')
    expect(sysDel.status).toBe(400)

    // Assign a user to the new role, then deletion is refused while in use.
    const dave = await h.api('/api/auth/users', 'POST', { username: 'dave', password: 'dave123', roleId })
    expect(dave.status).toBe(201)
    const daveId = (dave.data.user as { id: number }).id
    const usedDel = await h.api(`/api/auth/roles/${String(roleId)}`, 'DELETE')
    expect(usedDel.status).toBe(400)

    await h.api(`/api/auth/users/${String(daveId)}`, 'DELETE')
    const okDel = await h.api(`/api/auth/roles/${String(roleId)}`, 'DELETE')
    expect(okDel.status).toBe(200)
  })

  it('refuses to delete, disable, or demote the last active admin', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    const me = await h.me()

    const del = await h.api(`/api/auth/users/${String(me.id)}`, 'DELETE')
    expect(del.status).toBe(400)
    const disable = await h.api(`/api/auth/users/${String(me.id)}`, 'PATCH', { status: 0 })
    expect(disable.status).toBe(400)
    const demote = await h.api(`/api/auth/users/${String(me.id)}`, 'PATCH', { roleId: 2 })
    expect(demote.status).toBe(400)
  })

  it('changes the caller password after verifying the current one', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    const wrong = await h.api('/api/auth/password', 'POST', { currentPassword: 'nope', newPassword: 'newpass1' })
    expect(wrong.status).toBe(400)
    const ok = await h.api('/api/auth/password', 'POST', { currentPassword: 'admin123', newPassword: 'newpass1' })
    expect(ok.status).toBe(200)
    await h.logout()
    expect(await h.login('admin', 'newpass1')).toBe(200)
  })

  it('rejects malformed admin input with a 400', async () => {
    const h = await startHarness()
    await h.login('admin', 'admin123')
    const shortPw = await h.api('/api/auth/users', 'POST', { username: 'x', password: '123', roleId: 2 })
    expect(shortPw.status).toBe(400)
    const dup = await h.api('/api/auth/users', 'POST', { username: 'admin', password: 'secret1', roleId: 1 })
    expect(dup.status).toBe(400)
  })
})

describe('index bootstrap tap', () => {
  it('injects the auth bootstrap into the served index before </head>', async () => {
    const h = await startHarness()
    expect(h.taps.length).toBeGreaterThan(0)
    const applied = h.taps.reduce((out, tap) => tap(out), '<head></head><body>shell</body>')
    expect(applied).toContain('window.__DSH_AUTH__')
    expect(applied).toContain('/api/auth/logout')
  })
})

describe('integration with the real webserver dispatch', () => {
  it('the transport guard gates the /api prefix route and WebSocket upgrades that previously bypassed auth', async () => {
    const { WebServer } = await import('@deepseek-ai/dsh-host-webserver')
    const root = mkdtempSync(join(tmpdir(), 'dsh-auth-live-'))
    mkdirSync(join(root, 'dist'))
    const distIndex = join(root, 'dist', 'index.html')
    writeFileSync(distIndex, '<head></head><body>shell</body>')
    const dbPath = join(root, 'auth.db')

    const ctx = new Context()
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 })
    apply(ctx, new Config({ distIndex, dbPath }))

    // Simulate the client-connection /api prefix route and an upgrade route:
    // these are exactly the handlers the old fallback-only auth could not gate.
    ctx.effect(() => ctx.webServer.register({
      kind: 'prefix',
      path: '/api',
      handler: (_req, res) => { res.writeHead(200); res.end('API-REACHED') },
    }), 'test: /api route')
    ctx.effect(() => ctx.webServer.registerUpgrade({
      path: '/api/events',
      handler: (_req, socket) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: dsh-test\r\n\r\n')
      },
    }), 'test: /api/events upgrade')

    const port = ctx.webServer.port
    const cookie = async (username: string, password: string): Promise<string> => {
      const res = await fetch(`http://127.0.0.1:${String(port)}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        redirect: 'manual',
      })
      const setCookie = res.headers.get('set-cookie')
      const m = setCookie?.match(/dsh_token=([^;]*)/)
      return m !== undefined && m !== null ? `dsh_token=${m[1]}` : ''
    }

    // Unauthenticated /api RPC is rejected by the guard BEFORE the prefix
    // route handler runs — this is the login-bypass fix.
    const anon = await fetch(`http://127.0.0.1:${String(port)}/api/sessions.create`, { method: 'POST', redirect: 'manual' })
    expect(anon.status).toBe(401)
    expect(await anon.text()).toContain('未登录')

    // After login the same route reaches the /api prefix handler.
    const token = await cookie('admin', 'admin123')
    expect(token).not.toBe('')
    const authed = await fetch(`http://127.0.0.1:${String(port)}/api/sessions.create`, {
      method: 'POST',
      headers: { cookie: token },
      redirect: 'manual',
    })
    expect(authed.status).toBe(200)
    expect(await authed.text()).toBe('API-REACHED')

    // WebSocket upgrade without a session is refused by the guard (the socket
    // is destroyed instead of reaching the upgrade handler).
    const refused = connect(port, '127.0.0.1')
    refused.on('error', () => { /* server-side reset is the fixture outcome */ })
    await once(refused, 'connect')
    const refusedClosed = once(refused, 'close')
    refused.write([
      'GET /api/events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-test',
      '',
      '',
    ].join('\r\n'))
    await refusedClosed

    // The authenticated upgrade reaches the handler.
    const accepted = connect(port, '127.0.0.1')
    accepted.on('error', () => { /* handled by close */ })
    await once(accepted, 'connect')
    const acceptedData = once(accepted, 'data')
    accepted.write([
      'GET /api/events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-test',
      `Cookie: ${token}`,
      '',
      '',
    ].join('\r\n'))
    const [upgradeData] = await acceptedData as [Buffer]
    expect(String(upgradeData)).toContain('101 Switching Protocols')
    accepted.destroy()

    await ctx.fiber.dispose()
    rmSync(root, { recursive: true, force: true })
  })
})
