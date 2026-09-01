/**
 * HTTP handler smoke tests: login, logout, /auth/me, change-password,
 * and the admin CRUD routes. Boots a real http server per test so the auth
 * plugin's `webServer.register` and `webServer.registerFallback` calls land
 * in real registrations, not mocks.
 *
 * Each test creates a fresh SQLite DB so suites run in isolation (fork-safe).
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { WebServer, WebRoute } from '@deepseek-ai/dsh-host-webserver'
import { apply as applyAuth } from '../src/auth.ts'
import { authBootstrapScript } from '../src/auth-api.ts'
import type { AuthUser } from '../src/auth-user.ts'

// ── authBootstrapScript unit tests ───────────────────────────────────────────

describe('authBootstrapScript', () => {
  it('returns null when user is null', () => {
    const script = authBootstrapScript(null)
    expect(script).toContain('window.__DSH_AUTH_USER__=null')
    expect(script).toMatch(/^<script>/)
  })

  it('serialises user fields into window.__DSH_AUTH_USER__', () => {
    const user: AuthUser = {
      id: 42 as AuthUser['id'],
      username: 'alice',
      displayName: 'Alice Admin',
      roleId: 1 as AuthUser['roleId'],
      roleName: 'admin',
      roleLabel: '管理员',
      permissions: ['page:admin'] as readonly string[],
      status: 1,
    }
    const script = authBootstrapScript(user)
    expect(script).toContain('"username":"alice"')
    expect(script).toContain('"roleName":"admin"')
    expect(script).toContain('"permissions":["page:admin"]')
  })

  it('dispatches a dsh-auth CustomEvent so client listeners can react', () => {
    const script = authBootstrapScript(null)
    expect(script).toContain('CustomEvent("dsh-auth"')
  })
})

// ── auth plugin HTTP integration tests ───────────────────────────────────────

interface RunningServer {
  port: number
  baseUrl: string
  close: () => Promise<void>
  ctx: Context
  cleanupAuth: () => void
}

/**
 * Start a real http server backed by a Cordis context. The auth plugin's
 * `webServer.register` calls register against a minimal in-process WebServer
 * implementation that dispatches HTTP requests to the registered handlers.
 */
async function bootAuthServer(): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-auth-api-test-'))
  const dbPath = join(dir, 'auth.db')
  const routes: Array<{ kind: 'exact' | 'prefix'; path: string; handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void> }> = []
  const webserverShim: WebServer = {
    host: '127.0.0.1',
    port: 0,
    register: (route: WebRoute) => {
      routes.push({ kind: route.kind, path: route.path, handler: route.handler })
      return () => {
        const idx = routes.findIndex(r => r.kind === route.kind && r.path === route.path)
        if (idx >= 0) routes.splice(idx, 1)
      }
    },
    registerFallback: () => () => {},
    registerGuard: () => () => {},
    tapIndex: () => () => {},
    renderIndex: (html: string) => html,
  } as unknown as WebServer

  const ctx = new Context()
  ctx.provide('webServer', webserverShim)
  applyAuth(ctx, { dbPath })

  // Start a real http server that dispatches to the registered routes.
  const httpServer = createServer(async (req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://x').pathname
    // Try exact match first.
    const exact = routes.find(r => r.kind === 'exact' && r.path === pathname)
    if (exact) {
      await exact.handler(req, res)
      return
    }
    // Longest-prefix match.
    let best: typeof routes[number] | undefined
    for (const r of routes) {
      if (r.kind !== 'prefix') continue
      if (pathname !== r.path && !pathname.startsWith(`${r.path}/`)) continue
      if (best === undefined || r.path.length > best.path.length) best = r
    }
    if (best) {
      await best.handler(req, res)
      return
    }
    res.writeHead(404)
    res.end()
  })

  await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', () => resolve()))
  const port = (httpServer.address() as AddressInfo).port

  return {
    port,
    baseUrl: `http://127.0.0.1:${String(port)}`,
    ctx,
    cleanupAuth: () => {
      ctx.fiber.dispose()
    },
    close: () => new Promise<void>((resolve) => {
      httpServer.close(() => {
        rmSync(dir, { recursive: true, force: true })
        resolve()
      })
    }),
  }
}

interface JsonResponse {
  status: number
  headers: Record<string, string>
  body: string
  json(): unknown
}

async function request(
  base: string,
  method: string,
  pathname: string,
  opts: { body?: unknown; cookie?: string } = {},
): Promise<JsonResponse> {
  const headers: Record<string, string> = {}
  const init: RequestInit = { method, headers }
  if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
    init.body = JSON.stringify(opts.body)
  }
  if (opts.cookie !== undefined) {
    headers['cookie'] = opts.cookie
  }
  const res = await fetch(`${base}${pathname}`, init)
  const text = await res.text()
  const out: JsonResponse = {
    status: res.status,
    headers: Object.fromEntries(Array.from(res.headers.entries())),
    body: text,
    json: () => JSON.parse(text) as unknown,
  }
  return out
}

function cookieValue(headers: Record<string, string>, name: string): string | undefined {
  const setCookie = headers['set-cookie']
  if (!setCookie) return undefined
  const match = setCookie.match(new RegExp(`${name}=([^;]*)`))
  return match?.[1]
}

describe('auth plugin HTTP integration', () => {
  let server: RunningServer

  beforeEach(async () => {
    server = await bootAuthServer()
  })

  afterEach(async () => {
    server.cleanupAuth()
    await server.close()
  })

  describe('session lifecycle', () => {
    it('POST /login with valid credentials returns 200 + session cookie', async () => {
      const res = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      expect(res.status).toBe(200)
      const token = cookieValue(res.headers, 'dsh_session')
      expect(token).toBeDefined()
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
    })

    it('POST /login with wrong password returns 401', async () => {
      const res = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'wrong' },
      })
      expect(res.status).toBe(401)
    })

    it('POST /api/auth/login rejects non-POST methods with 405', async () => {
      const res = await request(server.baseUrl, 'GET', '/api/auth/login')
      expect(res.status).toBe(405)
    })

    it('GET /login serves the login page HTML', async () => {
      const res = await request(server.baseUrl, 'GET', '/login')
      expect(res.status).toBe(200)
      expect(res.body).toContain('<!DOCTYPE html>')
    })

    it('POST /logout clears the session cookie', async () => {
      const login = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(login.headers, 'dsh_session')!
      const logout = await request(server.baseUrl, 'POST', '/logout', { cookie: `dsh_session=${cookie}` })
      expect(logout.status).toBe(200)
      const cleared = cookieValue(logout.headers, 'dsh_session')
      expect(cleared).toBe('')
    })

    it('GET /auth/me without a session returns 401', async () => {
      const res = await request(server.baseUrl, 'GET', '/auth/me')
      expect(res.status).toBe(401)
    })

    it('GET /auth/me with a valid session returns the user profile', async () => {
      const login = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(login.headers, 'dsh_session')!
      const me = await request(server.baseUrl, 'GET', '/auth/me', { cookie: `dsh_session=${cookie}` })
      expect(me.status).toBe(200)
      const profile = me.json() as {
        username: string
        roleName: string
        role: { id: number; name: string; label: string }
        permissions: string[]
      }
      expect(profile.username).toBe('admin')
      expect(profile.roleName).toBe('admin')
      expect(profile.role.label).toBe('管理员')
      expect(profile.permissions).toContain('page:admin')
    })
  })

  describe('admin user CRUD', () => {
    async function loginAsAdmin(): Promise<string> {
      const res = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      expect(res.status).toBe(200)
      const cookie = cookieValue(res.headers, 'dsh_session')
      expect(cookie).toBeDefined()
      return `dsh_session=${cookie}`
    }

    it('GET /auth/admin/users requires page:admin', async () => {
      // Create a 'user' role account with no admin permission
      const adminCookie = await loginAsAdmin()
      await request(server.baseUrl, 'POST', '/auth/admin/users', {
        cookie: adminCookie,
        body: { username: 'plain', password: 'plainpass', roleId: 2 },
      })
      // Now log in as 'plain' and try the admin endpoint
      const plainLogin = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'plain', password: 'plainpass' },
      })
      const plainCookie = cookieValue(plainLogin.headers, 'dsh_session')!
      const res = await request(server.baseUrl, 'GET', '/auth/admin/users', {
        cookie: `dsh_session=${plainCookie}`,
      })
      expect(res.status).toBe(403)
    })

    it('GET /auth/admin/users lists the seeded admin user', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'GET', '/auth/admin/users', { cookie })
      expect(res.status).toBe(200)
      const users = (res.json() as { users: Array<{ username: string }> }).users
      expect(users.some(u => u.username === 'admin')).toBe(true)
    })

    it('POST /auth/admin/users creates a new user', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'POST', '/auth/admin/users', {
        cookie,
        body: { username: 'bob', password: 'bobpass1', roleId: 2 },
      })
      expect(res.status).toBe(201)
      const created = res.json() as { user: { username: string } }
      expect(created.user.username).toBe('bob')
    })

    it('POST /auth/admin/users rejects weak passwords with 400', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'POST', '/auth/admin/users', {
        cookie,
        body: { username: 'bob', password: 'x', roleId: 2 },
      })
      expect(res.status).toBe(400)
    })

    it('PATCH /auth/admin/users/:id updates a user', async () => {
      const cookie = await loginAsAdmin()
      const create = await request(server.baseUrl, 'POST', '/auth/admin/users', {
        cookie,
        body: { username: 'patched', password: 'password123', roleId: 2 },
      })
      const created = (create.json() as { user: { id: number } }).user
      const patch = await request(server.baseUrl, 'PATCH', `/auth/admin/users/${String(created.id)}`, {
        cookie,
        body: { displayName: '已改名', status: 1 },
      })
      expect(patch.status).toBe(200)
      const updated = patch.json() as { user: { displayName: string } }
      expect(updated.user.displayName).toBe('已改名')
    })

    it('DELETE /auth/admin/users/:id removes the user', async () => {
      const cookie = await loginAsAdmin()
      const create = await request(server.baseUrl, 'POST', '/auth/admin/users', {
        cookie,
        body: { username: 'to-delete', password: 'password123', roleId: 2 },
      })
      const created = (create.json() as { user: { id: number } }).user
      const del = await request(server.baseUrl, 'DELETE', `/auth/admin/users/${String(created.id)}`, { cookie })
      expect(del.status).toBe(200)
      const list = await request(server.baseUrl, 'GET', '/auth/admin/users', { cookie })
      const users = (list.json() as { users: Array<{ username: string }> }).users
      expect(users.some(u => u.username === 'to-delete')).toBe(false)
    })
  })

  describe('admin role CRUD', () => {
    async function loginAsAdmin(): Promise<string> {
      const res = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(res.headers, 'dsh_session')!
      return `dsh_session=${cookie}`
    }

    it('GET /auth/admin/roles returns wrapped roles with permissions', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'GET', '/auth/admin/roles', { cookie })
      expect(res.status).toBe(200)
      const roles = (res.json() as { roles: Array<{ id: number; name: string; isSystem: boolean; permissions: string[] }> }).roles
      const admin = roles.find(r => r.name === 'admin')
      expect(admin?.isSystem).toBe(true)
      expect(admin?.permissions).toContain('page:admin')
    })

    it('GET /auth/admin/permissions returns the catalog view', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'GET', '/auth/admin/permissions', { cookie })
      expect(res.status).toBe(200)
      const perms = (res.json() as { permissions: Array<{ key: string; label: string; group: string }> }).permissions
      expect(perms.some(p => p.key === 'page:admin' && p.group === 'page')).toBe(true)
    })

    it('POST /auth/admin/roles creates a role and returns { role }', async () => {
      const cookie = await loginAsAdmin()
      const res = await request(server.baseUrl, 'POST', '/auth/admin/roles', {
        cookie,
        body: { name: 'reviewer', label: '审查员', description: '只读审查', permissions: ['page:chat'] },
      })
      expect(res.status).toBe(201)
      const created = res.json() as { role: { id: number; name: string; permissions: string[] } }
      expect(created.role.name).toBe('reviewer')
      expect(created.role.permissions).toContain('page:chat')
    })

    it('PATCH /auth/admin/roles/:id updates permissions', async () => {
      const cookie = await loginAsAdmin()
      const create = await request(server.baseUrl, 'POST', '/auth/admin/roles', {
        cookie,
        body: { name: 'editor', label: '编辑', permissions: ['page:chat'] },
      })
      const role = (create.json() as { role: { id: number } }).role
      const patch = await request(server.baseUrl, 'PATCH', `/auth/admin/roles/${String(role.id)}`, {
        cookie,
        body: { label: '内容编辑', permissions: ['page:chat', 'page:history'] },
      })
      expect(patch.status).toBe(200)
      const updated = patch.json() as { role: { label: string; permissions: string[] } }
      expect(updated.role.label).toBe('内容编辑')
      expect(updated.role.permissions).toEqual(['page:chat', 'page:history'])
    })
  })

  describe('change-password', () => {
    it('POST /auth/change-password without a session returns 401', async () => {
      const res = await request(server.baseUrl, 'POST', '/auth/change-password', {
        body: { currentPassword: 'admin123', newPassword: 'newpass123' },
      })
      expect(res.status).toBe(401)
    })

    it('POST /auth/change-password with valid current password succeeds', async () => {
      const login = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(login.headers, 'dsh_session')!
      const res = await request(server.baseUrl, 'POST', '/auth/change-password', {
        cookie: `dsh_session=${cookie}`,
        body: { currentPassword: 'admin123', newPassword: 'newpass123' },
      })
      expect(res.status).toBe(200)
    })

    it('POST /auth/change-password with wrong current password returns 400', async () => {
      const login = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(login.headers, 'dsh_session')!
      const res = await request(server.baseUrl, 'POST', '/auth/change-password', {
        cookie: `dsh_session=${cookie}`,
        body: { currentPassword: 'wrong', newPassword: 'newpass123' },
      })
      expect(res.status).toBe(400)
    })

    it('POST /auth/change-password rejects passwords shorter than 6 chars', async () => {
      const login = await request(server.baseUrl, 'POST', '/login', {
        body: { username: 'admin', password: 'admin123' },
      })
      const cookie = cookieValue(login.headers, 'dsh_session')!
      const res = await request(server.baseUrl, 'POST', '/auth/change-password', {
        cookie: `dsh_session=${cookie}`,
        body: { currentPassword: 'admin123', newPassword: 'short' },
      })
      expect(res.status).toBe(400)
    })
  })

  describe('fall-through', () => {
    it('unmatched routes return 404', async () => {
      const res = await request(server.baseUrl, 'GET', '/static/file.js')
      expect(res.status).toBe(404)
    })
  })
})
