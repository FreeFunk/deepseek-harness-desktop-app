/**
 * Auth plugin: role-based access control for the Web surface. Owns the auth
 * database (users/roles/permissions/sessions), the transport-level guard that
 * gates every request the webserver dispatches (HTTP routes, the /api/* RPC
 * prefix, and WebSocket upgrades), the login page, the admin console
 * (/admin), and the SPA bootstrap tap.
 *
 * The guard is the single enforcement point: before any route, fallback, or
 * upgrade handler runs it admits only the public auth surface (/login,
 * /api/auth/login, /api/auth/logout, and the /auth/* legacy aliases)
 * without a session and rejects everything else with a redirect (HTML
 * navigation), 401 JSON (API), or a destroyed socket (upgrade). Named routes
 * therefore cannot bypass login by being more specific than the fallback.
 *
 * Role model: a user has one role; a role has a set of permissions. Page
 * permissions (page:*) drive the UI and the admin-console gate; the
 * `api:admin` permission gates the user/role/permission management API.
 * @module @deepseek-ai/dsh-web-app/auth
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { AUTH_USER, AUTH_USER_HEADER, type WebGuard } from '@deepseek-ai/dsh-host-webserver'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import type { SessionToken } from './auth-user.ts'
import type { AuthUser } from './auth-user.ts'
import { AUTH_USER_KEY } from './auth-user.ts'
import { AuthStore } from './auth-store.ts'
import { ADMIN_CONSOLE_HTML } from './admin-console.ts'
import { AUTH_BOOTSTRAP_SCRIPT } from './bootstrap.ts'

export type { AuthUser } from './auth-user.ts'

/** Name of the HttpOnly session cookie. */
export const AUTH_SESSION_COOKIE = 'dsh_session'

/** Stable Cordis plugin name. */
export const name = 'dsh-web-app-auth'

/** Plugin dependency: webserver for route registration. */
export const inject = ['webServer']

/** Route prefix for auth API. */
export const AUTH_API_PREFIX = '/auth'

/**
 * Require a permission on the resolved `AuthUser`. Returns 403 with a JSON
 * error body when the user lacks the permission.
 */
function requirePermission(user: AuthUser | null | undefined, permission: string): boolean {
  return user !== null && user !== undefined && user.permissions.includes(permission)
}

/** Write a JSON response. */
function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

/** Read the session cookie value from a request. */
function readSessionCookie(req: IncomingMessage): string | undefined {
  const header = req.headers.cookie
  if (!header) return undefined
  const match = header.match(new RegExp(`(?:^|;\\s*)${AUTH_SESSION_COOKIE}=([^;]*)`))
  return match?.[1]
}

/** Set the session cookie on the response. */
function setSessionCookie(
  res: ServerResponse,
  token: string,
  expiresAt: number,
  secure: boolean,
): void {
  const expires = new Date(expiresAt).toUTCString()
  const parts = [
    `${AUTH_SESSION_COOKIE}=${token}`,
    `Expires=${expires}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ]
  if (secure) parts.push('Secure')
  res.setHeader('Set-Cookie', parts.join('; '))
}

/** Clear the session cookie. */
function clearSessionCookie(res: ServerResponse): void {
  res.setHeader(
    'Set-Cookie',
    `${AUTH_SESSION_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly`,
  )
}

/**
 * Login URL preserving the caller's query string. The connection launch token
 * (`?token=`) is the browser-session exchange input; dropping it across the
 * login redirect would strand `/api` requests with "authentication required".
 * @param req - the redirected request.
 * @returns `/login` plus the original query (empty when the caller had none).
 */
function loginUrlWithQuery(req: IncomingMessage): string {
  const url = new URL(req.url ?? '/', 'http://x')
  return `/login${url.search}`
}

/**
 * Root URL preserving the caller's query string, so a signed-in user hitting
 * `/login?token=...` returns to the app and re-enters the token exchange.
 * @param req - the redirected request.
 * @returns `/` plus the original query.
 */
function rootUrlWithQuery(req: IncomingMessage): string {
  const url = new URL(req.url ?? '/', 'http://x')
  return `/${url.search}`
}

// ── SPA bootstrap (re-exported from auth-bootstrap.ts) ───────────────────────

export { authBootstrapScript } from './auth-bootstrap.ts'

// ── Route handlers ────────────────────────────────────────────────────────────

async function readBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return await new Promise<Record<string, unknown> | null>((resolve) => {
    let data = ''
    req.on('data', (chunk: Buffer) => { data += chunk.toString() })
    req.on('end', () => {
      if (!data) { resolve(null); return }
      try { resolve(JSON.parse(data) as Record<string, unknown>) }
      catch { resolve(null) }
    })
    req.on('error', () => resolve(null))
  })
}

async function handleLogin(
  req: IncomingMessage,
  res: ServerResponse,
  _user: AuthUser | null,
  store: AuthStore,
  secure: boolean,
): Promise<void> {
  if (req.method !== 'POST') { json(res, 405, { error: 'method not allowed' }); return }
  const body = await readBody(req)
  const username = typeof body?.username === 'string' ? body.username.trim() : ''
  const password = typeof body?.password === 'string' ? body.password : ''
  if (!username || !password) { json(res, 400, { error: 'username and password required' }); return }
  const authed = store.verifyCredentials(username, password)
  if (!authed) { json(res, 401, { error: '用户名或密码错误' }); return }
  const { token, expiresAt } = store.createSession(authed.id)
  setSessionCookie(res, token, expiresAt, secure)
  json(res, 200, {
    id: authed.id,
    username: authed.username,
    displayName: authed.displayName,
    roleId: authed.roleId,
    roleName: authed.roleName,
    role: { id: authed.roleId, name: authed.roleName, label: authed.roleLabel },
    permissions: [...authed.permissions],
    status: authed.status,
  })
}

async function handleLogout(
  req: IncomingMessage,
  res: ServerResponse,
  _user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (req.method !== 'POST') { json(res, 405, { error: 'method not allowed' }); return }
  const token = readSessionCookie(req) as SessionToken | undefined
  store.destroySession(token ?? null)
  clearSessionCookie(res)
  json(res, 200, { ok: true })
}

async function handleMe(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
): Promise<void> {
  if (req.method !== 'GET') { json(res, 405, { error: 'method not allowed' }); return }
  if (!user) { json(res, 401, { error: 'not authenticated' }); return }
  json(res, 200, {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    roleId: user.roleId,
    roleName: user.roleName,
    role: { id: user.roleId, name: user.roleName, label: user.roleLabel },
    permissions: [...user.permissions],
    status: user.status,
  })
}

async function handleChangePassword(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (req.method !== 'POST') { json(res, 405, { error: 'method not allowed' }); return }
  if (!user) { json(res, 401, { error: 'not authenticated' }); return }
  const body = await readBody(req)
  const current = typeof body?.currentPassword === 'string' ? body.currentPassword : ''
  const next = typeof body?.newPassword === 'string' ? body.newPassword : ''
  if (!current || !next) { json(res, 400, { error: 'currentPassword and newPassword required' }); return }
  if (next.length < 6) { json(res, 400, { error: '新密码至少 6 个字符' }); return }
  try {
    store.changeOwnPassword(user.id, current, next)
    json(res, 200, { ok: true })
  } catch (err) {
    const msg = err instanceof Error ? err.message : '修改失败'
    json(res, 400, { error: msg })
  }
}

// ── Admin handlers ────────────────────────────────────────────────────────────

async function handleAdminUsers(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (!requirePermission(user, 'page:admin')) { json(res, 403, { error: 'permission denied' }); return }
  if (req.method === 'GET') {
    json(res, 200, { users: store.listUsers() })
    return
  }
  if (req.method === 'POST') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    const username = typeof body?.username === 'string' ? body.username.trim() : ''
    const password = typeof body?.password === 'string' ? body.password : ''
    const roleId = typeof body?.roleId === 'number' ? body.roleId : 0
    if (!username || !password || !roleId) { json(res, 400, { error: 'username, password, roleId required' }); return }
    try {
      const created = store.createUser({
        username,
        password,
        roleId,
        ...(typeof body?.displayName === 'string' ? { displayName: body.displayName } : {}),
        ...(typeof body?.status === 'number' ? { status: body.status } : {}),
      })
      json(res, 201, { user: created })
    } catch (err) {
      const msg = err instanceof Error ? err.message : '创建用户失败'
      json(res, 400, { error: msg })
    }
    return
  }
  json(res, 405, { error: 'method not allowed' })
}

async function handleAdminUserById(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
  idParam: string,
): Promise<void> {
  if (!requirePermission(user, 'page:admin')) { json(res, 403, { error: 'permission denied' }); return }
  const id = Number.parseInt(idParam, 10)
  if (!Number.isFinite(id)) { json(res, 400, { error: 'invalid id' }); return }
  if (req.method === 'PUT' || req.method === 'PATCH') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    try {
      const updates: { displayName?: string; roleId?: number; status?: number; password?: string } = {}
      if (typeof body?.displayName === 'string') updates.displayName = body.displayName
      if (typeof body?.roleId === 'number') updates.roleId = body.roleId
      if (typeof body?.status === 'number') updates.status = body.status
      if (typeof body?.password === 'string') updates.password = body.password
      const updated = store.updateUser(id, updates)
      json(res, 200, { user: updated })
    } catch (err) {
      const msg = err instanceof Error ? err.message : '更新失败'
      json(res, 400, { error: msg })
    }
    return
  }
  if (req.method === 'DELETE') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    store.deleteUser(id)
    json(res, 200, { ok: true })
    return
  }
  json(res, 405, { error: 'method not allowed' })
}

async function handleAdminRoles(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (!requirePermission(user, 'page:admin')) { json(res, 403, { error: 'permission denied' }); return }
  if (req.method === 'GET') { json(res, 200, { roles: store.listRoles() }); return }
  if (req.method === 'POST') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    const name = typeof body?.name === 'string' ? body.name.trim() : ''
    const label = typeof body?.label === 'string' ? body.label.trim() : ''
    const permissions = Array.isArray(body?.permissions) ? body.permissions as string[] : []
    if (!name || !label) { json(res, 400, { error: 'name and label required' }); return }
    try {
      const roleInput: { name: string; label: string; description?: string; permissions: string[] } = { name, label, permissions }
      if (typeof body?.description === 'string') roleInput.description = body.description
      const created = store.createRole(roleInput)
      json(res, 201, { role: created })
    } catch (err) {
      json(res, 400, { error: err instanceof Error ? err.message : '创建角色失败' })
    }
    return
  }
  json(res, 405, { error: 'method not allowed' })
}

async function handleAdminRoleById(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
  idParam: string,
): Promise<void> {
  if (!requirePermission(user, 'page:admin')) { json(res, 403, { error: 'permission denied' }); return }
  const id = Number.parseInt(idParam, 10)
  if (!Number.isFinite(id)) { json(res, 400, { error: 'invalid id' }); return }
  if (req.method === 'PUT' || req.method === 'PATCH') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    try {
      const updateInput: { label?: string; description?: string; permissions?: string[] } = {}
      if (typeof body?.label === 'string') updateInput.label = body.label
      if (typeof body?.description === 'string') updateInput.description = body.description
      if (Array.isArray(body?.permissions)) updateInput.permissions = body.permissions as string[]
      const updated = store.updateRole(id, updateInput)
      json(res, 200, { role: updated })
    } catch (err) {
      json(res, 400, { error: err instanceof Error ? err.message : '更新失败' })
    }
    return
  }
  if (req.method === 'DELETE') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    store.deleteRole(id)
    json(res, 200, { ok: true })
    return
  }
  json(res, 405, { error: 'method not allowed' })
}

async function handleAdminPermissions(
  req: IncomingMessage,
  res: ServerResponse,
  user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (!requirePermission(user, 'page:admin')) { json(res, 403, { error: 'permission denied' }); return }
  if (req.method === 'GET') {
    json(res, 200, { permissions: store.listPermissions().map(permissionView) })
    return
  }
  json(res, 405, { error: 'method not allowed' })
}

// ── Permission catalog ───────────────────────────────────────────────────────

/** Display metadata for the seeded permission catalog; unknown keys fall back to the key itself. */
const PERMISSION_CATALOG: Readonly<Record<string, { label: string; group: string; description: string }>> = {
  'page:chat': { label: '对话', group: 'page', description: '进入对话界面' },
  'page:history': { label: '会话历史', group: 'page', description: '查看会话历史列表' },
  'page:settings': { label: '设置', group: 'page', description: '访问设置（含模型配置）' },
  'page:tools': { label: '工具', group: 'page', description: '查看工具视图' },
  'page:admin': { label: '管理控制台', group: 'page', description: '进入用户/角色/权限管理控制台' },
  'api:admin': { label: '管理接口', group: 'api', description: '调用用户/角色/权限管理接口' },
  'session:list': { label: '会话列表', group: 'page', description: '查看会话列表' },
  'session:read': { label: '会话读取', group: 'page', description: '读取会话记录' },
  'session:delete': { label: '会话删除', group: 'page', description: '删除会话记录' },
  'settings:read': { label: '设置读取', group: 'page', description: '读取设置项' },
  'settings:write': { label: '设置写入', group: 'page', description: '修改设置项' },
}

/** Admin permissions-list row: stable key plus display metadata. */
interface PermissionView {
  id: number
  key: string
  label: string
  group: string
  description: string
}

function permissionView(permission: { id: number; name: string }): PermissionView {
  const meta = PERMISSION_CATALOG[permission.name]
  const group = meta?.group ?? (permission.name.startsWith('api:') ? 'api' : 'page')
  const label = meta?.label ?? permission.name
  return {
    id: permission.id,
    key: permission.name,
    label,
    group,
    description: meta?.description ?? label,
  }
}

// ── Plugin apply ─────────────────────────────────────────────────────────────

export interface AuthPluginOptions {
  /** Path to the SQLite database. Defaults to `~/.dsh/auth.db`. */
  dbPath?: string
  /** Session lifetime in hours. Default: 24. */
  sessionExpireHours?: number
  /** Register the admin console HTML route. Default: true. */
  adminConsole?: boolean
}

/**
 * Mount auth routes on the host webserver and close over the `AuthStore`.
 * The store is lazily opened on first request; the caller may call `dispose()`
 * on teardown.
 *
 * Registered routes:
 *   GET    /login          (login page HTML)
 *   POST   /login          (JSON login)
 *   POST   /logout
 *   GET    /auth/me
 *   POST   /auth/change-password
 *   GET    /auth/admin/users
 *   POST   /auth/admin/users
 *   PUT    /auth/admin/users/:id
 *   DELETE /auth/admin/users/:id
 *   GET    /auth/admin/roles
 *   POST   /auth/admin/roles
 *   PUT    /auth/admin/roles/:id
 *   DELETE /auth/admin/roles/:id
 *   GET    /auth/admin/permissions
 *   GET    /admin          (admin console HTML, when `adminConsole` is true)
 *
 * The `AUTH_USER` symbol is attached to `IncomingMessage` for downstream use.
 */
export function apply(
  ctx: Context,
  options: AuthPluginOptions = {},
): void {
  const webServer = ctx.get('webServer') as WebServer | undefined
  if (!webServer) throw new Error('dsh-web-app-auth: webServer service not available')

  const dbPath = options.dbPath ?? join(homedir(), '.dsh', 'auth.db')
  const store = new AuthStore({
    ...(options.dbPath ? { dbPath: options.dbPath } : {}),
    ...(options.sessionExpireHours ? { sessionExpireHours: options.sessionExpireHours } : {}),
  })

  // Detect HTTPS from X-Forwarded-Proto (for reverse proxies) or the socket.
  function isSecure(req: IncomingMessage): boolean {
    const proto = req.headers['x-forwarded-proto']
    if (proto) return (Array.isArray(proto) ? proto[0] : proto) === 'https'
    return !!(req.socket as unknown as { encrypted?: boolean }).encrypted
  }

  // Shared user-resolution middleware: run before every auth route.
  function resolveUser(req: IncomingMessage): AuthUser | null {
    const token = readSessionCookie(req) as SessionToken | undefined
    return store.getUserByToken(token ?? null)
  }

  // Attach the resolved user for downstream readers: both the auth package's
  // own string key and the webserver package's cross-package AUTH_USER symbol
  // (the connection configuration-plane fence reads the latter).
  function attachUser(req: IncomingMessage, user: AuthUser | null): void {
    // Idempotent: the transport guard already attached the resolved user before
    // dispatch runs on the real server; redefining a non-configurable property
    // with a freshly resolved (different object identity) user would throw.
    if (!(AUTH_USER_KEY in req)) {
      Object.defineProperty(req, AUTH_USER_KEY, {
        value: user,
        writable: false,
        enumerable: false,
        configurable: false,
      })
    }
    if (!(AUTH_USER in req)) {
      Object.defineProperty(req, AUTH_USER, {
        value: user,
        writable: false,
        enumerable: false,
        configurable: false,
      })
    }
  }

  // Transport gate: every request (HTTP and upgrade) passes here before any
  // route, fallback, or upgrade handler. Only the public auth surface may
  // proceed without a session.
  const guard: WebGuard = (target, next) => {
    const pathname = new URL(target.req.url ?? '/', 'http://x').pathname
    const method = target.req.method ?? 'GET'
    const user = resolveUser(target.req)
    // A resource handler receives a Fetch Request built from these headers, so
    // the attached symbol does not survive; carry presence across the
    // conversion and overwrite any client-supplied value.
    if (user !== null) target.req.headers[AUTH_USER_HEADER] = '1'
    else delete target.req.headers[AUTH_USER_HEADER]
    attachUser(target.req, user)
    if (user !== null) return next()
    const publicPath =
      pathname === '/login'
      // The launch-token handshake authenticates itself; the guard must not
      // redirect it to /login before BrowserAuth can exchange the token.
      || pathname === '/connect'
      || pathname === '/api/auth/login'
      || pathname === '/api/auth/logout'
      || pathname === '/auth/login'
      || pathname === '/auth/logout'
      || pathname === '/logout'
      || (pathname === '/auth/login-json' && method === 'POST')
    if (publicPath) return next()
    if (target.socket !== undefined) { target.socket.destroy(); return }
    if (target.res !== undefined) {
      if (pathname.startsWith('/api/') || pathname.startsWith('/auth/')) {
        json(target.res, 401, { error: '未登录' })
        return
      }
      const accept = target.req.headers.accept ?? ''
      if (accept.includes('text/html')) {
        target.res.writeHead(302, { Location: loginUrlWithQuery(target.req) })
        target.res.end()
        return
      }
      json(target.res, 401, { error: '未登录' })
      return
    }
    return next()
  }
  ctx.effect(() => webServer.registerGuard(guard), 'dsh-web-app-auth: transport guard')

  // The marker on the request is keyed by a stable string rather than a
  // symbol identity, because Symbol keys are not visible to code outside the
  // package that defines them.
  function dispatch(req: IncomingMessage, res: ServerResponse): true | undefined {
    const pathname = new URL(req.url ?? '/', 'http://x').pathname
    const user = resolveUser(req)
    attachUser(req, user)

    // ── /login (HTML page; POST also accepts JSON login) ─────────────────────
    if (pathname === '/login' || pathname === '/auth/login') {
      if (req.method === 'GET') {
        if (user !== null) {
          res.writeHead(302, { Location: rootUrlWithQuery(req) })
          res.end()
          return true
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(LOGIN_HTML)
        return true
      }
      if (req.method === 'POST') {
        void handleLogin(req, res, user, store, isSecure(req))
        return true
      }
      json(res, 405, { error: 'method not allowed' })
      return true
    }

    // ── /login-json (legacy alias for the SPA login form) ───────────────────
    if (pathname === '/login-json' || pathname === '/auth/login-json') {
      void handleLogin(req, res, user, store, isSecure(req))
      return true
    }

    // ── /logout ─────────────────────────────────────────────────────────────
    if (pathname === '/logout' || pathname === '/auth/logout' || pathname === '/api/auth/logout') {
      void handleLogout(req, res, user, store)
      return true
    }

    // ── /api/auth/login (JSON) ──────────────────────────────────────────────
    if (pathname === '/api/auth/login') {
      void handleLogin(req, res, user, store, isSecure(req))
      return true
    }

    // ── /auth/me and /api/auth/me ───────────────────────────────────────────
    if (pathname === '/auth/me' || pathname === '/api/auth/me') {
      void handleMe(req, res, user)
      return true
    }

    // ── /auth/change-password and /api/auth/password ────────────────────────
    if (pathname === '/auth/change-password' || pathname === '/api/auth/password') {
      void handleChangePassword(req, res, user, store)
      return true
    }

    // ── /auth/menus and /api/auth/menus ─────────────────────────────────────
    if (pathname === '/auth/menus' || pathname === '/api/auth/menus') {
      if (req.method !== 'GET') { json(res, 405, { error: 'method not allowed' }); return true }
      if (user === null) { json(res, 401, { error: 'not authenticated' }); return true }
      json(res, 200, { menus: menusFor(user) })
      return true
    }

    // ── /auth/admin/* and /api/auth/* admin surface ─────────────────────────
    const adminMatch = pathname.match(/^\/(?:auth\/admin|api\/auth)\/(.+)$/)
    if (adminMatch) {
      const sub = adminMatch[1] ?? ""
      if (sub === 'users') { void handleAdminUsers(req, res, user, store); return true }
      if (sub.startsWith('users/')) {
        void handleAdminUserById(req, res, user, store, sub.slice('users/'.length))
        return true
      }
      if (sub === 'roles') { void handleAdminRoles(req, res, user, store); return true }
      if (sub.startsWith('roles/')) {
        void handleAdminRoleById(req, res, user, store, sub.slice('roles/'.length))
        return true
      }
      if (sub === 'permissions') { void handleAdminPermissions(req, res, user, store); return true }
    }

    // ── /admin ──────────────────────────────────────────────────────────────
    if (pathname === '/admin' && options.adminConsole !== false) {
      if (user === null) { res.writeHead(302, { Location: loginUrlWithQuery(req) }); res.end(); return true }
      if (!requirePermission(user, 'page:admin')) {
        res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(/* html */`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>无权限</title></head>
<body style="background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh">
<div style="text-align:center"><h1 style="color:#f85149">403 无权限</h1>
<p style="color:#8b949e">当前账号没有访问管理控制台的权限</p>
<p style="margin-top:12px"><a href="/" style="color:#58a6ff">返回首页</a></p></div></body></html>`)
        return true
      }
      const settingsPath = join(dirname(dbPath), 'settings.yaml')
      const html = ADMIN_CONSOLE_HTML.replace('<!--__AUTH_BOOT_THEME__-->', bootThemeScript(themePreference(settingsPath)))
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(html)
      return true
    }

    // Not one of our routes — fall through to the next handler.
    return undefined
  }

  // Register exact routes first (matcher checks exact before prefix).
  const exactRoutes: WebRoute[] = [
    { kind: 'exact', path: '/login', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/login-json', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/logout', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/admin', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/login', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/logout', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/me', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/password', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/menus', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/users', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/roles', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/api/auth/permissions', handler: (req, res) => { void dispatch(req, res) } },
  ]
  const prefixRoutes: WebRoute[] = [
    { kind: 'prefix', path: '/auth', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'prefix', path: '/api/auth', handler: (req, res) => { void dispatch(req, res) } },
  ]

  const disposers: Array<() => void> = []
  for (const r of exactRoutes) disposers.push(webServer.register(r))
  for (const r of prefixRoutes) disposers.push(webServer.register(r))

  // Inject the SPA bootstrap so the sidebar shows the signed-in user and
  // redirects an expired session to /login.
  ctx.effect(() => webServer.tapIndex(injectBootstrap), 'dsh-web-app-auth: bootstrap index tap')

  // Cleanup: close the database and remove routes.
  ctx.effect(() => () => {
    for (const d of disposers) d()
    store.dispose()
  }, 'dsh-web-app-auth: cleanup')
}

// ── Login page and SPA bootstrap ─────────────────────────────────────────────

const LOGIN_HTML = /* html */`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - DeepSeek Harness</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:380px;max-width:90vw}
.box h1{font-size:24px;margin-bottom:8px;color:#f0f6fc;text-align:center}
.box p{color:#8b949e;font-size:14px;margin-bottom:24px;text-align:center}
.fg{margin-bottom:16px}
.fg label{display:block;font-size:13px;color:#c9d1d9;margin-bottom:6px}
.fg input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px;outline:none}
.fg input:focus{border-color:#58a6ff}
.btn{width:100%;padding:10px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin-top:8px}
.btn:hover{background:#2ea043}
.err{color:#f85149;font-size:13px;text-align:center;margin-top:12px;display:none}
.err.show{display:block}
</style>
</head>
<body>
<div class="box">
<h1>DeepSeek Harness</h1>
<p>请输入用户名和密码登录</p>
<form id="f">
<div class="fg"><label>用户名</label><input type="text" id="u" autocomplete="username" required autofocus></div>
<div class="fg"><label>密码</label><input type="password" id="p" autocomplete="current-password" required></div>
<button class="btn">登录</button>
</form>
<div id="e" class="err"></div>
</div>
<script>
document.getElementById("f").addEventListener("submit",async function(e){e.preventDefault();var x=document.getElementById("e");x.classList.remove("show");try{var r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})});if(!r.ok){var d=await r.json();x.textContent=d.error||"登录失败";x.classList.add("show");return}window.location.href="/"+window.location.search}catch(err){x.textContent="网络错误";x.classList.add("show")}})
</script>
</body>
</html>`

/** Fixed page menu catalog; a user sees the entries their role's permissions allow. */
const PAGE_MENUS: ReadonlyArray<{ key: string; permission: string; label: string; path: string }> = [
  { key: 'chat', permission: 'page:chat', label: '对话', path: '/' },
  { key: 'history', permission: 'page:history', label: '会话历史', path: '/history' },
  { key: 'settings', permission: 'page:settings', label: '设置', path: '/settings' },
  { key: 'tools', permission: 'page:tools', label: '工具', path: '/tools' },
  { key: 'admin', permission: 'page:admin', label: '管理控制台', path: '/admin' },
]

/** The menus the signed-in user may open, derived from their page permissions. */
function menusFor(user: AuthUser): Array<{ key: string; label: string; path: string }> {
  return PAGE_MENUS.filter(entry => user.permissions.includes(entry.permission))
    .map(({ key, label, path }) => ({ key, label, path }))
}

/** Inject the auth bootstrap before the SPA's </head> (or append when absent). */
function injectBootstrap(html: string): string {
  const script = `<script>${AUTH_BOOTSTRAP_SCRIPT}</script>`
  if (html.includes('</head>')) return html.replace('</head>', `${script}</head>`)
  return `${html}${script}`
}

/** Built-in appearance preferences, mirroring the ui-theme settings document. */
type ThemePreference = 'light' | 'dark' | 'system'

/**
 * Read the persisted appearance preference from the Host user-settings
 * document (settings.yaml, namespace ui-theme, field preference). The admin
 * page renders this on every load so it follows the same appearance the SPA
 * shows. Absent or unparseable documents fall back to system.
 * @param settingsPath - the settings document path (derived from the auth DB's home).
 * @returns the stored preference, or system.
 */
function themePreference(settingsPath: string): ThemePreference {
  try {
    const text = readFileSync(settingsPath, 'utf8')
    const section = /^\s*ui-theme:[ \t]*\r?\n([\s\S]*?)(?=^\S[^\n]*:|\z)/m.exec(text)
    const within = section?.[1] ?? text
    const pref = /^\s*preference:[ \t]*['"]?(light|dark|system)['"]?[ \t]*$/m.exec(within)
    if (pref !== null) return pref[1] as ThemePreference
  } catch {
    // No document yet — the default applies.
  }
  return 'system'
}

/**
 * Inline boot-theme script for the standalone admin page, matching the SPA's
 * own theme bootstrap: it resolves system via prefers-color-scheme, then
 * toggles body[data-ds-dark-theme] and color-scheme so the page CSS flips
 * to the dark palette exactly when the application would.
 * @param preference - the persisted appearance preference.
 * @returns a <script> element string.
 */
function bootThemeScript(preference: ThemePreference): string {
  const json = JSON.stringify(preference)
  return `<script>(() => {
  const preference = ${json}
  const systemDark = preference === 'system'
    && typeof matchMedia !== 'undefined'
    && matchMedia('(prefers-color-scheme: dark)').matches
  const dark = preference === 'dark' || systemDark
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
  document.body.toggleAttribute('data-ds-dark-theme', dark)
})()</script>`
}

/** Plugin config schema (passed through to AuthPluginOptions). */
export const Config: z<AuthPluginOptions> = z.object({
  dbPath: z.string(),
  sessionExpireHours: z.natural().min(1),
  adminConsole: z.boolean(),
})
