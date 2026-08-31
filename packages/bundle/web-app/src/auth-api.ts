/**
 * Auth plugin: registers `/login`, `/logout`, and `/auth/admin/*` HTTP routes
 * on the host webserver, plus a slot contribution for the SPA startup script.
 *
 * Session management uses the `AUTH_SESSION_COOKIE` HttpOnly cookie; the
 * browser-side `authBootstrap` script reads the `AUTH_USER` event to populate
 * the client-side identity.
 *
 * All `/auth/admin/*` routes require the `page:admin` permission on the
 * resolved `AuthUser`; the `api:admin` permission gates destructive mutations.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import type { SessionToken } from './auth-user.ts'
import type { AuthUser } from './auth-user.ts'
import { AUTH_USER_KEY } from './auth-user.ts'
import { AuthStore } from './auth-store.ts'

export { AUTH_USER, type AuthUser } from './auth-user.ts'

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

// ── SPA bootstrap (re-exported from auth-bootstrap.ts) ───────────────────────

export { authBootstrapScript } from './auth-bootstrap.ts'

// ── Route handlers ────────────────────────────────────────────────────────────

type RouteHandler = (req: IncomingMessage, res: ServerResponse, user: AuthUser | null) => void | Promise<void>

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
  json(res, 200, { id: authed.id, username: authed.username, roleName: authed.roleName })
}

async function handleLogout(
  req: IncomingMessage,
  res: ServerResponse,
  _user: AuthUser | null,
  store: AuthStore,
): Promise<void> {
  if (req.method !== 'POST') { json(res, 405, { error: 'method not allowed' }); return }
  const token = readSessionCookie(req) as SessionToken | undefined
  store.destroySession(token)
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
    permissions: [...user.permissions],
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
    const list = store.listUsers()
    json(res, 200, list.map(u => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      roleId: u.roleId,
      roleName: u.roleName,
      status: u.status,
    })))
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
      const created = store.createUser({ username, password, roleId })
      json(res, 201, { id: created.id, username: created.username, roleId: created.roleId })
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
  if (req.method === 'PUT') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    try {
      const updated = store.updateUser(id, {
        displayName: body?.displayName as string | undefined,
        roleId: typeof body?.roleId === 'number' ? body.roleId : undefined,
        status: typeof body?.status === 'number' ? body.status : undefined,
        password: typeof body?.password === 'string' ? body.password : undefined,
      })
      json(res, 200, { id: updated.id, username: updated.username, roleId: updated.roleId })
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
  if (req.method === 'GET') { json(res, 200, store.listRoles()); return }
  if (req.method === 'POST') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    const name = typeof body?.name === 'string' ? body.name.trim() : ''
    const label = typeof body?.label === 'string' ? body.label.trim() : ''
    const description = typeof body?.description === 'string' ? body.description : undefined
    const permissions = Array.isArray(body?.permissions) ? body.permissions as string[] : []
    if (!name || !label) { json(res, 400, { error: 'name and label required' }); return }
    try {
      const created = store.createRole({ name, label, description, permissions })
      json(res, 201, created)
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
  if (req.method === 'PUT') {
    if (!requirePermission(user, 'api:admin')) { json(res, 403, { error: 'api:admin permission required' }); return }
    const body = await readBody(req)
    try {
      const updated = store.updateRole(id, {
        label: typeof body?.label === 'string' ? body.label : undefined,
        description: typeof body?.description === 'string' ? body.description : undefined,
        permissions: Array.isArray(body?.permissions) ? body.permissions : undefined,
      })
      json(res, 200, updated)
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
  if (req.method === 'GET') { json(res, 200, store.listPermissions()); return }
  json(res, 405, { error: 'method not allowed' })
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
 *   POST   /login
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

  const store = new AuthStore({
    dbPath: options.dbPath,
    sessionExpireHours: options.sessionExpireHours,
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
    return store.getUserByToken(token) ?? null
  }

  // The marker on the request is keyed by a stable string rather than a
  // symbol identity, because Symbol keys are not visible to code outside the
  // package that defines them.
  function dispatch(req: IncomingMessage, res: ServerResponse): true | undefined {
    const pathname = new URL(req.url ?? '/', 'http://x').pathname

    // Attach the resolved user for downstream readers.
    const user = resolveUser(req)
    Object.defineProperty(req, AUTH_USER_KEY, {
      value: user,
      writable: false,
      enumerable: false,
      configurable: false,
    })

    // ── /login ──────────────────────────────────────────────────────────────
    if (pathname === '/login') {
      void handleLogin(req, res, user, store, isSecure(req))
      return true
    }

    // ── /logout ──────────────────────────────────────────────────────────────
    if (pathname === '/logout') {
      void handleLogout(req, res, user, store)
      return true
    }

    // ── /auth/me ─────────────────────────────────────────────────────────────
    if (pathname === '/auth/me') {
      void handleMe(req, res, user)
      return true
    }

    // ── /auth/change-password ───────────────────────────────────────────────
    if (pathname === '/auth/change-password') {
      void handleChangePassword(req, res, user, store)
      return true
    }

    // ── /auth/admin/* ────────────────────────────────────────────────────────
    if (pathname.startsWith('/auth/admin/')) {
      const sub = pathname.slice('/auth/admin/'.length)
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
      if (!requirePermission(user, 'page:admin')) {
        res.writeHead(302, { Location: '/login' })
        res.end()
        return true
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(adminConsoleHtml())
      return true
    }

    // Not one of our routes — fall through to the next handler.
    return undefined
  }

  // Register exact routes first (matcher checks exact before prefix).
  const exactRoutes: WebRoute[] = [
    { kind: 'exact', path: '/login', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/logout', handler: (req, res) => { void dispatch(req, res) } },
    { kind: 'exact', path: '/admin', handler: (req, res) => { void dispatch(req, res) } },
  ]
  const prefixRoute: WebRoute = {
    kind: 'prefix',
    path: '/auth',
    handler: (req, res) => { void dispatch(req, res) },
  }

  const disposers: Array<() => void> = []
  for (const r of exactRoutes) disposers.push(webServer.register(r))
  disposers.push(webServer.register(prefixRoute))

  // Cleanup: close the database and remove routes.
  ctx.effect(() => () => {
    for (const d of disposers) d()
    store.dispose()
  }, 'dsh-web-app-auth: cleanup')
}

// ── Admin console HTML ───────────────────────────────────────────────────────

function adminConsoleHtml(): string {
  return /* html */`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DSH 管理控制台</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #f7f8fa; color: #1a1a2e; min-height: 100vh; }
  .header { background: #1a1a2e; color: #fff; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
  .header h1 { font-size: 1.2rem; font-weight: 600; }
  .header a { color: #7ec8e3; text-decoration: none; font-size: 0.875rem; }
  .container { max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
  .tabs { display: flex; gap: 0.5rem; border-bottom: 2px solid #e5e7eb; margin-bottom: 1.5rem; }
  .tab { padding: 0.75rem 1.25rem; cursor: pointer; border: none; background: none; font-size: 0.9rem; color: #6b7280; border-bottom: 2px solid transparent; margin-bottom: -2px; }
  .tab.active { color: #1a1a2e; border-bottom-color: #1a1a2e; font-weight: 500; }
  .tab:hover { color: #1a1a2e; }
  .panel { display: none; }
  .panel.active { display: block; }
  .card { background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card h2 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #f3f4f6; font-size: 0.875rem; }
  th { color: #6b7280; font-weight: 500; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }
  .badge-admin { background: #dbeafe; color: #1e40af; }
  .badge-user { background: #d1fae5; color: #065f46; }
  .btn { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.4rem 0.8rem; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; cursor: pointer; font-size: 0.8rem; color: #374151; }
  .btn:hover { background: #f9fafb; }
  .btn-danger { border-color: #fca5a5; color: #991b1b; }
  .btn-danger:hover { background: #fef2f2; }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
  .form-row { display: flex; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .form-row input, .form-row select { padding: 0.4rem 0.6rem; border: 1px solid #d1d5db; border-radius: 6px; font-size: 0.875rem; min-width: 140px; }
  .form-row label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8rem; color: #6b7280; }
  .error { color: #dc2626; font-size: 0.875rem; margin-top: 0.5rem; }
  .success { color: #059669; font-size: 0.875rem; margin-top: 0.5rem; }
</style>
</head>
<body>
<div class="header">
  <h1>DSH 管理控制台</h1>
  <a href="/">← 返回首页</a>
</div>
<div class="container">
  <div class="tabs">
    <button class="tab active" data-tab="users">用户管理</button>
    <button class="tab" data-tab="roles">角色管理</button>
  </div>

  <!-- Users panel -->
  <div class="panel active" id="panel-users">
    <div class="card">
      <h2>创建用户</h2>
      <form id="create-user-form">
        <div class="form-row">
          <label>用户名<input type="text" name="username" required></label>
          <label>显示名<input type="text" name="displayName"></label>
          <label>密码<input type="password" name="password" required minlength="6"></label>
          <label>角色
            <select name="roleId" required></select>
          </label>
        </div>
        <button type="submit" class="btn">创建用户</button>
        <div id="create-user-msg"></div>
      </form>
    </div>
    <div class="card">
      <h2>用户列表</h2>
      <table>
        <thead><tr><th>ID</th><th>用户名</th><th>显示名</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
        <tbody id="users-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Roles panel -->
  <div class="panel" id="panel-roles">
    <div class="card">
      <h2>角色列表</h2>
      <table>
        <thead><tr><th>ID</th><th>标识</th><th>标签</th><th>描述</th><th>操作</th></tr></thead>
        <tbody id="roles-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
(async function() {
  const TABS = document.querySelectorAll('.tab');
  TABS.forEach(t => t.addEventListener('click', () => {
    TABS.forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab).classList.add('active');
  }));

  async function api(url, opts) {
    const r = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...opts?.headers },
      ...opts,
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || '请求失败');
    return j;
  }

  async function loadRoles(selectEl) {
    const roles = await api('/auth/admin/roles');
    selectEl.innerHTML = roles.map(r => \`<option value="\${r.id}">\${r.label}</option>\`).join('');
  }

  async function loadUsers() {
    const users = await api('/auth/admin/users');
    document.getElementById('users-tbody').innerHTML = users.map(u => \`
      <tr>
        <td>\${u.id}</td>
        <td>\${u.username}</td>
        <td>\${u.displayName ?? '—'}</td>
        <td><span class="badge \${u.roleId === 1 ? 'badge-admin' : 'badge-user'}">\${u.roleName}</span></td>
        <td>\${u.status === 1 ? '正常' : '禁用'}</td>
        <td>
          <button class="btn btn-sm btn-danger" onclick="deleteUser(\${u.id})">删除</button>
        </td>
      </tr>
    \`).join('');
  }

  async function deleteUser(id) {
    if (!confirm('确定删除该用户？')) return;
    await api(\`/auth/admin/users/\${id}\`, { method: 'DELETE' });
    loadUsers();
  }

  window.deleteUser = deleteUser;

  const roleSelect = document.querySelector('select[name="roleId"]');
  await loadRoles(roleSelect);
  await loadUsers();

  document.getElementById('create-user-form').addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const msg = document.getElementById('create-user-msg');
    try {
      await api('/auth/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          username: fd.get('username'),
          displayName: fd.get('displayName') || undefined,
          password: fd.get('password'),
          roleId: Number(fd.get('roleId')),
        }),
      });
      msg.className = 'success';
      msg.textContent = '用户创建成功';
      e.target.reset();
      await loadRoles(roleSelect);
      await loadUsers();
    } catch(err) {
      msg.className = 'error';
      msg.textContent = err.message;
    }
  });
})();
</script>
</body>
</html>`
}

/** Plugin config schema (passed through to AuthPluginOptions). */
export const Config: z<AuthPluginOptions> = z.object({
  dbPath: z.string(),
  sessionExpireHours: z.natural().min(1),
  adminConsole: z.boolean(),
})
