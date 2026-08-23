/**
 * @deepseek-ai/dsh-web-app/auth — role-based access control for the Web
 * surface. Owns the auth database (`users`/`roles`/`permissions`/`sessions`),
 * the transport-level guard that gates every request the webserver dispatches
 * (HTTP routes, the `/api/*` RPC prefix, and WebSocket upgrades), the login
 * page, the admin console (`/admin`), and the SPA bootstrap tap.
 *
 * The guard is the single enforcement point: before any route, fallback, or
 * upgrade handler runs it admits only the public auth surface (`/login`,
 * `/api/auth/login`, `/api/auth/logout`) without a session and rejects
 * everything else with a redirect (HTML navigation), 401 JSON (API), or a
 * destroyed socket (upgrade). Named routes therefore cannot bypass login by
 * being more specific than the fallback.
 *
 * Role model: a user has one role; a role has a set of permissions. Page
 * permissions (`page:*`) drive the UI and the admin-console gate; the
 * `api:admin` permission gates the user/role/permission management API.
 * @module @deepseek-ai/dsh-web-app/auth
 */

import { DatabaseSync } from 'node:sqlite'
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { mkdirSync, readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { serveStatic } from '@deepseek-ai/dsh-host-frontend-static'
import type { Context } from '@deepseek-ai/cordis'
import type { WebGuard } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { ADMIN_CONSOLE_HTML } from './admin-console.ts'
import { AUTH_BOOTSTRAP_SCRIPT } from './bootstrap.ts'

export const name = 'auth'
export const inject = ['webServer']

export interface Config {
  /** Absolute path to the built frontend `index.html` this plugin serves. */
  distIndex: string
  /** SQLite database path; defaults to `~/.dsh/auth.db`. */
  dbPath?: string
  /** Session lifetime in hours; defaults to 24. */
  sessionExpireHours?: number
}

export const Config: z<Config> = z.object({
  distIndex: z.string().required(),
  dbPath: z.string(),
  sessionExpireHours: z.natural().min(1).default(24),
})

/** One `dsh_users` row. */
interface UserRow {
  id: number
  username: string
  password_hash: string
  display_name: string
  role_id: number
  status: number
  created_at: string
  updated_at: string
}

/** One `dsh_roles` row. */
interface RoleRow {
  id: number
  name: string
  label: string
  description: string
  is_system: number
  created_at: string
}

/** One `dsh_permissions` row. */
interface PermissionRow {
  id: number
  key: string
  label: string
  group: string
  description: string
}

/** One `dsh_sessions` row. */
interface SessionRow {
  token: string
  user_id: number
  created_at: string
  expires_at: string
}

/** Signed-in user face returned by `/api/auth/me` and used by the guard. */
export interface AuthUser {
  id: number
  username: string
  displayName: string
  role: { id: number; name: string; label: string }
  permissions: string[]
  status: number
}

/** Admin API role row. */
export interface RoleView {
  id: number
  name: string
  label: string
  description: string
  isSystem: boolean
  permissions: string[]
  createdAt: string
}

/** Admin API user row. */
export interface UserView {
  id: number
  username: string
  displayName: string
  roleId: number
  roleName: string
  roleLabel: string
  status: number
  createdAt: string
}

/** Admin API permission row. */
export interface PermissionView {
  id: number
  key: string
  label: string
  group: string
  description: string
}

/** Seeded permission catalog; keys are stable identifiers the role editor toggles. */
const PERMISSION_SEED = [
  { key: 'page:chat', label: '对话', group: 'page', description: '进入对话界面' },
  { key: 'page:history', label: '会话历史', group: 'page', description: '查看会话历史列表' },
  { key: 'page:settings', label: '设置', group: 'page', description: '访问设置（含模型配置）' },
  { key: 'page:tools', label: '工具', group: 'page', description: '查看工具视图' },
  { key: 'page:admin', label: '管理控制台', group: 'page', description: '进入用户/角色/权限管理控制台' },
  { key: 'api:admin', label: '管理接口', group: 'api', description: '调用用户/角色/权限管理接口' },
] as const

/** Seeded roles: the system `admin` and `user` roles. */
const ROLE_SEED = [
  {
    name: 'admin',
    label: '管理员',
    description: '拥有全部权限',
    isSystem: true,
    permissions: PERMISSION_SEED.map(p => p.key),
  },
  {
    name: 'user',
    label: '普通用户',
    description: '可使用对话、会话历史与工具',
    isSystem: true,
    permissions: ['page:chat', 'page:history', 'page:tools'],
  },
] as const

/** Password hash minimum length for new/changed passwords. */
const MIN_PASSWORD_LENGTH = 6

/** Cookie name carrying the session token. */
const SESSION_COOKIE = 'dsh_token'

/**
 * All database access for the auth surface. One instance owns one SQLite
 * file; the database is created and seeded lazily in the constructor.
 */
class AuthStore {
  private readonly db: DatabaseSync
  private readonly sessionExpireMs: number

  constructor(dbPath: string, sessionExpireHours: number) {
    mkdirSync(dirname(dbPath), { recursive: true })
    this.db = new DatabaseSync(dbPath)
    this.sessionExpireMs = sessionExpireHours * 60 * 60 * 1000
    this.db.exec('PRAGMA journal_mode=WAL')
    this.createSchema()
    this.seedPermissions()
    this.seedRoles()
    this.migrateLegacyUsers()
    this.ensureAdmin()
    this.cleanExpiredSessions()
  }

  /** Close the SQLite handle (plugin teardown). */
  dispose(): void {
    this.db.close()
  }

  private createSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dsh_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        is_system INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dsh_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        "group" TEXT NOT NULL DEFAULT 'page',
        description TEXT NOT NULL DEFAULT ''
      )
    `)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dsh_role_permissions (
        role_id INTEGER NOT NULL REFERENCES dsh_roles(id) ON DELETE CASCADE,
        permission_id INTEGER NOT NULL REFERENCES dsh_permissions(id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
      )
    `)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dsh_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        role_id INTEGER NOT NULL REFERENCES dsh_roles(id),
        status INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dsh_sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES dsh_users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL
      )
    `)
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_dsh_users_role ON dsh_users(role_id)')
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_dsh_sessions_user ON dsh_sessions(user_id)')
  }

  private seedPermissions(): void {
    const insert = this.db.prepare('INSERT OR IGNORE INTO dsh_permissions (key, label, "group", description) VALUES (?, ?, ?, ?)')
    for (const p of PERMISSION_SEED) insert.run(p.key, p.label, p.group, p.description)
  }

  private seedRoles(): void {
    for (const seed of ROLE_SEED) {
      const existing = this.db.prepare('SELECT id FROM dsh_roles WHERE name = ?').get(seed.name) as { id: number } | undefined
      const roleId = existing?.id ?? Number(
        this.db.prepare('INSERT INTO dsh_roles (name, label, description, is_system) VALUES (?, ?, ?, ?)')
          .run(seed.name, seed.label, seed.description, Number(seed.isSystem)).lastInsertRowid,
      )
      for (const key of seed.permissions) {
        const perm = this.db.prepare('SELECT id FROM dsh_permissions WHERE key = ?').get(key) as { id: number } | undefined
        if (perm !== undefined) {
          this.db.prepare('INSERT OR IGNORE INTO dsh_role_permissions (role_id, permission_id) VALUES (?, ?)').run(roleId, perm.id)
        }
      }
    }
  }

  private tableExists(name: string): boolean {
    return this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined
  }

  /**
   * Carry pre-RBAC `users` rows (schema `role TEXT`) into the new schema the
   * first time the new tables are empty, mapping the legacy role name onto
   * the seeded roles. Sessions are not carried over: users re-login.
   */
  private migrateLegacyUsers(): void {
    if (!this.tableExists('users')) return
    const count = (this.db.prepare('SELECT COUNT(*) AS c FROM dsh_users').get() as { c: number }).c
    if (count > 0) return
    const legacy = this.db.prepare('SELECT username, password_hash, role FROM users').all() as unknown as Array<{ username: string; password_hash: string; role: string }>
    if (legacy.length === 0) return
    const adminRole = this.roleIdByName('admin')
    const userRole = this.roleIdByName('user')
    const insert = this.db.prepare('INSERT INTO dsh_users (username, password_hash, role_id, status) VALUES (?, ?, ?, 1)')
    for (const row of legacy) {
      insert.run(row.username, row.password_hash, row.role === 'admin' ? adminRole : userRole)
    }
  }

  /** Create the bootstrap `admin`/`admin123` account when no user exists. */
  private ensureAdmin(): void {
    const count = (this.db.prepare('SELECT COUNT(*) AS c FROM dsh_users').get() as { c: number }).c
    if (count > 0) return
    const adminRole = this.roleIdByName('admin')
    this.db.prepare('INSERT INTO dsh_users (username, password_hash, role_id, status) VALUES (?, ?, ?, 1)')
      .run('admin', AuthStore.hashPassword('admin123'), adminRole)
  }

  private cleanExpiredSessions(): void {
    this.db.prepare('DELETE FROM dsh_sessions WHERE expires_at < ?').run(new Date().toISOString())
  }

  private roleNameById(id: number): string {
    const row = this.db.prepare('SELECT name FROM dsh_roles WHERE id = ?').get(id) as { name: string } | undefined
    if (row === undefined) throw new Error('角色不存在')
    return row.name
  }

  private roleIdByName(name: string): number {
    const row = this.db.prepare('SELECT id FROM dsh_roles WHERE name = ?').get(name) as { id: number } | undefined
    if (row === undefined) throw new Error(`auth: seeded role ${name} missing`)
    return row.id
  }

  private static hashPassword(password: string): string {
    const salt = randomBytes(16).toString('hex')
    const hash = scryptSync(password, salt, 64).toString('hex')
    return `${salt}:${hash}`
  }

  private static verifyPassword(password: string, stored: string): boolean {
    const [salt, hash] = stored.split(':')
    if (!salt || !hash) return false
    const candidate = scryptSync(password, salt, 64)
    const expected = Buffer.from(hash, 'hex')
    return candidate.length === expected.length && timingSafeEqual(candidate, expected)
  }

  private permissionsForRole(roleId: number): string[] {
    const rows = this.db.prepare(`
      SELECT p.key FROM dsh_permissions p
      JOIN dsh_role_permissions rp ON rp.permission_id = p.id
      WHERE rp.role_id = ?
      ORDER BY p.id
    `).all(roleId) as unknown as Array<{ key: string }>
    return rows.map(r => r.key)
  }

  private toAuthUser(row: UserRow & { role_name: string; role_label: string }): AuthUser {
    return {
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      role: { id: row.role_id, name: row.role_name, label: row.role_label },
      permissions: this.permissionsForRole(row.role_id),
      status: row.status,
    }
  }

  private userQuery(): string {
    return `
      SELECT u.id, u.username, u.password_hash, u.display_name, u.role_id, u.status, u.created_at, u.updated_at,
             r.name AS role_name, r.label AS role_label
      FROM dsh_users u JOIN dsh_roles r ON r.id = u.role_id
    `
  }

  /** Resolve the session bearer to the signed-in user, or null when absent/expired/disabled. */
  getUserByToken(token: string | undefined): AuthUser | null {
    if (!token) return null
    const session = this.db.prepare('SELECT * FROM dsh_sessions WHERE token = ?').get(token) as SessionRow | undefined
    if (session === undefined) return null
    if (new Date(session.expires_at).getTime() < Date.now()) {
      this.db.prepare('DELETE FROM dsh_sessions WHERE token = ?').run(token)
      return null
    }
    const row = this.db.prepare(`${this.userQuery()} WHERE u.id = ? AND u.status = 1`).get(session.user_id) as
      (UserRow & { role_name: string; role_label: string }) | undefined
    return row === undefined ? null : this.toAuthUser(row)
  }

  /** Verify a username/password pair against an active user. */
  verifyCredentials(username: string, password: string): AuthUser | null {
    const row = this.db.prepare(`${this.userQuery()} WHERE u.username = ?`).get(username) as
      (UserRow & { role_name: string; role_label: string }) | undefined
    if (row === undefined || !AuthStore.verifyPassword(password, row.password_hash) || row.status !== 1) return null
    return this.toAuthUser(row)
  }

  /** Create a session and return its token plus expiry. */
  createSession(userId: number): { token: string; expiresAt: string } {
    const token = randomUUID()
    const expiresAt = new Date(Date.now() + this.sessionExpireMs).toISOString()
    this.db.prepare('INSERT INTO dsh_sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt)
    return { token, expiresAt }
  }

  /** Delete a session by token (idempotent). */
  destroySession(token: string | undefined): void {
    if (!token) return
    this.db.prepare('DELETE FROM dsh_sessions WHERE token = ?').run(token)
  }

  /** Admin listing of users with their role labels. */
  listUsers(): UserView[] {
    const rows = this.db.prepare(`
      SELECT u.id, u.username, u.display_name, u.role_id, u.status, u.created_at,
             r.name AS role_name, r.label AS role_label
      FROM dsh_users u JOIN dsh_roles r ON r.id = u.role_id
      ORDER BY u.id
    `).all() as unknown as Array<{ id: number; username: string; display_name: string; role_id: number; status: number; created_at: string; role_name: string; role_label: string }>
    return rows.map(r => ({
      id: r.id,
      username: r.username,
      displayName: r.display_name,
      roleId: r.role_id,
      roleName: r.role_name,
      roleLabel: r.role_label,
      status: r.status,
      createdAt: r.created_at,
    }))
  }

  /** Create a user; throws with a user-facing message on validation failure. */
  createUser(input: { username: string; password: string; displayName?: string; roleId: number; status?: number }): UserView {
    const username = input.username.trim()
    if (!username) throw new Error('用户名不能为空')
    if (!input.password || input.password.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`密码至少 ${MIN_PASSWORD_LENGTH} 位`)
    }
    this.getRole(input.roleId)
    const taken = this.db.prepare('SELECT id FROM dsh_users WHERE username = ?').get(username)
    if (taken !== undefined) throw new Error('用户名已存在')
    this.db.prepare('INSERT INTO dsh_users (username, password_hash, display_name, role_id, status) VALUES (?, ?, ?, ?, ?)')
      .run(username, AuthStore.hashPassword(input.password), input.displayName?.trim() ?? '', input.roleId, input.status ?? 1)
    return this.userViewByUsername(username)
  }

  /** Update a user's mutable fields; a supplied password resets the login. */
  updateUser(id: number, input: { displayName?: string; roleId?: number; status?: number; password?: string }): UserView {
    const existing = this.db.prepare('SELECT * FROM dsh_users WHERE id = ?').get(id) as UserRow | undefined
    if (existing === undefined) throw new Error('用户不存在')
    if (input.roleId !== undefined) this.getRole(input.roleId)
    const nextRoleId = input.roleId ?? existing.role_id
    const nextStatus = input.status ?? existing.status
    const demotesOrDisablesLastAdmin = this.isLastActiveAdmin(existing)
      && (nextStatus === 0 || this.roleNameById(nextRoleId) !== 'admin')
    if (demotesOrDisablesLastAdmin) throw new Error('不能停用或移除最后一个管理员')
    if (input.password !== undefined) {
      if (input.password.length < MIN_PASSWORD_LENGTH) throw new Error(`密码至少 ${MIN_PASSWORD_LENGTH} 位`)
      this.db.prepare('UPDATE dsh_users SET password_hash = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(AuthStore.hashPassword(input.password), id)
    }
    this.db.prepare(`UPDATE dsh_users SET
      display_name = ?, role_id = ?, status = ?, updated_at = datetime('now')
      WHERE id = ?`)
      .run(input.displayName?.trim() ?? existing.display_name, nextRoleId, nextStatus, id)
    const row = this.db.prepare(`${this.userQuery()} WHERE u.id = ?`).get(id) as (UserRow & { role_name: string; role_label: string }) | undefined
    if (row === undefined) throw new Error('用户不存在')
    return this.userViewFromRow(row)
  }

  /**
   * Delete a user. Refuses when the target is the last active admin (so the
   * deployment cannot lock itself out of the console).
   */
  deleteUser(id: number): void {
    const existing = this.db.prepare('SELECT * FROM dsh_users WHERE id = ?').get(id) as UserRow | undefined
    if (existing === undefined) throw new Error('用户不存在')
    if (this.isLastActiveAdmin(existing)) throw new Error('不能删除最后一个管理员')
    this.db.prepare('DELETE FROM dsh_users WHERE id = ?').run(id)
  }

  /** Whether the row is the last active user whose role is the admin role. */
  private isLastActiveAdmin(row: UserRow): boolean {
    const role = this.db.prepare('SELECT name FROM dsh_roles WHERE id = ?').get(row.role_id) as { name: string } | undefined
    if (role?.name !== 'admin' || row.status !== 1) return false
    const admins = this.db.prepare(`
      SELECT COUNT(*) AS c FROM dsh_users u JOIN dsh_roles r ON r.id = u.role_id
      WHERE r.name = 'admin' AND u.status = 1 AND u.id != ?
    `).get(row.id) as { c: number }
    return admins.c === 0
  }

  /** Change the caller's own password after verifying the current one. */
  changeOwnPassword(userId: number, currentPassword: string, newPassword: string): void {
    const row = this.db.prepare('SELECT * FROM dsh_users WHERE id = ?').get(userId) as UserRow | undefined
    if (row === undefined) throw new Error('用户不存在')
    if (!AuthStore.verifyPassword(currentPassword, row.password_hash)) throw new Error('当前密码不正确')
    if (!newPassword || newPassword.length < MIN_PASSWORD_LENGTH) throw new Error(`新密码至少 ${MIN_PASSWORD_LENGTH} 位`)
    this.db.prepare('UPDATE dsh_users SET password_hash = ?, updated_at = datetime(\'now\') WHERE id = ?')
      .run(AuthStore.hashPassword(newPassword), userId)
  }

  private userViewByUsername(username: string): UserView {
    const row = this.db.prepare(`${this.userQuery()} WHERE u.username = ?`).get(username) as
      (UserRow & { role_name: string; role_label: string }) | undefined
    if (row === undefined) throw new Error('用户不存在')
    return this.userViewFromRow(row)
  }

  private userViewFromRow(row: UserRow & { role_name: string; role_label: string }): UserView {
    return {
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      roleId: row.role_id,
      roleName: row.role_name,
      roleLabel: row.role_label,
      status: row.status,
      createdAt: row.created_at,
    }
  }

  /** Admin listing of roles with their permission keys. */
  listRoles(): RoleView[] {
    const rows = this.db.prepare('SELECT * FROM dsh_roles ORDER BY id').all() as unknown as RoleRow[]
    return rows.map(r => this.roleViewFromRow(r))
  }

  private roleViewFromRow(row: RoleRow): RoleView {
    return {
      id: row.id,
      name: row.name,
      label: row.label,
      description: row.description,
      isSystem: row.is_system === 1,
      permissions: this.permissionsForRole(row.id),
      createdAt: row.created_at,
    }
  }

  /** Resolve one role or throw a user-facing error. */
  getRole(id: number): RoleView {
    const row = this.db.prepare('SELECT * FROM dsh_roles WHERE id = ?').get(id) as RoleRow | undefined
    if (row === undefined) throw new Error('角色不存在')
    return this.roleViewFromRow(row)
  }

  /** Create a role with an optional initial permission set. */
  createRole(input: { name: string; label: string; description?: string; permissions?: string[] }): RoleView {
    const name = input.name.trim()
    if (!name) throw new Error('角色标识不能为空')
    if (!input.label.trim()) throw new Error('角色显示名不能为空')
    const taken = this.db.prepare('SELECT id FROM dsh_roles WHERE name = ?').get(name)
    if (taken !== undefined) throw new Error('角色标识已存在')
    const id = Number(this.db.prepare('INSERT INTO dsh_roles (name, label, description) VALUES (?, ?, ?)')
      .run(name, input.label.trim(), input.description?.trim() ?? '').lastInsertRowid)
    this.setRolePermissions(id, input.permissions ?? [])
    return this.getRole(id)
  }

  /** Update a role's mutable fields; `permissions` replaces the full set. */
  updateRole(id: number, input: { label?: string; description?: string; permissions?: string[] }): RoleView {
    const existing = this.getRole(id)
    if (input.label !== undefined && !input.label.trim()) throw new Error('角色显示名不能为空')
    if (input.label !== undefined || input.description !== undefined) {
      this.db.prepare('UPDATE dsh_roles SET label = ?, description = ? WHERE id = ?')
        .run(input.label?.trim() ?? existing.label, input.description?.trim() ?? existing.description, id)
    }
    if (input.permissions !== undefined) this.setRolePermissions(id, input.permissions)
    return this.getRole(id)
  }

  /** Delete a non-system role that no user holds. */
  deleteRole(id: number): void {
    const existing = this.getRole(id)
    if (existing.isSystem) throw new Error('系统角色不可删除')
    const used = (this.db.prepare('SELECT COUNT(*) AS c FROM dsh_users WHERE role_id = ?').get(id) as { c: number }).c
    if (used > 0) throw new Error('该角色下仍有用户，无法删除')
    this.db.prepare('DELETE FROM dsh_roles WHERE id = ?').run(id)
  }

  /** Replace a role's permission set with the named keys (unknown keys ignored). */
  private setRolePermissions(roleId: number, keys: string[]): void {
    this.db.prepare('DELETE FROM dsh_role_permissions WHERE role_id = ?').run(roleId)
    const insert = this.db.prepare('INSERT OR IGNORE INTO dsh_role_permissions (role_id, permission_id) VALUES (?, ?)')
    for (const key of keys) {
      const perm = this.db.prepare('SELECT id FROM dsh_permissions WHERE key = ?').get(key) as { id: number } | undefined
      if (perm !== undefined) insert.run(roleId, perm.id)
    }
  }

  /** Admin listing of the permission catalog. */
  listPermissions(): PermissionView[] {
    const rows = this.db.prepare('SELECT * FROM dsh_permissions ORDER BY id').all() as unknown as PermissionRow[]
    return rows.map(r => ({ id: r.id, key: r.key, label: r.label, group: r.group, description: r.description }))
  }
}

/** Read the session token from a Cookie header. */
function tokenFromCookie(cookie: string | undefined): string | undefined {
  return cookie?.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`))?.[1]
}

/** URL pathname of a request target, defensively defaulted to `/`. */
function pathnameOf(url: string | undefined): string {
  try {
    return new URL(url ?? '/', 'http://dsh.internal').pathname
  } catch {
    return '/'
  }
}

/** Whether a request prefers an HTML document (used for login redirects). */
function acceptsHtml(req: IncomingMessage): boolean {
  return (req.headers.accept ?? '').includes('text/html')
}

/** Write a JSON response. */
function json(res: ServerResponse, code: number, data: unknown): void {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(data))
}

/** Buffer the request body as UTF-8 text. */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => { chunks.push(chunk) })
    req.on('end', () => { resolve(Buffer.concat(chunks).toString('utf8')) })
    req.on('error', reject)
  })
}

/** Parse an `:id` suffix after a base path, or undefined when not a positive integer. */
function idFromPath(path: string, base: string): number | undefined {
  const rest = path.slice(base.length + 1)
  const id = Number(rest)
  return Number.isInteger(id) && id > 0 ? id : undefined
}

const LOGIN_HTML = `<!DOCTYPE html>
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
document.getElementById("f").addEventListener("submit",async function(e){e.preventDefault();var x=document.getElementById("e");x.classList.remove("show");try{var r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})});if(!r.ok){var d=await r.json();x.textContent=d.error||"登录失败";x.classList.add("show");return}window.location.href="/"}catch(err){x.textContent="网络错误";x.classList.add("show")}})
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

/** Inject the auth bootstrap before the SPA's `</head>` (or append when absent). */
function injectBootstrap(html: string): string {
  const script = `<script>${AUTH_BOOTSTRAP_SCRIPT}</script>`
  if (html.includes('</head>')) return html.replace('</head>', `${script}</head>`)
  return `${html}${script}`
}

/** Built-in appearance preferences, mirroring the ui-theme settings document. */
type ThemePreference = 'light' | 'dark' | 'system'

/**
 * Read the persisted appearance preference from the Host user-settings
 * document (`settings.yaml`, namespace `ui-theme`, field `preference`). The
 * admin page renders this on every load so it follows the same appearance the
 * SPA shows. Absent or unparseable documents fall back to `system`.
 * @param settingsPath - the settings document path (derived from the auth DB's home).
 * @returns the stored preference, or `system`.
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
 * own theme bootstrap: it resolves `system` via `prefers-color-scheme`, then
 * toggles `body[data-ds-dark-theme]` and `color-scheme` so the page CSS flips
 * to the dark palette exactly when the application would.
 * @param preference - the persisted appearance preference.
 * @returns a `<script>` element string.
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

/**
 * Mount the auth plugin: the transport guard, the auth/admin API, the login
 * and admin-console pages, the SPA bootstrap tap, and static dist serving.
 * @param ctx - plugin context carrying the webServer service.
 * @param config - validated {@link Config}.
 */
export function apply(ctx: Context, config: Config): void {
  // Resolved lazily so importing the module never touches the home directory
  // (the default is only read when the plugin actually mounts).
  const dbPath = config.dbPath ?? join(homedir(), '.dsh', 'auth.db')
  const store = new AuthStore(dbPath, config.sessionExpireHours ?? 24)
  const settingsPath = join(dirname(dbPath), 'settings.yaml')
  const distIndex = config.distIndex
  const distRoot = dirname(distIndex)
  const renderIndex = async (): Promise<string> => ctx.webServer.renderIndex(await readFile(distIndex, 'utf8'))
  const getSession = (req: IncomingMessage): AuthUser | null => store.getUserByToken(tokenFromCookie(req.headers.cookie))

  ctx.effect(() => () => { store.dispose() }, 'auth: database')

  // Transport gate: every request (HTTP and upgrade) passes here before any
  // route, fallback, or upgrade handler. Only the public auth surface may
  // proceed without a session.
  const guard: WebGuard = (target, next) => {
    const path = pathnameOf(target.req.url)
    const method = target.req.method
    if (path === '/login' || path === '/api/auth/logout' || (path === '/api/auth/login' && method === 'POST')) {
      return next()
    }
    const user = getSession(target.req)
    if (user !== null) return next()
    if (target.socket !== undefined) { target.socket.destroy(); return }
    if (target.res !== undefined) {
      if (path.startsWith('/api/')) { json(target.res, 401, { error: '未登录' }); return }
      if (acceptsHtml(target.req)) { target.res.writeHead(302, { Location: '/login' }); target.res.end(); return }
      target.res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
      target.res.end(JSON.stringify({ error: '未登录' }))
      return
    }
    return next()
  }
  ctx.effect(() => ctx.webServer.registerGuard(guard), 'auth: transport guard')

  const register = (
    kind: 'exact' | 'prefix',
    path: string,
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
  ): void => {
    ctx.effect(() => ctx.webServer.register({ kind, path, handler }), `auth: route ${path}`)
  }

  const requireAdmin = (req: IncomingMessage, res: ServerResponse): AuthUser | null => {
    const user = getSession(req)
    if (user === null) { json(res, 401, { error: '未登录' }); return null }
    if (!user.permissions.includes('api:admin')) { json(res, 403, { error: '没有管理权限' }); return null }
    return user
  }

  register('exact', '/login', (req, res) => {
    if (getSession(req) !== null) {
      res.writeHead(302, { Location: '/' })
      res.end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(LOGIN_HTML)
  })

  register('exact', '/api/auth/login', async (req, res) => {
    if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed' }); return }
    try {
      const body = JSON.parse(await readBody(req)) as { username?: unknown; password?: unknown }
      if (typeof body.username !== 'string' || typeof body.password !== 'string') {
        json(res, 400, { error: '用户名或密码不能为空' }); return
      }
      const user = store.verifyCredentials(body.username, body.password)
      if (user === null) { json(res, 401, { error: '用户名或密码错误' }); return }
      const { token, expiresAt } = store.createSession(user.id)
      const maxAge = Math.max(1, Math.round((new Date(expiresAt).getTime() - Date.now()) / 1000))
      const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`,
      })
      res.end(JSON.stringify({ token, user }))
    } catch (e) {
      json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  })

  register('exact', '/api/auth/logout', (req, res) => {
    store.destroySession(tokenFromCookie(req.headers.cookie))
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    })
    res.end(JSON.stringify({ ok: true }))
  })

  register('exact', '/api/auth/me', (req, res) => {
    const user = getSession(req)
    if (user === null) { json(res, 401, { error: '未登录' }); return }
    json(res, 200, user)
  })

  register('exact', '/api/auth/menus', (req, res) => {
    const user = getSession(req)
    if (user === null) { json(res, 401, { error: '未登录' }); return }
    json(res, 200, { menus: menusFor(user) })
  })

  register('exact', '/api/auth/password', async (req, res) => {
    const user = getSession(req)
    if (user === null) { json(res, 401, { error: '未登录' }); return }
    if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed' }); return }
    try {
      const body = JSON.parse(await readBody(req)) as { currentPassword?: unknown; newPassword?: unknown }
      if (typeof body.currentPassword !== 'string' || typeof body.newPassword !== 'string') {
        json(res, 400, { error: '参数不完整' }); return
      }
      store.changeOwnPassword(user.id, body.currentPassword, body.newPassword)
      json(res, 200, { ok: true })
    } catch (e) {
      json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  })

  register('exact', '/api/auth/users', async (req, res) => {
    const admin = requireAdmin(req, res)
    if (admin === null) return
    if (req.method === 'GET') { json(res, 200, { users: store.listUsers() }); return }
    if (req.method === 'POST') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          username?: unknown
          password?: unknown
          displayName?: unknown
          roleId?: unknown
          status?: unknown
        }
        if (typeof body.username !== 'string' || typeof body.password !== 'string' || typeof body.roleId !== 'number') {
          json(res, 400, { error: '参数不完整' }); return
        }
        const user = store.createUser({
          username: body.username,
          password: body.password,
          roleId: body.roleId,
          ...(typeof body.displayName === 'string' ? { displayName: body.displayName } : {}),
          ...(typeof body.status === 'number' ? { status: body.status } : {}),
        })
        json(res, 201, { user })
      } catch (e) {
        json(res, 400, { error: e instanceof Error ? e.message : String(e) })
      }
      return
    }
    json(res, 405, { error: 'Method not allowed' })
  })

  register('prefix', '/api/auth/users', async (req, res) => {
    const admin = requireAdmin(req, res)
    if (admin === null) return
    const id = idFromPath(pathnameOf(req.url), '/api/auth/users')
    if (id === undefined) { json(res, 404, { error: '用户不存在' }); return }
    try {
      if (req.method === 'PATCH') {
        const body = JSON.parse(await readBody(req)) as {
          displayName?: unknown
          roleId?: unknown
          status?: unknown
          password?: unknown
        }
        const user = store.updateUser(id, {
          ...(typeof body.displayName === 'string' ? { displayName: body.displayName } : {}),
          ...(typeof body.roleId === 'number' ? { roleId: body.roleId } : {}),
          ...(typeof body.status === 'number' ? { status: body.status } : {}),
          ...(typeof body.password === 'string' ? { password: body.password } : {}),
        })
        json(res, 200, { user })
        return
      }
      if (req.method === 'DELETE') {
        store.deleteUser(id)
        json(res, 200, { ok: true })
        return
      }
      json(res, 405, { error: 'Method not allowed' })
    } catch (e) {
      json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  })

  register('exact', '/api/auth/roles', async (req, res) => {
    const admin = requireAdmin(req, res)
    if (admin === null) return
    if (req.method === 'GET') { json(res, 200, { roles: store.listRoles() }); return }
    if (req.method === 'POST') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          name?: unknown
          label?: unknown
          description?: unknown
          permissions?: unknown
        }
        if (typeof body.name !== 'string' || typeof body.label !== 'string') {
          json(res, 400, { error: '参数不完整' }); return
        }
        const role = store.createRole({
          name: body.name,
          label: body.label,
          ...(typeof body.description === 'string' ? { description: body.description } : {}),
          ...(Array.isArray(body.permissions) ? { permissions: body.permissions.filter((p): p is string => typeof p === 'string') } : {}),
        })
        json(res, 201, { role })
      } catch (e) {
        json(res, 400, { error: e instanceof Error ? e.message : String(e) })
      }
      return
    }
    json(res, 405, { error: 'Method not allowed' })
  })

  register('prefix', '/api/auth/roles', async (req, res) => {
    const admin = requireAdmin(req, res)
    if (admin === null) return
    const id = idFromPath(pathnameOf(req.url), '/api/auth/roles')
    if (id === undefined) { json(res, 404, { error: '角色不存在' }); return }
    try {
      if (req.method === 'PATCH') {
        const body = JSON.parse(await readBody(req)) as {
          label?: unknown
          description?: unknown
          permissions?: unknown
        }
        const role = store.updateRole(id, {
          ...(typeof body.label === 'string' ? { label: body.label } : {}),
          ...(typeof body.description === 'string' ? { description: body.description } : {}),
          ...(Array.isArray(body.permissions) ? { permissions: body.permissions.filter((p): p is string => typeof p === 'string') } : {}),
        })
        json(res, 200, { role })
        return
      }
      if (req.method === 'DELETE') {
        store.deleteRole(id)
        json(res, 200, { ok: true })
        return
      }
      json(res, 405, { error: 'Method not allowed' })
    } catch (e) {
      json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  })

  register('exact', '/api/auth/permissions', (req, res) => {
    const admin = requireAdmin(req, res)
    if (admin === null) return
    json(res, 200, { permissions: store.listPermissions() })
  })

  register('prefix', '/admin', (req, res) => {
    const user = getSession(req)
    if (user === null) { res.writeHead(302, { Location: '/login' }); res.end(); return }
    if (!user.permissions.includes('page:admin')) {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>无权限</title></head>'
        + '<body style="background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh">'
        + '<div style="text-align:center"><h1 style="color:#f85149">403 无权限</h1>'
        + '<p style="color:#8b949e">当前账号没有访问管理控制台的权限</p>'
        + '<p style="margin-top:12px"><a href="/" style="color:#58a6ff">返回首页</a></p></div></body></html>')
      return
    }
    const html = ADMIN_CONSOLE_HTML.replace('<!--__AUTH_BOOT_THEME__-->', bootThemeScript(themePreference(settingsPath)))
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(html)
  })

  ctx.effect(() => ctx.webServer.tapIndex(injectBootstrap), 'auth: bootstrap index tap')

  // Fallback: serve the SPA dist. The transport guard has already admitted
  // the request, so no per-request auth check belongs here.
  ctx.effect(() => ctx.webServer.registerFallback(async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405)
      res.end()
      return
    }
    await serveStatic(decodeURIComponent(pathnameOf(req.url)), res, distRoot, distIndex, renderIndex)
  }), 'auth: static fallback')
}
