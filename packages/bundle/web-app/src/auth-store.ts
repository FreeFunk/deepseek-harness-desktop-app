/**
 * SQLite-backed RBAC store: users, roles, permissions, and sessions.
 * The schema is initialized lazily on first use; the caller owns disposal.
 */

import { DatabaseSync, type StatementSync } from 'node:sqlite'
import { homedir } from 'node:os'
import { join, dirname } from 'node:path'
import { mkdirSync } from 'node:fs'
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto'
import type { SessionToken, UserId, RoleId, Permission } from './auth-user.ts'
import type { AuthUser } from './auth-user.ts'

const SCHEMA_VERSION = 1

const INIT_SQL = `
CREATE TABLE IF NOT EXISTS _meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO _meta (key, value) VALUES ('schema_version', '${String(SCHEMA_VERSION)}');

CREATE TABLE IF NOT EXISTS roles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT UNIQUE NOT NULL,
  label       TEXT NOT NULL,
  description TEXT,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS permissions (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id         INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id   INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  role_id      INTEGER NOT NULL REFERENCES roles(id),
  status       INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
  token      BLOB PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);
`

// ── Password hashing ──────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 100_000

function hashPassword(password: string, salt: Buffer): Buffer {
  return createHash('sha512')
    .update(salt)
    .update(Buffer.from(password, 'utf8'))
    .update(String(PBKDF2_ITERATIONS))
    .digest()
}

function verifyPassword(password: string, storedHash: string): boolean {
  const decoded = Buffer.from(storedHash, 'base64')
  if (decoded.byteLength < 49) return false
  const salt = decoded.subarray(0, 16)
  const stored = decoded.subarray(16)
  const computed = hashPassword(password, salt)
  return stored.length === computed.length && timingSafeEqual(stored, computed)
}

function encodeHash(salt: Buffer, hash: Buffer): string {
  return Buffer.concat([salt, hash]).toString('base64')
}

// ── Session token ────────────────────────────────────────────────────────────

function generateToken(): SessionToken {
  return randomBytes(32).toString('base64url') as SessionToken
}

function tokenBytes(token: SessionToken): Buffer {
  return Buffer.from(token, 'base64url')
}

// Add a leading marker to the DB so the file format is identifiable.
function tagSchemaVersion(db: DatabaseSync): void {
  // Ensure _meta exists for any schema migration tooling.
  db.exec(`CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
}

// ── Database row types ───────────────────────────────────────────────────────

interface DbUser {
  id: number
  username: string
  password_hash: string
  display_name: string | null
  role_id: number
  status: number
  role_name: string
  role_label: string
  permissions: string | null
}

interface DbSession {
  token: Buffer
  user_id: number
  expires_at: number
}

interface DbRole {
  id: number
  name: string
  label: string
  description: string | null
}

interface DbPermission {
  id: number
  name: string
}

// ── AuthStore ────────────────────────────────────────────────────────────────

export interface AuthStoreOptions {
  /** SQLite database file path. Default: `~/.dsh/auth.db`. */
  dbPath?: string
  /** Session lifetime in hours. Default: 24. */
  sessionExpireHours?: number
}

/**
 * SQLite-backed RBAC store: users, roles, permissions, and sessions.
 * Thread-unsafe — Node's `DatabaseSync` is per-worker; the web runtime uses
 * one instance on the host thread. Disposal closes the database.
 */
export class AuthStore {
  private readonly db: DatabaseSync
  private readonly sessionExpireMs: number
  // Prepared statements (cached for hot path).
  private readonly stmts: {
    userById: StatementSync
    userByUsername: StatementSync
    sessionInsert: StatementSync
    sessionDelete: StatementSync
    sessionGet: StatementSync
    sessionPurge: StatementSync
    usersList: StatementSync
    userInsert: StatementSync
    userUpdate: StatementSync
    userUpdatePassword: StatementSync
    userDelete: StatementSync
    rolesList: StatementSync
    roleInsert: StatementSync
    roleUpdate: StatementSync
    roleDelete: StatementSync
    rolePermissionsDelete: StatementSync
    rolePermissionsInsert: StatementSync
    permissionsList: StatementSync
    permissionInsert: StatementSync
    permissionByName: StatementSync
  }

  constructor(options: AuthStoreOptions = {}) {
    const dbPath = options.dbPath ?? join(homedir(), '.dsh', 'auth.db')
    this.sessionExpireMs = (options.sessionExpireHours ?? 24) * 60 * 60 * 1000
    mkdirSync(dirname(dbPath), { recursive: true })
    this.db = new DatabaseSync(dbPath)
    this.db.exec('PRAGMA journal_mode = WAL')
    this.db.exec('PRAGMA foreign_keys = ON')
    tagSchemaVersion(this.db)
    this.db.exec(INIT_SQL)

    // Prepared statements
    this.stmts = {
      userById: this.db.prepare(/* sql */ `
        SELECT u.id, u.username, u.password_hash, u.display_name, u.role_id, u.status,
               r.name AS role_name, r.label AS role_label,
               (SELECT GROUP_CONCAT(p.name) FROM role_permissions rp
                  JOIN permissions p ON p.id = rp.permission_id
                  WHERE rp.role_id = r.id) AS permissions
        FROM users u JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
      `),
      userByUsername: this.db.prepare(/* sql */ `SELECT id FROM users WHERE username = ? AND status = 1`),
      sessionInsert: this.db.prepare(/* sql */ `INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`),
      sessionDelete: this.db.prepare(/* sql */ `DELETE FROM sessions WHERE token = ?`),
      sessionGet: this.db.prepare(/* sql */ `SELECT user_id, expires_at FROM sessions WHERE token = ?`),
      sessionPurge: this.db.prepare(/* sql */ `DELETE FROM sessions WHERE expires_at < ?`),
      usersList: this.db.prepare(/* sql */ `SELECT id FROM users WHERE status != 0 ORDER BY id`),
      userInsert: this.db.prepare(/* sql */ `
        INSERT INTO users (username, password_hash, display_name, role_id, status)
        VALUES (?, ?, ?, ?, ?)
      `),
      userUpdate: this.db.prepare(/* sql */ `
        UPDATE users SET display_name = ?, role_id = ?, status = ?, updated_at = unixepoch() WHERE id = ?
      `),
      userUpdatePassword: this.db.prepare(/* sql */ `
        UPDATE users SET password_hash = ?, updated_at = unixepoch() WHERE id = ?
      `),
      userDelete: this.db.prepare(/* sql */ `DELETE FROM users WHERE id = ?`),
      rolesList: this.db.prepare(/* sql */ `SELECT id, name, label, description FROM roles ORDER BY id`),
      roleInsert: this.db.prepare(/* sql */ `INSERT INTO roles (name, label, description) VALUES (?, ?, ?)`),
      roleUpdate: this.db.prepare(/* sql */ `UPDATE roles SET label = ?, description = ? WHERE id = ?`),
      roleDelete: this.db.prepare(/* sql */ `DELETE FROM roles WHERE id = ?`),
      rolePermissionsDelete: this.db.prepare(/* sql */ `DELETE FROM role_permissions WHERE role_id = ?`),
      rolePermissionsInsert: this.db.prepare(/* sql */ `INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`),
      permissionsList: this.db.prepare(/* sql */ `SELECT id, name FROM permissions ORDER BY id`),
      permissionInsert: this.db.prepare(/* sql */ `INSERT OR IGNORE INTO permissions (name) VALUES (?)`),
      permissionByName: this.db.prepare(/* sql */ `SELECT id FROM permissions WHERE name = ?`),
    }

    this.seedDefaults()
  }

  /** Close the database handle. */
  dispose(): void {
    this.db.close()
  }

  // ── User / session lookups ────────────────────────────────────────────────

  /** Verify credentials and resolve to a live user; null on failure. */
  verifyCredentials(username: string, password: string): AuthUser | null {
    const row = this.stmts.userByUsername.get(username) as { id: number } | undefined
    if (!row) return null
    const user = this.stmts.userById.get(row.id) as DbUser | undefined
    if (!user) return null
    if (!verifyPassword(password, user.password_hash)) return null
    return this.toAuthUser(user)
  }

  /** Resolve a session token to its user, or null on miss / expiry / disabled. */
  getUserByToken(token: SessionToken | null): AuthUser | null {
    if (!token) return null
    const now = Date.now()
    const session = this.stmts.sessionGet.get(tokenBytes(token)) as DbSession | undefined
    if (!session) return null
    if (session.expires_at <= now) {
      this.stmts.sessionDelete.run(tokenBytes(token))
      return null
    }
    const user = this.stmts.userById.get(session.user_id) as DbUser | undefined
    return user ? this.toAuthUser(user) : null
  }

  /** Mint a fresh session for the given user; returns the token + absolute expiry epoch ms. */
  createSession(userId: UserId): { token: SessionToken; expiresAt: number } {
    const token = generateToken()
    const expiresAt = Date.now() + this.sessionExpireMs
    this.stmts.sessionInsert.run(tokenBytes(token), userId, expiresAt)
    this.stmts.sessionPurge.run(Date.now())
    return { token, expiresAt }
  }

  /** Drop one session by token (idempotent). */
  destroySession(token: SessionToken | null): void {
    if (!token) return
    this.stmts.sessionDelete.run(tokenBytes(token))
  }

  // ── User management (admin) ───────────────────────────────────────────────

  listUsers(): AuthUser[] {
    const rows = this.stmts.usersList.all() as { id: number }[]
    const result: AuthUser[] = []
    for (const row of rows) {
      const user = this.stmts.userById.get(row.id) as DbUser | undefined
      if (!user) continue
      const resolved = this.toAuthUser(user)
      if (resolved !== null) result.push(resolved)
    }
    return result
  }

  createUser(input: {
    username: string
    password: string
    roleId: number
    displayName?: string
    status?: number
  }): AuthUser {
    const salt = randomBytes(16)
    const hash = hashPassword(input.password, salt)
    const info = this.stmts.userInsert.run(
      input.username,
      encodeHash(salt, hash),
      input.displayName ?? null,
      input.roleId,
      input.status ?? 1,
    )
    const user = this.stmts.userById.get(info.lastInsertRowid) as unknown as DbUser
    const resolved = this.toAuthUser(user)
    if (resolved === null) throw new Error('created user but has no active session')
    return resolved
  }

  updateUser(
    id: number,
    updates: {
      displayName?: string
      roleId?: number
      status?: number
      password?: string
    },
  ): AuthUser {
    const existing = this.stmts.userById.get(id) as DbUser | undefined
    if (!existing) throw new Error('user not found')
    this.stmts.userUpdate.run(
      updates.displayName !== undefined ? updates.displayName : existing.display_name,
      updates.roleId !== undefined ? updates.roleId : existing.role_id,
      updates.status !== undefined ? updates.status : existing.status,
      id,
    )
    if (updates.password !== undefined) {
      const salt = randomBytes(16)
      this.stmts.userUpdatePassword.run(encodeHash(salt, hashPassword(updates.password, salt)), id)
    }
    const user = this.stmts.userById.get(id) as unknown as DbUser
    const resolved = this.toAuthUser(user)
    if (resolved === null) throw new Error('updated user but has no active session')
    return resolved
  }

  deleteUser(id: number): void {
    this.stmts.userDelete.run(id)
  }

  /** Verify the current password then set a new one. */
  changeOwnPassword(userId: number, currentPassword: string, newPassword: string): void {
    const user = this.stmts.userById.get(userId) as DbUser | undefined
    if (!user) throw new Error('user not found')
    if (!verifyPassword(currentPassword, user.password_hash)) throw new Error('当前密码不正确')
    const salt = randomBytes(16)
    this.stmts.userUpdatePassword.run(encodeHash(salt, hashPassword(newPassword, salt)), userId)
  }

  // ── Role management ───────────────────────────────────────────────────────

  listRoles(): DbRole[] {
    return this.stmts.rolesList.all() as unknown as DbRole[]
  }

  createRole(input: {
    name: string
    label: string
    description?: string
    permissions?: Permission[]
  }): DbRole {
    const info = this.stmts.roleInsert.run(input.name, input.label, input.description ?? null)
    if (input.permissions?.length) {
      this.assignPermissions(info.lastInsertRowid as number, input.permissions)
    }
    return this.stmts.rolesList.get(info.lastInsertRowid) as unknown as DbRole
  }

  updateRole(
    id: number,
    updates: { label?: string; description?: string; permissions?: Permission[] },
  ): DbRole {
    const existing = this.stmts.rolesList.get(id) as unknown as DbRole | undefined
    if (!existing) throw new Error('role not found')
    if (updates.label !== undefined || updates.description !== undefined) {
      this.stmts.roleUpdate.run(
        updates.label !== undefined ? updates.label : existing.label,
        updates.description !== undefined ? updates.description : existing.description,
        id,
      )
    }
    if (updates.permissions !== undefined) {
      this.stmts.rolePermissionsDelete.run(id)
      if (updates.permissions.length) this.assignPermissions(id, updates.permissions)
    }
    return this.stmts.rolesList.get(id) as DbRole
  }

  deleteRole(id: number): void {
    this.stmts.roleDelete.run(id)
  }

  listPermissions(): DbPermission[] {
    return this.stmts.permissionsList.all() as unknown as DbPermission[]
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  /** Convert a DB row to a runtime AuthUser; null when disabled. */
  private toAuthUser(user: DbUser): AuthUser | null {
    if (user.status === 0) return null
    return {
      id: user.id as UserId,
      username: user.username,
      displayName: user.display_name,
      roleId: user.role_id as RoleId,
      roleName: user.role_name,
      permissions: user.permissions ? (user.permissions.split(',') as readonly Permission[]) : [],
      status: user.status,
    }
  }

  private assignPermissions(roleId: number, perms: readonly Permission[]): void {
    for (const name of perms) {
      this.stmts.permissionInsert.run(name)
      const row = this.stmts.permissionByName.get(name) as { id: number } | undefined
      if (row) this.stmts.rolePermissionsInsert.run(roleId, row.id)
    }
  }

  private seedDefaults(): void {
    const existing = this.db.prepare(/* sql */ `SELECT 1 FROM roles WHERE name = 'admin'`).get()
    if (existing) return
    // Permissions
    const perms = [
      'page:admin', 'api:admin',
      'session:list', 'session:read', 'session:delete',
      'settings:read', 'settings:write',
    ] as const
    const userRolePerms = ['session:list', 'session:read', 'settings:read', 'settings:write']
    for (const p of perms) this.stmts.permissionInsert.run(p)

    // Admin role (gets every permission)
    const adminInfo = this.stmts.roleInsert.run('admin', '管理员', '完整系统管理权限')
    const adminId = adminInfo.lastInsertRowid as number
    for (const p of perms) {
      const row = this.stmts.permissionByName.get(p) as { id: number } | undefined
      if (row) this.stmts.rolePermissionsInsert.run(adminId, row.id)
    }

    // User role (subset)
    const userInfo = this.stmts.roleInsert.run('user', '普通用户', '基础使用权限')
    const userId = userInfo.lastInsertRowid as number
    for (const p of userRolePerms) {
      const row = this.stmts.permissionByName.get(p) as { id: number } | undefined
      if (row) this.stmts.rolePermissionsInsert.run(userId, row.id)
    }

    // Default admin account
    const salt = randomBytes(16)
    const hash = hashPassword('admin123', salt)
    this.stmts.userInsert.run('admin', encodeHash(salt, hash), '系统管理员', adminId, 1)
  }
}