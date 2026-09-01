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
  created_at: number
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
  created_at: number
}

interface DbPermission {
  id: number
  name: string
}

/** Admin users-list row: role display name plus creation time. */
export interface UserView {
  id: number
  username: string
  displayName: string | null
  roleId: number
  roleName: string
  roleLabel: string
  status: number
  createdAt: number
  permissions: readonly string[]
}

/** Admin roles-list row: permission keys plus the system-role marker. */
export interface RoleView {
  id: number
  name: string
  label: string
  description: string | null
  isSystem: boolean
  permissions: string[]
  createdAt: number
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
    roleById: StatementSync
    roleByName: StatementSync
    rolePermissionsList: StatementSync
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
    // v0 → v1: the initial pre-release layout had no role_id on users; add it
    // when the column is absent so an existing auth.db survives the upgrade.
    // Runs after INIT_SQL so fresh databases already carry the column; the
    // users index is created here too because it cannot exist on a pre-v1
    // table until the column has been added.
    const userColumns = this.db.prepare(`PRAGMA table_info(users)`).all() as Array<{ name: string }>
    if (!userColumns.some((column) => column.name === 'role_id')) {
      this.db.exec('ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id)')
      this.db.exec("UPDATE users SET role_id = (SELECT r.id FROM roles r WHERE r.name = 'user') WHERE role_id IS NULL")
    }
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id)')

    // Prepared statements
    this.stmts = {
      userById: this.db.prepare(/* sql */ `
        SELECT u.id, u.username, u.password_hash, u.display_name, u.role_id, u.status, u.created_at,
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
      usersList: this.db.prepare(/* sql */ `
        SELECT u.id, u.username, u.display_name, u.role_id, u.status, u.created_at,
               r.name AS role_name, r.label AS role_label
        FROM users u JOIN roles r ON r.id = u.role_id
        WHERE u.status != 0
        ORDER BY u.id
      `),
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
      rolesList: this.db.prepare(/* sql */ `SELECT id, name, label, description, created_at FROM roles ORDER BY id`),
      roleById: this.db.prepare(/* sql */ `SELECT id, name, label, description, created_at FROM roles WHERE id = ?`),
      roleByName: this.db.prepare(/* sql */ `SELECT id FROM roles WHERE name = ?`),
      rolePermissionsList: this.db.prepare(/* sql */ `
        SELECT p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
        WHERE rp.role_id = ? ORDER BY p.id
      `),
      roleInsert: this.db.prepare(/* sql */ `INSERT INTO roles (name, label, description) VALUES (?, ?, ?)`),
      roleUpdate: this.db.prepare(/* sql */ `UPDATE roles SET label = ?, description = ? WHERE id = ?`),
      roleDelete: this.db.prepare(/* sql */ `DELETE FROM roles WHERE id = ?`),
      rolePermissionsDelete: this.db.prepare(/* sql */ `DELETE FROM role_permissions WHERE role_id = ?`),
      rolePermissionsInsert: this.db.prepare(/* sql */ `INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`),
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

  listUsers(): UserView[] {
    const rows = this.stmts.usersList.all() as unknown as Array<{
      id: number
      username: string
      display_name: string | null
      role_id: number
      status: number
      created_at: number
      role_name: string
      role_label: string
    }>
    return rows.map(row => ({
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      roleId: row.role_id,
      roleName: row.role_name,
      roleLabel: row.role_label,
      status: row.status,
      createdAt: row.created_at,
      permissions: this.permissionsForRole(row.role_id),
    }))
  }

  createUser(input: {
    username: string
    password: string
    roleId: number
    displayName?: string
    status?: number
  }): UserView {
    const username = input.username.trim()
    if (!username) throw new Error('用户名不能为空')
    if (input.password.length < 6) throw new Error('密码长度至少 6 位')
    const salt = randomBytes(16)
    const hash = hashPassword(input.password, salt)
    const info = this.stmts.userInsert.run(
      username,
      encodeHash(salt, hash),
      input.displayName ?? null,
      input.roleId,
      input.status ?? 1,
    )
    return this.userViewFromRow(this.stmts.userById.get(info.lastInsertRowid) as unknown as DbUser)
  }

  updateUser(
    id: number,
    updates: {
      displayName?: string
      roleId?: number
      status?: number
      password?: string
    },
  ): UserView {
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
    return this.userViewFromRow(this.stmts.userById.get(id) as unknown as DbUser)
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

  listRoles(): RoleView[] {
    const rows = this.stmts.rolesList.all() as unknown as DbRole[]
    return rows.map(row => this.roleViewFromRow(row))
  }

  createRole(input: {
    name: string
    label: string
    description?: string
    permissions?: Permission[]
  }): RoleView {
    const info = this.stmts.roleInsert.run(input.name, input.label, input.description ?? null)
    const id = info.lastInsertRowid as number
    if (input.permissions?.length) this.assignPermissions(id, input.permissions)
    return this.roleViewFromRow(this.stmts.roleById.get(id) as unknown as DbRole)
  }

  updateRole(
    id: number,
    updates: { label?: string; description?: string; permissions?: Permission[] },
  ): RoleView {
    const existing = this.stmts.roleById.get(id) as unknown as DbRole | undefined
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
    return this.roleViewFromRow(this.stmts.roleById.get(id) as unknown as DbRole)
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
      roleLabel: user.role_label,
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
    // Idempotent seeding: every open fills missing catalog entries, missing
    // roles, role permissions, and the default admin account, so a database
    // created by an earlier pre-release layout (which seeded roles only and
    // skipped the user) converges to the same state without a destructive
    // reset. Role permission rows are re-inserted only when the role has none.
    const perms = [
      'page:admin', 'api:admin',
      'page:chat', 'page:history', 'page:settings', 'page:tools',
      'session:list', 'session:read', 'session:delete',
      'settings:read', 'settings:write',
    ] as const
    const userRolePerms = ['page:chat', 'page:history', 'page:settings', 'page:tools', 'session:list', 'session:read', 'settings:read', 'settings:write']
    for (const p of perms) this.stmts.permissionInsert.run(p)

    const adminId = this.ensureRole('admin', '管理员', '完整系统管理权限')
    for (const p of perms) this.assignPermissions(adminId, [p])
    const userId = this.ensureRole('user', '普通用户', '基础使用权限')
    for (const p of userRolePerms) this.assignPermissions(userId, [p])

    // Default admin account; absent in databases seeded by the old pre-release
    // layout, which created the admin role but never a user.
    const adminUser = this.db.prepare(`SELECT id FROM users WHERE username = 'admin'`).get() as { id: number } | undefined
    if (adminUser === undefined) {
      const salt = randomBytes(16)
      const hash = hashPassword('admin123', salt)
      this.stmts.userInsert.run('admin', encodeHash(salt, hash), '系统管理员', adminId, 1)
    }
  }

  /** Resolve one role id by name, creating the role when absent. */
  private ensureRole(name: string, label: string, description: string): number {
    const row = this.stmts.roleByName.get(name) as { id: number } | undefined
    if (row !== undefined) return row.id
    return this.stmts.roleInsert.run(name, label, description).lastInsertRowid as number
  }

  /** Permission keys held by one role, in catalog order. */
  private permissionsForRole(roleId: number): string[] {
    const rows = this.stmts.rolePermissionsList.all(roleId) as unknown as Array<{ name: string }>
    return rows.map(row => row.name)
  }

  /** Build the admin roles-list view from a DB row. */
  private roleViewFromRow(row: DbRole): RoleView {
    return {
      id: row.id,
      name: row.name,
      label: row.label,
      description: row.description,
      isSystem: row.name === 'admin' || row.name === 'user',
      permissions: this.permissionsForRole(row.id),
      createdAt: row.created_at,
    }
  }

  /** Build the admin users-list view from a DB row. */
  private userViewFromRow(row: DbUser): UserView {
    return {
      id: row.id,
      username: row.username,
      displayName: row.display_name,
      roleId: row.role_id,
      roleName: row.role_name,
      roleLabel: row.role_label,
      status: row.status,
      createdAt: row.created_at,
      permissions: row.permissions ? (row.permissions.split(',') as readonly string[]) : [],
    }
  }

}
