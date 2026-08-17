/**
 * SQLite 数据库操作：用户表、会话表、菜单表的 CRUD。
 * 使用 node:sqlite 同步 API，数据库文件路径由 AuthConfig 指定。
 * @module @deepseek-ai/dsh-auth
 */

import { DatabaseSync } from 'node:sqlite'
import { randomUUID } from 'node:crypto'
import type { User, Session, MenuItem, UserRole, AuthConfig } from './types.ts'

/** 数据库 schema 版本 */
const SCHEMA_VERSION = 1

/** 建表 SQL */
const CREATE_TABLES = /* sql */ 
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS menus (
  key TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  parent TEXT,
  roles TEXT NOT NULL DEFAULT '["user","admin"]',
  \"order\" INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);


/** 默认菜单数据 */
const DEFAULT_MENUS: MenuItem[] = [
  { key: 'chat', label: '对话', parent: null, roles: ['user', 'admin'], order: 1 },
  { key: 'sessions', label: '会话历史', parent: null, roles: ['user', 'admin'], order: 2 },
  { key: 'settings', label: '设置', parent: null, roles: ['admin'], order: 3 },
  { key: 'user-management', label: '用户管理', parent: null, roles: ['admin'], order: 4 },
  { key: 'tools', label: '工具', parent: null, roles: ['user', 'admin'], order: 5 },
]

export class AuthStore {
  private db: DatabaseSync

  constructor(config: AuthConfig) {
    this.db = new DatabaseSync(config.dbPath)
    this.db.exec('PRAGMA journal_mode=WAL')
    this.db.exec('PRAGMA foreign_keys=ON')
    this.initSchema()
    this.seedDefaults(config)
  }

  /** 初始化数据库表结构 */
  private initSchema(): void {
    this.db.exec(CREATE_TABLES)
    const row = this.db.prepare('SELECT version FROM schema_version').get() as { version: number } | undefined
    if (!row) {
      this.db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(SCHEMA_VERSION)
    }
  }

  /** 写入默认数据 */
  private seedDefaults(config: AuthConfig): void {
    const existing = this.db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number }
    if (existing.count === 0) {
      const { hashPassword } = require('./auth-utils.ts')
      const hash = hashPassword(config.defaultAdminPassword)
      this.db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
        .run(config.defaultAdminUsername, hash, 'admin')

      const insertMenu = this.db.prepare(
        'INSERT OR IGNORE INTO menus (key, label, parent, roles, "order") VALUES (?, ?, ?, ?, ?)'
      )
      for (const menu of DEFAULT_MENUS) {
        insertMenu.run(menu.key, menu.label, menu.parent, JSON.stringify(menu.roles), menu.order)
      }
    }
  }

  /** 根据用户名查找用户 */
  findUserByUsername(username: string): User | undefined {
    return this.db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined
  }

  /** 根据 ID 查找用户 */
  findUserById(id: number): User | undefined {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as User | undefined
  }

  /** 创建用户 */
  createUser(username: string, passwordHash: string, role: UserRole = 'user'): User {
    const result = this.db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, passwordHash, role)
    return this.findUserById(result.lastInsertRowid as number)!
  }

  /** 列出所有用户 */
  listUsers(): User[] {
    return this.db.prepare('SELECT * FROM users ORDER BY id').all() as User[]
  }

  /** 创建会话 */
  createSession(userId: number, expireHours: number): Session {
    const token = randomUUID()
    const expiresAt = new Date(Date.now() + expireHours * 3600_000).toISOString()
    this.db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
      .run(token, userId, expiresAt)
    return this.db.prepare('SELECT * FROM sessions WHERE token = ?').get(token) as Session
  }

  /** 验证会话 token */
  validateSession(token: string): Session | undefined {
    const session = this.db.prepare('SELECT * FROM sessions WHERE token = ?').get(token) as Session | undefined
    if (!session) return undefined
    if (new Date(session.expiresAt) < new Date()) {
      this.db.prepare('DELETE FROM sessions WHERE token = ?').run(token)
      return undefined
    }
    return session
  }

  /** 删除会话 */
  deleteSession(token: string): void {
    this.db.prepare('DELETE FROM sessions WHERE token = ?').run(token)
  }

  /** 清理过期会话 */
  cleanExpiredSessions(): void {
    this.db.prepare('DELETE FROM sessions WHERE expires_at < datetime(\"now\")').run()
  }

  /** 获取用户可见菜单 */
  getUserMenus(userId: number): MenuItem[] {
    const user = this.findUserById(userId)
    if (!user) return []
    const allMenus = this.db.prepare('SELECT * FROM menus ORDER BY \"order\"').all() as Array<Record<string, unknown>>
    return allMenus
      .filter(row => {
        const roles = JSON.parse(row.roles as string) as UserRole[]
        return roles.includes(user.role)
      })
      .map(row => ({
        key: row.key as string,
        label: row.label as string,
        parent: row.parent as string | null,
        roles: JSON.parse(row.roles as string),
        order: row.order as number,
      }))
  }

  /** 关闭数据库 */
  close(): void {
    this.db.close()
  }
}
