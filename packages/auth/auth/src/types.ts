/**
 * 认证模块的纯类型定义：用户、角色、菜单、会话、配置。
 * @module @deepseek-ai/dsh-auth
 */

/** 用户角色 */
export type UserRole = 'admin' | 'user'

/** 用户记录 */
export interface User {
  id: number
  username: string
  passwordHash: string
  role: UserRole
  createdAt: string
}

/** 会话记录 */
export interface Session {
  token: string
  userId: number
  createdAt: string
  expiresAt: string
}

/** 菜单项 */
export interface MenuItem {
  key: string
  label: string
  /** 父菜单 key，顶级菜单为 null */
  parent: string | null
  /** 允许访问的角色列表 */
  roles: UserRole[]
  /** 排序权重 */
  order: number
}

/** 登录请求 */
export interface LoginRequest {
  username: string
  password: string
}

/** 登录响应 */
export interface LoginResponse {
  token: string
  user: Omit<User, 'passwordHash'>
}

/** 认证配置 */
export interface AuthConfig {
  /** SQLite 数据库文件路径 */
  dbPath: string
  /** 会话过期时间（小时） */
  sessionExpireHours: number
  /** 默认管理员用户名 */
  defaultAdminUsername: string
  /** 默认管理员密码 */
  defaultAdminPassword: string
}

/** 默认配置 */
export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  dbPath: ':memory:',
  sessionExpireHours: 24,
  defaultAdminUsername: 'admin',
  defaultAdminPassword: 'admin123',
}
