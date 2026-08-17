/**
 * 认证服务：用户名密码登录、会话管理、菜单权限。
 * 作为 Cordis Service 注册到 ctx.auth，通过 SQLite 持久化用户和会话数据。
 * @module @deepseek-ai/dsh-auth
 */

import { Context, Service } from '@deepseek-ai/cordis'
import { AuthStore } from './store.ts'
import { verifyPassword, hashPassword } from './auth-utils.ts'
import type { AuthConfig, LoginRequest, LoginResponse, MenuItem, User, UserRole } from './types.ts'
import { DEFAULT_AUTH_CONFIG } from './types.ts'

export type { AuthConfig, LoginRequest, LoginResponse, MenuItem, User, UserRole } from './types.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    auth: AuthService
  }
}

/** 认证错误码 */
export type AuthErrorCode =
  | 'invalid-credentials'
  | 'user-not-found'
  | 'session-expired'
  | 'session-not-found'
  | 'username-taken'
  | 'permission-denied'

/** 认证错误 */
export class AuthError extends Error {
  readonly code: AuthErrorCode
  constructor(code: AuthErrorCode, message: string) {
    super(message)
    this.name = 'AuthError'
    this.code = code
  }
}

/** 插件名称 */
export const name = 'auth'

/**
 * 认证服务：管理用户认证、会话和菜单权限。
 * 作为 Cordis Service 注册，其他插件可通过 ctx.auth 调用。
 */
export class AuthService extends Service {
  private store: AuthStore
  private config: AuthConfig

  constructor(ctx: Context, config: Partial<AuthConfig> = {}) {
    super(ctx, 'auth')
    this.config = { ...DEFAULT_AUTH_CONFIG, ...config }
    this.store = new AuthStore(this.config)
  }

  /**
   * 用户登录：验证用户名密码，创建会话 token。
   * @returns 登录响应（token + 用户信息）
   * @throws AuthError 用户名或密码错误
   */
  login(req: LoginRequest): LoginResponse {
    const user = this.store.findUserByUsername(req.username)
    if (!user) {
      throw new AuthError('invalid-credentials', '用户名或密码错误')
    }
    if (!verifyPassword(req.password, user.passwordHash)) {
      throw new AuthError('invalid-credentials', '用户名或密码错误')
    }
    const session = this.store.createSession(user.id, this.config.sessionExpireHours)
    const { passwordHash: _, ...safeUser } = user
    return { token: session.token, user: safeUser }
  }

  /**
   * 用户登出：删除会话 token。
   */
  logout(token: string): void {
    this.store.deleteSession(token)
  }

  /**
   * 验证会话 token 并返回用户信息。
   * @returns 用户信息（不含密码哈希）
   * @throws AuthError 会话无效或已过期
   */
  validateSession(token: string): Omit<User, 'passwordHash'> {
    const session = this.store.validateSession(token)
    if (!session) {
      throw new AuthError('session-expired', '会话已过期，请重新登录')
    }
    const user = this.store.findUserById(session.userId)
    if (!user) {
      throw new AuthError('user-not-found', '用户不存在')
    }
    const { passwordHash: _, ...safeUser } = user
    return safeUser
  }

  /**
   * 获取用户可见的菜单列表。
   */
  getMenus(userId: number): MenuItem[] {
    return this.store.getUserMenus(userId)
  }

  /**
   * 创建新用户（需要管理员权限）。
   */
  createUser(username: string, password: string, role: UserRole = 'user'): User {
    const existing = this.store.findUserByUsername(username)
    if (existing) {
      throw new AuthError('username-taken', 用户名 "" 已被占用)
    }
    const hash = hashPassword(password)
    return this.store.createUser(username, hash, role)
  }

  /**
   * 列出所有用户。
   */
  listUsers(): User[] {
    return this.store.listUsers()
  }

  /**
   * 获取当前用户（从 cookie token 解析）。
   */
  getUserFromCookie(cookieHeader: string | undefined): Omit<User, 'passwordHash'> | null {
    if (!cookieHeader) return null
    const match = cookieHeader.match(/dsh_token=([^;]+)/)
    if (!match) return null
    try {
      return this.validateSession(match[1])
    } catch {
      return null
    }
  }

  /** 清理过期会话 */
  dispose(): void {
    this.store.cleanExpiredSessions()
    this.store.close()
  }
}

export default AuthService
