/**
 * Auth plugin entry point. Function plugin with named exports
 * (name / inject / Config / apply). Registers /login, /logout,
 * /auth/me, /auth/change-password, /auth/admin/*, and /admin routes,
 * and attaches AUTH_USER to authenticated requests.
 *
 * Session storage: SQLite at ~/.dsh/auth.db by default.
 *
 * Permissions: page:admin and api:admin gate the admin routes.
 * @module @deepseek-ai/dsh-web-app/auth
 */

// Re-export all public types and utilities
export {
  AUTH_USER,
  AUTH_USER_KEY,
  type AuthUser,
  type SessionToken,
  type RoleId,
  type UserId,
  type Permission,
} from './auth-user.ts'
export { AuthStore, type AuthStoreOptions } from './auth-store.ts'
export { AUTH_SESSION_COOKIE, type AuthPluginOptions, authBootstrapScript } from './auth-api.ts'

// Re-export function plugin exports so this module is the Cordis entry point
export {
  name,
  inject,
  apply,
  type Config,
} from './auth-api.ts'