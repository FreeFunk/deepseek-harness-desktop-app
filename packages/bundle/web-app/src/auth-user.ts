/**
 * AUTH_USER symbol: a cross-boundary authentication marker attached to the
 * raw IncomingMessage by the transport guard after session verification.
 * Callers downstream read it via the canonical string key on IncomingMessage.
 */

/** Session token: opaque branded string. */
export type SessionToken = string & { readonly __brand: 'SessionToken' }

/** Role id: opaque branded number. */
export type RoleId = number & { readonly __brand: 'RoleId' }

/** User id: opaque branded number. */
export type UserId = number & { readonly __brand: 'UserId' }

/** One permission string, stored as the canonical identifier. */
export type Permission = string

/**
 * Authenticated user attached to requests that passed the session guard.
 * The permissions array is the authoritative capability set; callers must
 * not interpret arbitrary strings as capabilities without an explicit check.
 */
export interface AuthUser {
  readonly id: UserId
  readonly username: string
  /** Hashed display name; may be absent when the operator has not set one. */
  readonly displayName: string | null
  readonly roleId: RoleId
  /** The current role name, resolved at attach time. */
  readonly roleName: string
  readonly permissions: readonly Permission[]
  readonly status: number
}

/**
 * Stable symbol marking the authenticated user on IncomingMessage.
 * Plugins read `req[AUTH_USER]` after the transport guard has run.
 *
 * For cross-package access, use the string key `'@deepseek-ai/dsh-web-app/auth-user'`
 * — Symbol keys are not visible to code outside the package that defines them.
 */
export const AUTH_USER = Symbol.for('@deepseek-ai/dsh-web-app/auth-user')

/** String key for cross-package access to the AUTH_USER marker. */
export const AUTH_USER_KEY = '@deepseek-ai/dsh-web-app/auth-user' as const