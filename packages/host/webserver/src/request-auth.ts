/**
 * Cross-package contract for an authenticated session attached to an HTTP
 * request. A composing auth guard stores the signed-in user on the request
 * under this symbol; downstream fences (the connection configuration-plane
 * gate) read it to enforce by role instead of by reachability. The symbol
 * lives in the webserver package both plugins already share, so neither side
 * imports the other's plugin body.
 */

import type { IncomingMessage } from 'node:http'

/** Symbol carrying the authenticated session user a guard attached to the request. */
export const AUTH_USER = Symbol('dsh.authUser')

/**
 * Internal header carrying the guard's presence marker into Fetch-derived
 * requests. A resource handler receives a Fetch Request built from the Node
 * request headers, so the symbol on the IncomingMessage does not survive that
 * conversion; the guard sets this header on every request instead.
 */
export const AUTH_USER_HEADER = 'x-dsh-auth-user'

/** The session-user face a fence reads permissions from (a structural subset of an auth plugin's user). */
export interface AuthUserFace {
  /** Role-scoped permission keys the request's session holds. */
  readonly permissions: readonly string[]
}

/**
 * Read the authenticated session user a guard attached to this request.
 * @param req - the gated request.
 * @returns the attached user, or undefined when no guard ran or no session exists.
 */
export function authUserOf(req: IncomingMessage): AuthUserFace | undefined {
  return (req as unknown as Record<PropertyKey, unknown>)[AUTH_USER] as AuthUserFace | undefined
}
