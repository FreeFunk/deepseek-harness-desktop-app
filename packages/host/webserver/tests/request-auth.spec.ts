/**
 * The request-auth contract: the symbol guards attach sessions under and the
 * fence reads them back through. A guard that ran and found a session leaves
 * the user on the request; no session leaves the slot absent.
 */
import { describe, expect, it } from 'vitest'
import { Readable } from 'node:stream'
import type { IncomingMessage } from 'node:http'
import { AUTH_USER, authUserOf, type AuthUserFace } from '../src/request-auth.ts'

function fakeRequest(): IncomingMessage {
  return Readable.from([]) as unknown as IncomingMessage
}

describe('request auth contract', () => {
  it('returns undefined until a guard attaches a session', () => {
    expect(authUserOf(fakeRequest())).toBeUndefined()
  })

  it('returns the session user a guard attached under the symbol', () => {
    const req = fakeRequest()
    const user = { permissions: ['page:settings'] } satisfies AuthUserFace
    ;(req as unknown as Record<PropertyKey, unknown>)[AUTH_USER] = user
    expect(authUserOf(req)).toBe(user)
  })
})
