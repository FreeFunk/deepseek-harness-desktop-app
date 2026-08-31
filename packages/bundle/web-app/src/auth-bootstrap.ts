/**
 * SPA bootstrap: inject `window.__DSH_AUTH_USER__` into the served SPA
 * index so the client side can render user-aware UI without an extra
 * round-trip. The injection happens via the webserver's `tapIndex` so the
 * script tag is added in the page head alongside other upstream injections.
 */

import type { AuthUser } from './auth-user.ts'

/** Build the `<script>` block to inject for the given (or null) user. */
export function authBootstrapScript(user: AuthUser | null): string {
  const payload = user === null
    ? 'null'
    : JSON.stringify({
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        roleId: user.roleId,
        roleName: user.roleName,
        permissions: [...user.permissions],
      })
  return `<script>(function(){window.__DSH_AUTH_USER__=${payload};`
    + 'window.dispatchEvent(new CustomEvent("dsh-auth",{detail:window.__DSH_AUTH_USER__}))})();</script>'
}