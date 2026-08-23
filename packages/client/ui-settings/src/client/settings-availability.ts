/**
 * Whether the settings/configuration plane may be used from this page. A
 * loopback page (the desktop) always can; a remote page can once its
 * authenticated session carries the settings-page permission. The signal is
 * reactive so an auth session that resolves after plugin startup still enables
 * settings: the web-app auth bootstrap publishes the session through the page
 * global `__DSH_AUTH__` and a `dsh-auth` window event after `/api/auth/me`
 * resolves, and this signal subscribes to both.
 */

/** One listener observed by a signal; subscribe returns the disposer. */
export interface SettingsAvailability {
  /** Whether settings are usable right now. */
  getSnapshot(): boolean
  /**
   * Observe availability changes.
   * @param listener - invoked after each change.
   * @returns the disposer removing this listener.
   */
  subscribe(listener: () => void): () => void
}

/** Page global the web-app auth bootstrap fills with the signed-in session. */
interface AuthSessionGlobal {
  __DSH_AUTH__?: { permissions?: readonly string[] } | null
}

/** Window event the web-app auth bootstrap fires after publishing the session. */
export const AUTH_SESSION_EVENT = 'dsh-auth'

/** The permission the configuration plane is gated on; the server enforces the same key. */
export const SETTINGS_PERMISSION = 'page:settings'

/**
 * Build the settings availability signal for one connection state.
 * @param isLoopback - whether the page authority is loopback (the desktop).
 * @param root - host object override for tests; defaults to `globalThis`.
 * @returns the signal, `true` forever for loopback, otherwise reflecting the session.
 */
export function createSettingsAvailability(
  isLoopback: boolean,
  root: unknown = globalThis,
): SettingsAvailability {
  let available = isLoopback
  const listeners = new Set<() => void>()
  const setAvailable = (next: boolean): void => {
    if (next === available) return
    available = next
    for (const listener of [...listeners]) {
      try {
        listener()
      } catch (error) {
        console.error('[ui-settings] settings-availability listener threw:', error)
      }
    }
  }
  const host = root as AuthSessionGlobal & {
    addEventListener?: (type: string, listener: () => void) => void
  }
  if (!isLoopback && host.addEventListener !== undefined) {
    const read = (): void => {
      setAvailable(host.__DSH_AUTH__?.permissions?.includes(SETTINGS_PERMISSION) === true)
    }
    host.addEventListener(AUTH_SESSION_EVENT, read)
    // The session may already have resolved before this signal was created.
    read()
  }
  return {
    getSnapshot: () => available,
    subscribe(listener) {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
  }
}
