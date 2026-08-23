/**
 * Settings-availability signal: loopback is always enabled; a remote page
 * follows the authenticated session the web-app bootstrap publishes through
 * the page global and the `dsh-auth` window event.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  AUTH_SESSION_EVENT, createSettingsAvailability, SETTINGS_PERMISSION,
} from '../src/client/settings-availability.ts'

/** Fake host object capturing listeners and exposing a mutable session. */
function fakeRoot(initialSession: unknown) {
  const listeners = new Map<string, Set<() => void>>()
  const root = {
    __DSH_AUTH__: initialSession,
    addEventListener(type: string, listener: () => void) {
      let set = listeners.get(type)
      if (set === undefined) {
        set = new Set()
        listeners.set(type, set)
      }
      set.add(listener)
    },
    dispatch(type: string) {
      for (const listener of [...(listeners.get(type) ?? [])]) listener()
    },
    setSession(session: unknown) {
      root.__DSH_AUTH__ = session
      root.dispatch(AUTH_SESSION_EVENT)
    },
  }
  return root
}

describe('createSettingsAvailability', () => {
  it('is always available on loopback', () => {
    const signal = createSettingsAvailability(true, fakeRoot(undefined))
    expect(signal.getSnapshot()).toBe(true)
  })

  it('is unavailable for a remote page with no session', () => {
    const signal = createSettingsAvailability(false, fakeRoot(null))
    expect(signal.getSnapshot()).toBe(false)
  })

  it('reflects a session already carrying the settings permission', () => {
    const signal = createSettingsAvailability(false, fakeRoot({ permissions: ['page:chat', SETTINGS_PERMISSION] }))
    expect(signal.getSnapshot()).toBe(true)
  })

  it('ignores a session without the settings permission', () => {
    const signal = createSettingsAvailability(false, fakeRoot({ permissions: ['page:chat'] }))
    expect(signal.getSnapshot()).toBe(false)
  })

  it('enables settings when the session event arrives with the permission', () => {
    const root = fakeRoot(null)
    const signal = createSettingsAvailability(false, root)
    expect(signal.getSnapshot()).toBe(false)
    root.setSession({ permissions: [SETTINGS_PERMISSION] })
    expect(signal.getSnapshot()).toBe(true)
  })

  it('disables settings when the session event arrives without the permission', () => {
    const root = fakeRoot({ permissions: [SETTINGS_PERMISSION] })
    const signal = createSettingsAvailability(false, root)
    expect(signal.getSnapshot()).toBe(true)
    root.setSession({ permissions: ['page:chat'] })
    expect(signal.getSnapshot()).toBe(false)
  })

  it('does not re-notify a change to the current value', () => {
    const root = fakeRoot(null)
    const signal = createSettingsAvailability(false, root)
    const notify = vi.fn()
    signal.subscribe(notify)
    root.setSession({ permissions: [] })
    expect(notify).not.toHaveBeenCalled()
  })

  it('notifies subscribers on change and stops on dispose', () => {
    const root = fakeRoot(null)
    const signal = createSettingsAvailability(false, root)
    const seen: boolean[] = []
    const dispose = signal.subscribe(() => { seen.push(signal.getSnapshot()) })
    root.setSession({ permissions: [SETTINGS_PERMISSION] })
    expect(seen).toEqual([true])
    dispose()
    root.setSession({ permissions: [] })
    expect(seen).toEqual([true])
  })

  it('isolates one throwing listener from the other subscribers', () => {
    const root = fakeRoot(null)
    const signal = createSettingsAvailability(false, root)
    const boom = vi.fn(() => { throw new Error('listener failed') })
    const fine = vi.fn()
    signal.subscribe(boom)
    signal.subscribe(fine)
    root.setSession({ permissions: [SETTINGS_PERMISSION] })
    expect(fine).toHaveBeenCalledTimes(1)
  })

  it('stays unavailable when no event source exists', () => {
    const signal = createSettingsAvailability(false, {})
    expect(signal.getSnapshot()).toBe(false)
  })
})
