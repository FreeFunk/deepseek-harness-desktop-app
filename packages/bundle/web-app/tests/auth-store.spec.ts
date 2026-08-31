/**
 * Smoke test for the AuthStore. Verifies schema initialization, password
 * verification, and user/role CRUD.
 */

import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AuthStore } from '../src/auth-store.ts'

describe('AuthStore', () => {
  function freshStore(): { store: AuthStore; path: string } {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-auth-test-'))
    const path = join(dir, 'auth.db')
    return { store: new AuthStore({ dbPath: path, sessionExpireHours: 1 }), path }
  }

  it('seeds default roles and permissions', () => {
    const { store } = freshStore()
    try {
      const roles = store.listRoles()
      expect(roles.map(r => r.name)).toContain('admin')
      expect(roles.map(r => r.name)).toContain('user')
    } finally {
      store.dispose()
    }
  })

  it('seeds the default admin/admin account', () => {
    const { store } = freshStore()
    try {
      const user = store.verifyCredentials('admin', 'admin')
      expect(user).not.toBeNull()
      expect(user?.username).toBe('admin')
      expect(user?.roleName).toBe('admin')
    } finally {
      store.dispose()
    }
  })

  it('rejects bad passwords', () => {
    const { store } = freshStore()
    try {
      const user = store.verifyCredentials('admin', 'wrong')
      expect(user).toBeNull()
    } finally {
      store.dispose()
    }
  })

  it('creates, lists, and deletes users', () => {
    const { store } = freshStore()
    try {
      const roles = store.listRoles()
      const userRole = roles.find(r => r.name === 'user')
      expect(userRole).toBeDefined()
      const created = store.createUser({
        username: 'alice',
        password: 'secret123',
        roleId: userRole!.id,
      })
      expect(created.username).toBe('alice')
      const users = store.listUsers()
      expect(users.some(u => u.username === 'alice')).toBe(true)
      store.deleteUser(created.id)
      const after = store.listUsers()
      expect(after.some(u => u.username === 'alice')).toBe(false)
    } finally {
      store.dispose()
    }
  })
})