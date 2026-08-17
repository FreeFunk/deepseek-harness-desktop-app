/**
 * 密码哈希与验证工具。
 * 使用 Node.js 内置 crypto 模块的 scrypt 算法。
 * @module @deepseek-ai/dsh-auth
 */

import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

/** 盐值长度（字节） */
const SALT_LENGTH = 16
/** scrypt 密钥长度（字节） */
const KEY_LENGTH = 64
/** 哈希格式分隔符 */
const SEPARATOR = ':'

/**
 * 对密码进行哈希处理，返回 salt:hash 格式的字符串。
 */
export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_LENGTH).toString('hex')
  const hash = scryptSync(password, salt, KEY_LENGTH).toString('hex')
  return ${salt}
}

/**
 * 验证密码是否匹配哈希值。
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, hash] = storedHash.split(SEPARATOR)
  if (!salt || !hash) return false
  const computed = scryptSync(password, salt, KEY_LENGTH)
  const expected = Buffer.from(hash, 'hex')
  if (computed.length !== expected.length) return false
  return timingSafeEqual(computed, expected)
}
