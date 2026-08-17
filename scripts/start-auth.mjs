/**
 * 认证代理服务器启动入口。
 * 使用方式: node scripts/start-auth.mjs
 * 环境变量:
 *   AUTH_PORT        - 监听端口 (默认 3080)
 *   AUTH_HOST        - 监听地址 (默认 0.0.0.0)
 *   BACKEND_URL      - 后端 harness 地址 (默认 http://127.0.0.1:3099)
 *   AUTH_DB_PATH     - SQLite 数据库路径 (默认 ~/.dsh/auth.db)
 *   ADMIN_USERNAME   - 默认管理员用户名 (默认 admin)
 *   ADMIN_PASSWORD   - 默认管理员密码 (默认 admin123)
 */

import { startAuthWebServer } from '../packages/auth/auth-web/src/index.ts'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { mkdirSync } from 'node:fs'

const dshHome = join(homedir(), '.dsh')
mkdirSync(dshHome, { recursive: true })

const config = {
  port: parseInt(process.env.AUTH_PORT || '3080', 10),
  host: process.env.AUTH_HOST || '0.0.0.0',
  backendUrl: process.env.BACKEND_URL || 'http://127.0.0.1:3099',
  auth: {
    dbPath: process.env.AUTH_DB_PATH || join(dshHome, 'auth.db'),
    sessionExpireHours: parseInt(process.env.SESSION_EXPIRE_HOURS || '24', 10),
    defaultAdminUsername: process.env.ADMIN_USERNAME || 'admin',
    defaultAdminPassword: process.env.ADMIN_PASSWORD || 'admin123',
  },
}

console.log('[auth] 配置:', {
  port: config.port,
  backendUrl: config.backendUrl,
  dbPath: config.auth.dbPath,
  adminUser: config.auth.defaultAdminUsername,
})

const { close } = startAuthWebServer(config)

process.on('SIGINT', () => { close(); process.exit(0) })
process.on('SIGTERM', () => { close(); process.exit(0) })
