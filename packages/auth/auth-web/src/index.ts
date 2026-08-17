/**
 * 认证 Web 服务器：独立的 Express 服务器，提供登录页面、API 路由和反向代理。
 * 运行在 harness 前端，拦截所有请求进行会话验证，未登录用户重定向到登录页。
 * @module @deepseek-ai/dsh-auth-web
 */

import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { AuthService } from '@deepseek-ai/dsh-auth'
import type { AuthConfig, MenuItem, User } from '@deepseek-ai/dsh-auth'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

/** 不需要认证的路径 */
const PUBLIC_PATHS = new Set([
  '/api/auth/login',
  '/api/auth/login.html',
  '/login',
  '/login.html',
  '/favicon.ico',
])

/** 静态资源路径前缀 */
const STATIC_PREFIXES = ['/assets/', '/@', '/node_modules/', '/src/']

export interface AuthWebConfig {
  /** 监听端口 */
  port: number
  /** 监听地址 */
  host: string
  /** 后端 harness 地址 */
  backendUrl: string
  /** 认证配置 */
  auth: AuthConfig
}

/** 安全用户信息 */
type SafeUser = Omit<User, 'passwordHash'>

/** 登录页面 HTML */
const LOGIN_PAGE = <!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - DeepSeek Harness</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0d1117;
  color: #c9d1d9;
  display: flex; justify-content: center; align-items: center;
  min-height: 100vh;
}
.login-box {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 12px;
  padding: 40px;
  width: 380px;
  max-width: 90vw;
}
.login-box h1 {
  font-size: 24px;
  margin-bottom: 8px;
  color: #f0f6fc;
  text-align: center;
}
.login-box p {
  color: #8b949e;
  font-size: 14px;
  margin-bottom: 24px;
  text-align: center;
}
.form-group { margin-bottom: 16px; }
.form-group label {
  display: block; font-size: 13px;
  color: #c9d1d9; margin-bottom: 6px;
}
.form-group input {
  width: 100%; padding: 10px 12px;
  background: #0d1117; border: 1px solid #30363d;
  border-radius: 6px; color: #c9d1d9;
  font-size: 14px; outline: none;
  transition: border-color 0.2s;
}
.form-group input:focus { border-color: #58a6ff; }
.btn {
  width: 100%; padding: 10px;
  background: #238636; color: #fff;
  border: none; border-radius: 6px;
  font-size: 14px; cursor: pointer;
  transition: background 0.2s;
  margin-top: 8px;
}
.btn:hover { background: #2ea043; }
.error-msg {
  color: #f85149; font-size: 13px;
  text-align: center; margin-top: 12px;
  display: none;
}
.error-msg.show { display: block; }
</style>
</head>
<body>
<div class="login-box">
  <h1>DeepSeek Harness</h1>
  <p>请输入用户名和密码登录</p>
  <form id="loginForm">
    <div class="form-group">
      <label for="username">用户名</label>
      <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    </div>
    <div class="form-group">
      <label for="password">密码</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">登 录</button>
  </form>
  <div id="error" class="error-msg"></div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault()
  const errorEl = document.getElementById('error')
  errorEl.classList.remove('show')
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      })
    })
    if (!res.ok) {
      const data = await res.json()
      errorEl.textContent = data.error || '登录失败'
      errorEl.classList.add('show')
      return
    }
    window.location.href = '/'
  } catch (err) {
    errorEl.textContent = '网络错误，请重试'
    errorEl.classList.add('show')
  }
})
</script>
</body>
</html>

/**
 * 启动认证 Web 服务器。
 * 在 harness 前端作为反向代理运行，拦截所有请求进行会话验证。
 */
export function startAuthWebServer(config: AuthWebConfig): { close: () => void } {
  const auth = new AuthService(null as any, config.auth)

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || '/', http://)
    const pathname = url.pathname

    // 1. 登录页面
    if (pathname === '/login' || pathname === '/login.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(LOGIN_PAGE)
      return
    }

    // 2. API 路由
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      await handleLogin(req, res, auth)
      return
    }
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      handleLogout(req, res, auth)
      return
    }
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      handleMe(req, res, auth)
      return
    }
    if (pathname === '/api/auth/menus' && req.method === 'GET') {
      handleMenus(req, res, auth)
      return
    }

    // 3. 会话验证
    const user = auth.getUserFromCookie(req.headers.cookie)
    if (!user) {
      // API 请求返回 401
      if (pathname.startsWith('/api/')) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({ error: '未登录，请先登录' }))
        return
      }
      // 页面请求重定向到登录页
      res.writeHead(302, { Location: '/login' })
      res.end()
      return
    }

    // 4. 代理到后端
    proxyToBackend(req, res, config.backendUrl)
  })

  server.listen(config.port, config.host, () => {
    console.log([auth] 认证服务已启动: http://:)
  })

  return {
    close: () => {
      auth.dispose()
      server.close()
    },
  }
}

/** 处理登录请求 */
async function handleLogin(req: IncomingMessage, res: ServerResponse, auth: AuthService): Promise<void> {
  const body = await readBody(req)
  try {
    const { username, password } = JSON.parse(body)
    if (!username || !password) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ error: '用户名和密码不能为空' }))
      return
    }
    const result = auth.login({ username, password })
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Set-Cookie': dsh_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=,
    })
    res.end(JSON.stringify(result))
  } catch (err: any) {
    res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ error: err.message || '登录失败' }))
  }
}

/** 处理登出请求 */
function handleLogout(req: IncomingMessage, res: ServerResponse, auth: AuthService): void {
  const token = extractToken(req.headers.cookie)
  if (token) auth.logout(token)
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Set-Cookie': 'dsh_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
  })
  res.end(JSON.stringify({ ok: true }))
}

/** 处理获取当前用户请求 */
function handleMe(req: IncomingMessage, res: ServerResponse, auth: AuthService): void {
  const user = auth.getUserFromCookie(req.headers.cookie)
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ error: '未登录' }))
    return
  }
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(user))
}

/** 处理获取菜单请求 */
function handleMenus(req: IncomingMessage, res: ServerResponse, auth: AuthService): void {
  const user = auth.getUserFromCookie(req.headers.cookie)
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ error: '未登录' }))
    return
  }
  const menus = auth.getMenus(user.id)
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(menus))
}

/** 代理请求到后端 harness */
function proxyToBackend(req: IncomingMessage, res: ServerResponse, backendUrl: string): void {
  const target = new URL(req.url || '/', backendUrl)
  const options = {
    method: req.method,
    headers: { ...req.headers },
    hostname: target.hostname,
    port: target.port,
    path: target.pathname + target.search,
  }
  // 删除 hop-by-hop 头
  delete (options.headers as any)['host']
  delete (options.headers as any)['connection']

  const proxyReq = (target.protocol === 'https:' ? require('node:https').request : require('node:http').request)(
    options,
    (proxyRes: IncomingMessage) => {
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers)
      proxyRes.pipe(res)
    }
  )
  proxyReq.on('error', () => {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('后端服务不可用')
  })
  req.pipe(proxyReq)
}

/** 读取请求 body */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', chunk => { data += chunk })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

/** 从 cookie 中提取 token */
function extractToken(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined
  const match = cookieHeader.match(/dsh_token=([^;]+)/)
  return match ? match[1] : undefined
}
