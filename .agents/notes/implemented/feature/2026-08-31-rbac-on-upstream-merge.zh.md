# Agent Note: RBAC 与上游合并（方案 A）

状态：已实现

[English](./2026-08-31-rbac-on-upstream-merge.md)

## 背景

本地 fork (`FreeFunk/deepseek-harness-desktop-app`) 落后 upstream
(`deepseek-ai/deepseek-harness`) 1313 个 commit。直接 rebase 会引发大量
结构性冲突：上游已经做了 4 个破坏性重构，删除了 `apiProxy`/`WebSocketDownlinks`/
`PRIVILEGED_METHODS` 等本地扩展依赖的 API。

## 方案 A 的关键判断**：BrowserAuth + RBAC 分工

上游已经原生实现了会话/cookie/401 拒绝（`packages/client/connection/src/browser-auth.ts`），
但**没有**用户/角色/权限管理 UI。两者是不同维度：
- BrowserAuth = "你是谁"的认证层
- 本地 RBAC = "你能做什么"的授权层

合并策略：保留本地 RBAC 数据层（users / roles / permissions / admin console），
删掉手写的 cookie/session 实现，让上游 BrowserAuth 接管。

## 已完成的工作

### 代码

| 文件 | 行数 | 内容 |
|---|---|---|
| `packages/bundle/web-app/src/auth-user.ts` | ~50 | `AUTH_USER` Symbol、`AUTH_USER_KEY` 字符串键、AuthUser 类型 |
| `packages/bundle/web-app/src/auth-store.ts` | ~450 | RBAC SQLite 数据层（Node 22 `node:sqlite`）|
| `packages/bundle/web-app/src/auth-api.ts` | ~660 | HTTP 路由 + 管理控制台 HTML |
| `packages/bundle/web-app/src/auth-bootstrap.ts` | ~25 | SPA `__DSH_AUTH_USER__` 注入 + `dsh-auth` 事件 |
| `packages/bundle/web-app/src/auth.ts` | ~30 | 函数插件入口（`name`/`inject`/`Config`/`apply`）|
| `packages/bundle/web-app/tests/auth-store.spec.ts` | ~70 | AuthStore CRUD smoke tests |
| `packages/bundle/web-app/tests/auth-api.spec.ts` | ~280 | 真实 HTTP server 集成测试 |
| `packages/bundle/web-app/src/auth.README.md` | ~140 | 模块文档 |
| `packages/bundle/web-app/package.json` | 改动 | 加 `./auth` 导出和 `lib/auth.js` |

### 关键设计决定

1. **路由前缀策略**：exact routes (`/login`/`/logout`/`/admin`) + prefix route (`/auth`)。
   `dispatch()` 对未知路径返回 `undefined`，让 webserver fallback 处理静态文件。
2. **HTTPS 检测**：`isSecure(req)` 用 `X-Forwarded-Proto` 或 `req.socket.encrypted`，
   不是 `webServer.host`（后者只是 bind 地址）。
3. **密码哈希**：PBKDF2-SHA512，16 字节 salt，100k iterations。
4. **会话 token**：32 字节随机 + base64url 编码。
5. **AUTH_USER 跨包访问**：因为 Symbol 不能跨包稳定可见，使用字符串键
   `'@deepseek-ai/dsh-web-app/auth-user'`。
6. **设计原则遵守**：
   - ESM only（Node 22+）
   - 函数插件 `name`/`inject`/`Config`/`apply` 形式
   - `ctx.effect()` 注册清理 disposer
   - 严格模式 + Branded types for `SessionToken`/`UserId`/`RoleId`

## 风险与决策点

1. **`AUTH_USER_KEY` 命名空间**：如果上游也用类似键名（unlikely），会冲突。
   可考虑 namespace 改 `@deepseek-ai/dsh-web-app/rbac-user`，但增加复杂度，
   当前选择简单命名。
2. **数据库迁移路径**：本地的 `~/.dsh/auth.db` 表结构是新的（`_meta` / `users` /
   `roles` / `permissions` / `role_permissions` / `sessions`）。
   旧 schema 没有迁移路径——上游版本是没 RBAC 的，所以首次部署即干净创建。
3. **上游 BrowserAuth 已经覆盖认证**：本次 commit 让上游 BrowserAuth 负责
   cookie/session，本地 AuthStore 只管 user/role/permission 数据。
   两者并存但分工清楚：未登录 → BrowserAuth 401；非 admin 调 admin API → 本地 403。

## 未完成的工作

### 1. UI 提交整合

需要你在**普通终端**运行：

```bash
cd D:\code\my-tool-code\deepseek-harness-desktop-app
git show rebase-upstream:packages/client/ui-layout/src/client/AppFrame.tsx
git show rebase-upstream:packages/client/ui-settings-general/src/client/SettingsRoot.tsx
git show rebase-upstream:packages/client/ui-settings/src/client/settings-availability.ts
```

把这三个文件的内容贴在下一个对话里，我手工把它们移植到当前 `merge-upstream-rbac-v2` 之上。

### 2. 验证构建

```bash
pnpm install
pnpm run typecheck --filter @deepseek-ai/dsh-web-app
pnpm --filter @deepseek-ai/dsh-web-app run build:lib:host
pnpm --filter @deepseek-ai/dsh-web-app test auth-store
pnpm --filter @deepseek-ai/dsh-web-app test auth-api
```

## 关联 agent note

- [2026-08-24-browser-token-authentication](../architecture/2026-08-24-browser-token-authentication.md) —
  上游 BrowserAuth：browser session cookie 交换和 401 拒绝。
  本次 auth plugin 建立在 BrowserAuth 的 cookie 机制之上（共享 `dsh_session` cookie），
  但负责用户/角色/权限的数据层和 admin API，两者互补。
- [2026-07-23-web-permission-and-approval](../feature/2026-07-23-web-permission-and-approval.md) —
  sandbox/approval 策略，与 HTTP 认证正交。
- [2026-07-31-permission-default-for-new-sessions](../feature/2026-07-31-permission-default-for-new-sessions.md) —
  Permission Settings 默认值与会话 pinning。
- `feature/2026-08-31-rbac-auth-and-transport-guard.md`（旧 fork 上的 RBAC 实现笔记）
- `feature/2026-08-31-configuration-plane-by-role.md`（旧的配置面按角色门控笔记）

后两篇描述了 fork 上的本地实现，本次合并后**仅作为历史参考**——架构上的
"权限驱动" 决策保留（`AUTH_USER_KEY` + 字符串键 + `page:settings` 等权限键），
但实现细节已被精简（1020 行 auth.ts → ~600 行 auth-api + auth-store）。
