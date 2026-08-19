# Agent Note: Web auth as a transport guard plus a role/permission admin system

Status: implemented

## Problem

The fork's custom `auth` plugin in `packages/bundle/web-app/src/auth.ts` enforced login only through the webserver's fallback seat. The webserver matches named `exact`/`prefix` routes before the fallback, so every surface registered as a route skipped the auth check: the whole `/api/*` RPC prefix (owned by `@deepseek-ai/dsh-client-connection`, which exposes session creation, workspace and file operations, the model catalog, and event/WebSocket downlinks) and both WebSocket upgrade paths were reachable without a session. The `/api` trust fence is explicitly a DNS-rebinding/Host check, not authentication, so a remote caller reaching the nginx front could drive the API unauthenticated. The `menus`/`role` model also had no way to manage users, roles, or permissions from the UI, and the SPA had no logout or current-user surface.

## Decision

Two changes, one in `packages/host/webserver` and one in the auth plugin.

**The webserver gained a guard extension point.** `registerGuard(guard)` runs per request in registration order before any route, fallback, or upgrade handler. A guard either delegates via `next()` or short-circuits (responds, or destroys the upgrade socket); a guard that neither responds nor calls `next` stalls dispatch. Guards compose with the existing route tables, so no named route can bypass a composing guard. The auth plugin registers exactly one guard that admits only the public auth surface (`/login`, `POST /api/auth/login`, `/api/auth/logout`) without a session and rejects everything else — HTML navigation redirects to `/login`, API paths answer 401 JSON, upgrades destroy the socket. This closes the bypass at the transport boundary.

**The auth plugin became a complete RBAC store plus admin console.** The SQLite schema moved to prefixed tables (`dsh_users`, `dsh_roles`, `dsh_permissions`, `dsh_role_permissions`, `dsh_sessions`) with a one-user/one-role/role-permissions model, seeded `admin` and `user` system roles and a permission catalog, a legacy-`users` migration, and a bootstrap `admin`/`admin123` account. The HTTP surface is `/api/auth/login|logout|me|menus|password` plus admin-only `/api/auth/users|roles|permissions` (gated by the `api:admin` permission). The `/admin` console is a self-contained HTML page (no build step) gated by `page:admin`, with user CRUD, role/permission editing, and password change. The SPA index gets an injected bootstrap (via the existing `tapIndex`): it redirects expired sessions, exposes `window.__DSH_AUTH__`, hides `[data-dsh-page]` elements the user's page permissions deny, and renders a corner user chip with admin-console/password/logout actions. The database path is configurable (`authDbPath` on the bundle, `dbPath` on the plugin) so tests and deployments can avoid `~/.dsh/auth.db`.

## Alternatives considered

- **Auth check inside `client-connection`'s `/api` route.** Declined: it couples authentication into a transport package, leaves every other route (plugin bundles, future routes) ungated, and requires touching the same layer for each new surface instead of one guard.
- **A prefix route shadowing `/api`.** Declined: the webserver takes the longest prefix, so `/api` (client-connection) wins and a shadow route can never intercept it without changing the match order.
- **Frontend-only page hiding.** Declined for enforcement: hiding nav in the React SPA is UX, not security; the transport guard and permission checks are the actual boundary, and the bootstrap's `data-dsh-page` hook is best-effort on top.
- **Extending the existing `users`/`sessions`/`menus` tables in place.** Declined: the old `users.role` was a text column and `menus` was unmanaged; prefixed tables keep the migration one-way and simple, consistent with the pre-release "backends reject old on-disk formats" stance.
- **Integrating the admin pages into the React SPA's slot system.** Declined: it needs a new client bundle, settings-slot wiring, and a rebuilt dist for each change; a self-contained `/admin` page served by the plugin works wherever the plugin runs and stays testable over plain HTTP.

## Consequences

The login bypass is closed: an unauthenticated request cannot reach any HTTP route or WebSocket upgrade. Logged-in users get role-scoped menus and a logout/chip surface; admins get a working console. The deployment should change the bootstrap `admin123` password and assign normal users the `user` role. The existing `/api` trust fence (`trustedHosts`, loopback-pinned privileged methods) is unchanged and orthogonal: the guard is the authentication layer, the fence is DNS-rebinding defense. The per-file 100% coverage gate is not met by `auth.ts` (a ~950-line DB/HTTP/HTML module); the behavior is pinned by the new `tests/auth.spec.ts` HTTP suite including a real-webserver integration test that exercises the guard against a live `/api` prefix and upgrade route. A follow-up could enforce the loopback-pinned configuration plane by role (e.g. `page:settings`) rather than by reachability.