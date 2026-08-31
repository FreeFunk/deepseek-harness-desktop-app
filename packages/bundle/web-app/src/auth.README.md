# `@deepseek-ai/dsh-web-app/auth` — Built-in RBAC authentication

Integrates username/password login, session management, and an admin console
into the `dsh web` browser surface.

---

## What this module owns

| Concern | Detail |
|---|---|
| Auth UI | `/login`, `/logout`, `/admin` (HTML pages) |
| Auth API | `POST /auth/change-password` |
| Admin API | CRUD for users, roles, permissions |
| Session storage | SQLite at `~/.dsh/auth.db` (configurable) |
| Browser identity | `window.__DSH_AUTH_USER__` (injected in index.html) |

This module does **not** own the model prompt, client-side UI components, or
the web runtime variable — those belong to `dsh-client-connection` and
`dsh-web-frontend`.

---

## Configuration

Pass through `cordis.patch.yml`:

```yaml
entries:
  - name: web-app
    plugins:
      - '@deepseek-ai/dsh-web-app/auth'
        dbPath: ~/.dsh/auth.db          # optional; default: ~/.dsh/auth.db
        sessionExpireHours: 24         # optional; default: 24
        adminConsole: true             # optional; default: true
```

### Default roles and permissions

The SQLite schema seeds the following on first run:

| Role | Permissions |
|---|---|
| `admin` | `page:admin`, `api:admin`, `page:settings`, `page:chat` |
| `user` | `page:settings`, `page:chat` |

The default admin account is **username: `admin`, password: `admin`**. Change
the password immediately after first login.

---

## RBAC model

```
users ──role_id──▶ roles ────▶ role_permissions ──◀── permissions
  │
  └───sessions (opaque token → user_id, expires_at)
```

### Permissions used by this module

| Permission | Meaning |
|---|---|
| `page:admin` | May access `/admin` and all `/auth/admin/*` routes |
| `api:admin` | May perform destructive mutations (delete user, delete role) |

Other permission strings (e.g. `page:settings`, `page:chat`) are stored and
returned but not enforced by this module — downstream plugins can check them
via `AUTH_USER.permissions`.

---

## Admin API reference

### Users

| Method | Path | Require | Body | Response |
|---|---|---|---|---|
| `GET` | `/auth/admin/users` | `page:admin` | — | `User[]` |
| `POST` | `/auth/admin/users` | `api:admin` | `{username, password, displayName, roleId}` | `User` |
| `PUT` | `/auth/admin/users/:id` | `api:admin` | `{displayName?, roleId?, status?}` | `User` |
| `DELETE` | `/auth/admin/users/:id` | `api:admin` | — | `{}` |

### Roles

| Method | Path | Require | Body | Response |
|---|---|---|---|---|
| `GET` | `/auth/admin/roles` | `page:admin` | — | `Role[]` |
| `POST` | `/auth/admin/roles` | `api:admin` | `{name, label, description, permissions[]}` | `Role` |
| `PUT` | `/auth/admin/roles/:id` | `api:admin` | `{label?, description?, permissions[]?}` | `Role` |
| `DELETE` | `/auth/admin/roles/:id` | `api:admin` | — | `{}` |

### Permissions

| Method | Path | Require | Response |
|---|---|---|---|
| `GET` | `/auth/admin/permissions` | `page:admin` | `Permission[]` |

---

## Extending

### Adding a new permission-gated route

```ts
import { AUTH_USER } from '@deepseek-ai/dsh-web-app/auth'

function yourHandler(req: IncomingMessage, res: ServerResponse) {
  const user = (req as unknown as Record<string, unknown>)[
    '@deepseek-ai/dsh-web-app/auth-user'
  ] as AuthUser | null
  if (!user?.permissions.includes('page:your-feature')) {
    res.writeHead(403, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'permission denied' }))
    return
  }
  // ...
}
```

### Checking permissions in Cordis plugins

Inject `AUTH_USER` from `IncomingMessage` using the same key as above. The
`AuthUser` shape is exported from this module.

---

## Model Experience

This module does not make LLM API calls. Session tokens are opaque
`base64url` strings with 32 random bytes. Passwords use PBKDF2-SHA512
(100,000 iterations, 16-byte salt). Sessions expire server-side and are
purged on read.

---

## Known Limitations

- Session tokens are stored as binary blobs; concurrent session creation from
  multiple workers requires external locking (not needed for the single-host
  web runtime).
- The admin console does not support bulk role assignment.
- This module does not integrate with external identity providers.
