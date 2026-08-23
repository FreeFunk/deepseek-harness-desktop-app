# Agent Note: Configuration plane gated by role instead of loopback

Status: implemented

## Problem

The Settings → Models page on a remotely-served web deployment failed with
`settings are unavailable in this browser`. The configuration plane
(`settings.*`, `credentials.*`, `llm.discoverModels`) was pinned to
loopback-only in two places: the `/api` trust fence passed those methods with
an empty trust list, and the client-side settings mirror was created in
`memory` mode (terminally unavailable) whenever `connection.isLoopback` was
false. A remote browser therefore never read or wrote settings, regardless of
whether the operator had logged in.

## Decision

Gate the configuration plane by role rather than reachability now that the
web-app bundle ships a real authentication layer (`page:settings` permission).

**Server (`packages/client/connection` + `packages/host/webserver`).** A new
`AUTH_USER` symbol (in the webserver package both plugins already share) is
the cross-package contract: the auth guard stores the signed-in user on the
request under it, and the `/api` fence reads it back. The connection fence now
splits the former privileged set:

- Native/desktop methods (`host.pickDirectory`, `host.openPath`,
  `settings.openDocument`) and the agent-preset authoring plane stay
  loopback-only (unchanged).
- Configuration-plane methods pass for loopback (the desktop has no auth
  layer) or a session carrying `page:settings`. A session is the authoritative
  signal: the permission is enforced even when a reverse proxy rewrites `Host`
  to loopback, which would otherwise short-circuit the check.

**Client (`packages/client/ui-settings`).** A new `SettingsAvailability` signal
replaces the static loopback-only persistence decision. It is always true on
loopback and otherwise follows the authenticated session the web-app bootstrap
publishes as `window.__DSH_AUTH__` plus a `dsh-auth` window event (added to
the bootstrap). The shared describe mirror and every derived scope honor the
signal: availability flips to host, the mirror re-reads, and scopes re-derive,
so a remote admin session that resolves after startup still enables settings.
A remote session without `page:settings` stays `unavailable`/`memory`.

## Alternatives considered

- **Leaving the client on `isLoopback` and fixing only the fence.** Declined:
  the client would still refuse to read settings on a remote origin.
- **Relaxing the fence to any authenticated session.** Declined: `settings`
  and `credentials` expose the configuration and secret store, so the
  `page:settings` permission is the correct gate, matching the RBAC catalog.
- **Fixing the nginx `Host` rewrite instead of the fence.** The deployment's
  nginx forces `Host`/`Origin` to loopback, which defeats any reachability
  gate on the server. Role-gating the configuration plane is robust regardless
  of proxy rewriting, so it is the right code-level fix; passing the real
  origin through nginx remains a recommended deployment follow-up so
  native-only methods are reachability-gated again.

## Consequences

An authenticated `page:settings` user (the admin role) can now read and write
the configuration plane from a remote browser through nginx; Settings →
Models loads and persists. A `user`-role session is refused with 403 on the
configuration-plane methods while the model catalog (`llm.providers`,
`llm.models`) stays open. Native/desktop methods remain loopback-gated in code
but, in this nginx deployment, the loopback `Host` rewrite still admits them
for any authenticated session — the pre-existing state, not a regression; the
nginx pass-through follow-up closes it. Desktop (loopback, no auth guard)
behavior is unchanged.
