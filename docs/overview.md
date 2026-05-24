# Overview

clauth is a small auth toolkit assembled from clear, single-purpose
pieces. It does what `mix phx.gen.auth` ships in Phoenix — minus
the LiveView mounts, the asset pipeline, and the controller code
generation — as a set of composable functions and plugs you wire
into your own routes.

The pieces:

- **Passwords** — Argon2id hashing with a self-describing format
  so cost parameters can be ramped without invalidating old hashes
- **Authentication** — email + password lookup, timing-safe, with
  an optional account-lockout layer
- **Sessions** — DB-backed session tokens stored in `auth_tokens`,
  one row per device; session id rotates on login to defend
  against fixation
- **Conn plugs** — `load-current-user`, `require-auth`,
  `require-role`, `log-in-and-redirect`
- **Remember-me** — long-lived cookie carrying the same session
  token; one DB row, two cookies
- **Tokens** — single-use SHA-256-stored tokens for confirmation,
  reset, change-email, magic-link (in the `clauth/mail` subsystem)
- **Telemetry** — a 17-event lifecycle catalogue for logging,
  metrics, or DB-backed audit

Each piece works in isolation and composes through clug and
clecto rather than through internal magic.

---

## Where each thing lives

```
clauth/                  ← core (registration, login, sessions, tokens)
└── clauth/mail          ← opt-in: confirm / reset / change-email / magic-link
```

To use clauth's core you `(ql:quickload :clauth)`. For the mail
flows, add `(ql:quickload :clauth/mail)` — that pulls in
[cliam](https://github.com/gr8distance/cliam).

The mail flows are an opt-in subsystem because their dependency
graph (cliam → mailer adapters → SMTP / SES / Mailgun) is what
you'd otherwise pay for at load time. Apps that don't email
their users skip it.

---

## The two flavors of "auth"

It helps to distinguish them up front:

| | "Who is this request?" (session) | "Who controls this email?" (token) |
| -- | -- | -- |
| **What it answers** | A request is authenticated as user U | A user proved they hold address X |
| **Lifetime** | A session (14 days, half-life reissue at 7) | A single use (15 min for reset/magic, 7d for confirm) |
| **Storage** | One row in `auth_tokens` per device | One row in `auth_tokens`, deleted on use |
| **Transport** | Cookie carrying the raw token | Email body link carrying the raw token |
| **Helpers** | `login`, `logout`, `load-current-user`, `require-auth` | `deliver-confirmation-instructions`, `confirm-user!`, etc. |

Both ride the same `auth_tokens` table, distinguished by a
`context` column: `"session"`, `"confirm:<email>"`,
`"reset-password:<email>"`, `"login:<email>"`,
`"change:<new-email>"`. Token-binding to email means an address
change invalidates any in-flight token for the old address.

---

## A typical request lifecycle

```
   incoming request
        │
        ▼
   clug/session middleware            ← cookie → session map
        │
        ▼
   load-current-user                  ← session token → DB lookup
        │                                 → user attached as :current-user
        ▼
   route's :pipe-through plugs        ← require-auth, require-role, etc.
        │
        ▼
   handler                            ← reads (current-user conn)
```

`load-current-user` is the workhorse: on every request it reads
the cookie's session token, hashes it, looks it up in
`auth_tokens`, fetches the user record, and attaches it to the
conn. If the token is missing, expired, or its user is gone, it
silently no-ops — the next plug (`require-auth`) gets to decide
whether that's a 401 or a redirect.

---

## What earns its keep

clauth follows two rules about scope:

1. **Mirror what `phx.gen.auth` ships, no more.** If Phoenix
   doesn't generate the helper, clauth doesn't either.
2. **Out-of-scope problems get pointed at upstream solutions**,
   not re-implemented.

Things that are *not* in clauth:

- **HTTP bearer auth.** Use `clauth:create-token` /
  `find-and-validate-token` directly; that's ~10 lines of plug.
  Phoenix's `Phoenix.Token` likewise punts.
- **Idle session timeout.** Use `clug/session`'s cookie
  `:max-age`. clauth doesn't track last-request time.
- **CSRF.** Use `lack-middleware-csrf` from the Clack ecosystem.
- **Mail composition primitives.** clauth's mail flows use
  cliam; if you want raw email control, drop down to cliam
  directly.
- **OAuth / SSO.** Different problem entirely; pair clauth with
  whatever Lisp OAuth library you prefer.

---

## Reading order

If you're new, start here in order:

1. **[passwords](./passwords.md)** — how passwords are hashed
   and verified
2. **[changesets](./changesets.md)** — `register-changeset`,
   `change-password-changeset`, etc.
3. **[sessions](./sessions.md)** — DB-backed session tokens,
   login / logout
4. **[plugs](./plugs.md)** — conn-level helpers that gate routes
5. **[schema](./schema.md)** — what tables clauth expects

Then:

6. **[tokens](./tokens.md)** — single-use token primitives
7. **[remember-me](./remember-me.md)** — long-lived cookie flow
8. **[mail](./mail.md)** — the `clauth/mail` subsystem
9. **[telemetry](./telemetry.md)** — audit / observability hooks

Cross-cutting:

10. **[cookbook](./cookbook.md)** — full patterns
11. **[testing](./testing.md)** — unit-testing auth flows
