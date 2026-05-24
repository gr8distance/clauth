# sessions

clauth's sessions are **DB-backed**. The cookie carries a raw
session token; the database holds the SHA-256 hash. Each device
gets its own row in `auth_tokens` (context `"session"`), so
revoking a single device is a one-row delete and revoking
everything is a `DELETE WHERE user_id = ?`.

This page covers `authenticate` / `login` / `logout` plus the
session-token primitives that back them. The route-gating plugs
(`require-auth`, `require-role`) live in [plugs](./plugs.md).

---

## The contract

```
   email + password                               raw session token
        │                                                ▲
        ▼                                                │
   authenticate ────────────────────► login ────────────┘
                                          │
                                          ▼
                                   clug session cookie
                                          │
                                          ▼
                                   load-current-user
                                          │
                                          ▼
                                   :current-user assign
```

Three primitives, three plugs:

| Primitive | Role |
| --------- | ---- |
| `authenticate`              | "Is this email + password valid?" — returns the user record or NIL |
| `login`                     | "Mint a session for this user record" — writes a token row, stashes the raw value in the cookie session |
| `logout`                    | "Drop this device's session" — deletes the token row, clears the cookie session |
| `load-current-user` *(plug)*| "Read the cookie → look up the token → attach the user" |

The auth flow lives across these primitives; the plug layer
([plugs](./plugs.md)) gates routes on `:current-user` being
present.

---

## `(authenticate REPO SCHEMA-NAME EMAIL PASSWORD) → USER | NIL`

Look up the user by EMAIL and verify PASSWORD. Returns the
user plist on success, `NIL` otherwise.

```lisp
(let ((user (clauth:authenticate *repo* 'user "alice@example.com" "...")))
  (if user
      (login conn user :repo *repo* :token-schema 'auth-token)
      (render-login-error conn)))
```

Behavior:

- EMAIL is lowercased and trimmed (`normalize-email`) before the
  DB lookup — matches the normalization done by
  `register-changeset` so case differences don't cause "user not
  found."
- When the email is absent **or** the row has no password hash, a
  dummy Argon2 verify still runs against a precomputed dummy hash.
  This keeps timing approximately constant regardless of whether
  the user exists, blocking user-enumeration via response time.
- The dummy hash is computed at module load time, behind a
  thread-safe lock — the first concurrent `authenticate` call
  doesn't race to compute it.

`authenticate` does **not** enforce account lockout. For that:

---

## `(authenticate-with-lockout REPO SCHEMA-NAME EMAIL PASSWORD &key max-attempts lockout-seconds)`

Same lookup with a counter:

```lisp
(multiple-value-bind (user reason)
    (clauth:authenticate-with-lockout *repo* 'user email password)
  (case reason
    ((nil)            (login conn user ...))                       ; success
    (:locked          (render-error conn 423 "Account locked"))
    (:wrong-password  (render-error conn 401 "Invalid credentials"))))
```

Returns `(values user nil)` on success, or `(values nil reason)`
on failure. REASON is one of:

| Reason | When |
| ------ | ---- |
| `:locked`           | User is currently locked (`:locked-until` in the future), regardless of whether the password was correct |
| `:wrong-password`   | Wrong credentials, or user doesn't exist, or user has no password hash |

On every branch, `verify-password` runs against either the
stored hash or the dummy hash. The total time spent is dominated
by Argon2id, so the gap between "user missing" (verify only) and
"matched + atomic DB write" is within the low-percent range.
For threat models that include sophisticated timing attackers,
add constant-rate request handling upstream.

On a failed attempt, the counter is incremented via an
**atomic SQL-side fragment** — two concurrent wrong-password
requests can't both observe count=N and both write count=N+1.
Both writes turn into `failed_login_count + 1` on the DB.

The lock-until update is a read-modify-write because it's
conditional on "did this attempt cross the threshold?"; the
write is idempotent (same value), so the small race is harmless.

Defaults:

- `*lockout-max-attempts*` = 5
- `*lockout-duration-seconds*` = 900 (15 minutes)

Both can be overridden per-call via the keyword args, or
globally via `setf`.

The `users` table needs `:failed-login-count` (integer) and
`:locked-until` (naive datetime) columns for this to work. See
[schema](./schema.md).

### `(account-locked-p USER) → BOOLEAN`

Predicate. `T` if USER's `:locked-until` is in the future.
Uses UTC string comparison so DST transitions and timezone
migrations don't accidentally unlock accounts an hour early.

---

## `(login CONN USER &key repo token-schema) → CONN'`

Mark CONN as authenticated. USER must be a **loaded record**
(a plist) — not just an ID. Internally:

1. Mint a fresh session token via `build-session-token` (which
   creates a row in `auth_tokens` with context `"session"`).
2. Stash the raw value in the cookie session under
   `:user-token`.
3. Rotate the session id (`clug:rotate-session-id`) — defense
   against session fixation.
4. Emit `:login` telemetry.

```lisp
(let ((c (clauth:login conn user :repo *repo* :token-schema 'auth-token)))
  (clug:put-resp c 200 (json (list :ok t :user-id (getf user :id)))
                 (list "content-type" "application/json")))
```

The `:repo` + `:token-schema` keyword arguments are how clauth
finds the token table. Both must be supplied for the DB-backed
mode. (Omitting them falls back to a cookie-only mode — legacy
migration path; new code always passes them.)

`login` does **not** redirect. If you want "log in and go back
to where the user was trying to reach," use `log-in-and-redirect`
in [plugs](./plugs.md).

---

## `(logout CONN &key repo token-schema) → CONN'`

Clear the session for this device:

1. Read the raw token from the cookie session.
2. Delete the matching `auth_tokens` row.
3. Clear the cookie session (`clug:clear-session`).
4. Revoke the remember-me cookie + its DB row (if present).
5. Emit `:logout` telemetry.

```lisp
(defun logout-handler (conn)
  (clug:put-resp (clauth:logout conn :repo *repo* :token-schema 'auth-token)
                 302 "" (list "location" "/")))
```

Idempotent: logging out a conn that already has no session is a
no-op.

Both `:repo` and `:token-schema` are required to actually purge
the DB row. The convention: always pass them — anywhere you don't
is technically a leak (the token row outlives the session).

---

## `(load-current-user REPO USER-SCHEMA &key token-schema) → PLUG`

Return a **plug** (a function `(conn) → conn`) that attaches the
current user to the conn. The contract:

- Reads the raw session token from the cookie session.
- Hashes it and looks up the `auth_tokens` row (must have
  `context = "session"` and `expires_at` in the future).
- Fetches the user record by `:user-id`.
- Assigns it on the conn as `:current-user`.
- If the token is past `*session-token-reissue-after-seconds*`
  (default 7 days), mints a fresh token and deletes the old —
  matches Phoenix's session-token reissue half-life.

```lisp
(clug:defroutes routes
  (clug:scope "/me"
    :pipe-through (list (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
                        #'clauth:require-auth)
    (:get "" 'me-handler)))
```

`load-current-user` is silent — it just returns the conn
unchanged if there's no valid session. `require-auth` is what
decides "no current user → halt with 401 / 302."

If `token-schema` is omitted, you get a legacy cookie-only mode
where the session carries `:user-id` directly. Don't use it for
new code; it has no per-device revocation.

### Token reissue

Tokens are re-issued at half-life (default 7 days for a 14-day
total lifetime), not on every request. So the steady state is
~one row per device per week. When `load-current-user` reissues,
it:

1. Deletes the old token row
2. Creates a fresh one
3. Writes the new raw value to the cookie session

Known gap: delete-then-insert is not atomic. If the process dies
between them, the user is logged out on the next request. Phoenix
has the same shape. Mitigating that needs an UPDATE on
`token-hash` which clecto doesn't expose yet.

### What "logged in" actually means

A request is logged in iff:

1. The cookie session contains `:user-token`.
2. That token hashes to a row in `auth_tokens` with
   `context = "session"` and a future `expires_at`.
3. The row's `:user-id` points at an extant user.

Lose any of those → `load-current-user` leaves `:current-user`
unset and `require-auth` halts.

To force-log-out a single device, delete the token row. To
force-log-out everywhere, delete every token row for the user
(`logout-all-sessions` in [tokens](./tokens.md)).

---

## `(current-user CONN) → USER-PLIST | NIL`

Read the user record `load-current-user` attached. Convenience
wrapper around `(clug:get-assign conn :current-user)`.

```lisp
(defun me-handler (conn)
  (let ((u (clauth:current-user conn)))
    (clug:put-resp conn 200
                   (json (list :id (getf u :id) :email (getf u :email)))
                   (list "content-type" "application/json"))))
```

Returns `NIL` if no user is attached — which means
`load-current-user` either didn't run or didn't find a valid
session.

### `(current-user-id CONN)` / `(current-session-token CONN)`

Two adjacent helpers:

- `current-user-id` — reads `:user-id` from the session
  directly. **Legacy**; new code reads `(current-user conn)` and
  pulls `:id` off the record.
- `current-session-token` — reads the raw session token from
  the cookie session. Useful when you want to log the token (be
  careful, it's a credential) or pass it to a non-clauth
  consumer.

Both are safe on a destroyed session — they return `NIL` after
`clear-session`.

---

## Tunables

### `*session-token-validity-seconds*`

How long a session token is valid. Default `1209600` (14 days).
Matches `mix phx.gen.auth`.

### `*session-token-reissue-after-seconds*`

Half-life past which `load-current-user` mints a fresh token.
Default `604800` (7 days).

The reissue means a token's effective TTL is "validity + half
the validity again" — a token issued today is valid for 7 days
before reissue, and the reissued token is valid for another 14.
The user stays logged in as long as they keep using the app.

### `*session-context*`

Default `"session"`. The context string used for session tokens
in `auth_tokens`. Changing it lets you keep multiple parallel
session schemes in one table (e.g. "web" vs "mobile-app"); the
default is fine for most apps.

### `*session-token-key*`

Default `:user-token`. The cookie-session key where the raw
token lives. Matches Phoenix's session key naming.

---

## Snippets

**Login handler with redirect to captured return-to:**

```lisp
(defun login-submit (conn)
  (let ((attrs (parse-attrs conn)))
    (multiple-value-bind (user reason)
        (clauth:authenticate-with-lockout *repo* 'user
                                          (getf attrs :email)
                                          (getf attrs :password))
      (case reason
        ((nil)            (clauth:log-in-and-redirect
                           conn user :repo *repo* :token-schema 'auth-token
                           :default-path "/dashboard"))
        (:locked          (render-error conn 423 "Account locked"))
        (:wrong-password  (render-error conn 401 "Invalid credentials"))))))
```

**Wiring `load-current-user` once for all routes that care:**

```lisp
(defun authed-pipe ()
  (list (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
        #'clauth:require-auth))

(clug:defroutes routes
  (:get "/"        'home)
  (:get "/login"   'login-form)
  (:post "/login"  'login-submit)

  (clug:scope "/me"
    :pipe-through (authed-pipe)
    (:get  ""              'me)
    (:post "/password"     'change-password)))
```

**Custom session-context** (e.g. separate API token kind from
session token kind):

```lisp
(let ((clauth:*session-context* "web"))
  (clauth:login conn user :repo *repo* :token-schema 'auth-token))
;; later requests authenticate against context = "web"
```

(Note: this binding has to be in effect at the call site of
`login`, `load-current-user`, AND `logout` — they all reference
the parameter. In practice you `setf` it once at boot.)

**Force-logout of a single device** (e.g. from an admin
"manage sessions" screen):

```lisp
(defun revoke-device (token-id)
  (clauth:revoke-token *repo* 'auth-token token-id))
```

`auth_tokens` rows are listed for a user via
`(repo-all *repo* (-> (from :auth-tokens) (where '(= :user-id ID)) (where '(= :context "session"))))`.

**Force-logout everywhere** for a user:

```lisp
(clauth:logout-all-sessions *repo* 'user 'auth-token user-id)
```

Every device that holds a now-deleted token finds nothing in
`load-current-user` and gets logged out on its next request.
