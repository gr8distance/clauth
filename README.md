# clauth

Phoenix-flavored authentication for clack-based apps. Mirrors
[`mix phx.gen.auth`](https://hexdocs.pm/phoenix/Mix.Tasks.Phx.Gen.Auth.html)
as a small set of composable functions and plugs — no scaffolding, no
code generation, no magic. Sits on top of
[clug](https://github.com/gr8distance/clug) (routing / session),
[clecto](https://github.com/gr8distance/clecto) (schema / changeset
/ repo), and (optionally) [cliam](https://github.com/gr8distance/cliam)
(mailer).

> **Goal: everything `phx.gen.auth` ships, minus the LiveView / asset
> pipeline / scaffolding pieces. Nothing extra unless it earns its
> keep.**

Out of scope: LiveView mount callbacks, controller generators, HTTP
bearer auth (use [`Phoenix.Token`](https://hexdocs.pm/phoenix/Phoenix.Token.html)-style
helpers in your app), idle-session timeout (set the cookie max-age).

---

## What's in v0.2

**Registration & passwords**
- `register-changeset`, `password-changeset`, `change-password-changeset`,
  `change-email-changeset`
- Argon2id password hashing (via [ironclad](https://github.com/sharplispers/ironclad))
  with a self-describing hash format so the cost factor can be raised
  without invalidating old hashes
- `update-password!` / `update-email!` — atomic helpers that update the
  user, purge every token row, and emit `:credentials-changed`
  telemetry in one shot

**Authentication & sessions**
- `authenticate` (timing-safe even on missing email)
- DB-backed session tokens via `auth_tokens` (one row per device,
  14-day validity, 7-day reissue half-life — same as Phoenix)
- `login`, `logout`, `load-current-user`, `current-user`, …
- `log-in-and-redirect` with `:user-return-to` capture and an
  open-redirect guard
- Remember-me cookie (`login-with-remember-me`,
  `load-current-user-or-remember-me`) using the SAME session token
  the cookie carries
- Session fixation: `login` rotates the session id (`clug:rotate-session-id`)
- `require-auth` (`:redirect-to` HTML mode or JSON 401) and
  `redirect-if-authenticated`

**Mail-driven flows** (opt-in `clauth/mail`, depends on cliam)
- Email confirmation: `deliver-confirmation-instructions` / `confirm-user!`
- Password reset: `deliver-reset-instructions` / `reset-password!`
- Email change confirmation: `deliver-change-email-instructions` /
  `apply-email-change!`
- Magic-link login: `deliver-magic-link` / `log-in-by-magic-link!`
- Every token context is bound to the user's current email
  (`"confirm:alice@example.com"`), so an admin-side rotation
  invalidates pre-issued links

**Hardening additions (not in phx.gen.auth, kept because they pay
for themselves)**
- **Account lockout** (`authenticate-with-lockout`): per-account
  failed-attempt counter (atomic SQL increment) + temporary lock
- **Role-based authorization** (`require-role`): plug that 403s on
  mismatch; multi-role readers + fail-closed on reader errors
- **Telemetry** (`*auth-telemetry*` + `emit-auth-event` + a documented
  event catalog) for SOX/audit logs and observability
- **CSPRNG-grade tokens** (`generate-uuid` reads `/dev/urandom`;
  separate `generate-secure-token` for session-token-class uses)

**Security hardening throughout** (every section audited:
post-Tier-1, post-A, post-B, post-C, post-D, post-phx-mirror,
post-mail):
- Argon2id hash parser bounds every parameter (block-count,
  iterations, salt/hash length) so a tampered DB row can't trigger
  a memory blow-up or zero-length-hash bypass
- Identifier quoting escapes embedded `"`, rejects NUL bytes
- Email always normalized lowercase + trimmed
- Constant-time token verify everywhere
- Atomic credential-change flows (transaction + token purge) prevent
  half-revoked state

206 tests passing.

---

## Install

Not on Quicklisp yet — symlink:

```sh
git clone https://github.com/gr8distance/clauth.git ~/src/clauth
ln -s ~/src/clauth ~/quicklisp/local-projects/clauth
```

```lisp
(ql:quickload :clauth)         ; core
(ql:quickload :clauth/mail)    ; opt-in: cliam-backed mail flows
```

Dependencies pulled in automatically: ironclad, babel, alexandria,
bordeaux-threads, [clug](https://github.com/gr8distance/clug),
[clecto](https://github.com/gr8distance/clecto). `clauth/mail` adds
[cliam](https://github.com/gr8distance/cliam).

---

## Database schema

clauth needs two tables in your database: `users` and `auth_tokens`.
It does **not** ship a migration runner — pick the tool you already
use (dbmate, golang-migrate, goose, anything that runs SQL).

See [docs/schema.md](./docs/schema.md) for:

- the DDL for [SQLite](./docs/schema-sqlite.md) and [PostgreSQL](./docs/schema-postgres.md)
- common invariants (unique indexes that clauth depends on)
- how to apply the migration with each of the three tools above
- how to splice `auth-fields` / `auth-token-fields` into your clecto
  `defschema`

---

## Quickstart

```lisp
(defpackage #:demo
  (:use #:cl #:clauth #:clug #:clecto)
  (:shadowing-import-from #:clecto #:union))
(in-package #:demo)

;; --- 1. Schemas ----------------------------------------------------

(defschema user "users"
  (:id :integer :primary-key t)
  ;; Splice clauth's standard auth fields, or copy them by hand:
  (:email                 :string)
  (:password-hash         :string)
  (:confirmed-at          :naive-datetime)
  (:failed-login-count    :integer)
  (:locked-until          :naive-datetime)
  (:password              :string :virtual t)
  (:password-confirmation :string :virtual t)
  (:current-password      :string :virtual t)
  (:timestamps))

(defschema auth-token "auth_tokens"
  (:id               :integer :primary-key t)
  (:user-id          :integer)
  (:token-hash       :string)
  (:context          :string)
  (:authenticated-at :naive-datetime)
  (:expires-at       :naive-datetime)
  (:timestamps))

(defparameter *repo* (make-repo (make-sqlite-adapter ":memory:")))

(repo-execute *repo*
 "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                      password_hash TEXT, confirmed_at TEXT,
                      failed_login_count INTEGER DEFAULT 0,
                      locked_until TEXT,
                      inserted_at TEXT, updated_at TEXT)")

(repo-execute *repo*
 "CREATE TABLE auth_tokens (id INTEGER PRIMARY KEY,
                            user_id INTEGER,
                            token_hash TEXT UNIQUE,
                            context TEXT,
                            authenticated_at TEXT,
                            expires_at TEXT,
                            inserted_at TEXT, updated_at TEXT)")

;; --- 2. Register / authenticate / log in --------------------------

(multiple-value-bind (user err)
    (repo-insert *repo* (register-changeset
                         'user '(:email "alice@example.com"
                                 :password "correct-horse-battery-staple"
                                 :password-confirmation "correct-horse-battery-staple")))
  (when err
    (format t "rejected: ~a~%" (cs-errors err))))

(let ((user (authenticate *repo* 'user
                          "alice@example.com"
                          "correct-horse-battery-staple")))
  (when user
    (format t "welcome, user ~a~%" (getf user :id))))
```

---

## Wiring into a clug app

```lisp
(defroutes *routes*
  (:get  "/login"    'show-login-form)
  (:post "/login"    'do-login)
  (:post "/logout"   'do-logout)

  (scope "/account"
    :pipe-through (list (load-current-user *repo* 'user
                                           :token-schema 'auth-token)
                        (lambda (conn)
                          (require-auth conn :redirect-to "/login")))
    (:get  "/"        'account-show)
    (:post "/email"   'change-email)
    (:post "/password" 'change-password)))

(defun do-login (conn)
  (let* ((attrs (clug:get-assign conn :json-body))
         (user  (authenticate *repo* 'user
                              (getf attrs :email)
                              (getf attrs :password))))
    (if user
        (log-in-and-redirect conn user
                             :repo *repo*
                             :token-schema 'auth-token
                             :default-path "/account")
        (clug:put-resp conn 401 "{\"error\":\"invalid credentials\"}"
                       (list "content-type" "application/json")))))

(defun do-logout (conn)
  (clug:put-resp (logout conn :repo *repo* :token-schema 'auth-token)
                 302 "" (list "location" "/")))
```

---

## Core concepts

### Schema fields (`auth-fields`)

```lisp
(:email                 :string)        ; lowercased + trimmed at cast
(:password-hash         :string)        ; argon2id, parameterised string
(:confirmed-at          :naive-datetime)
(:failed-login-count    :integer)       ; for authenticate-with-lockout
(:locked-until          :naive-datetime)
;; virtuals (never reach SQL):
(:password              :string :virtual t)
(:password-confirmation :string :virtual t)
(:current-password      :string :virtual t)
```

`(clauth:auth-fields)` returns these as a list you can splice into
`defschema`. Use them verbatim or copy and tailor.

### Changesets

```lisp
;; sign-up
(register-changeset 'user attrs)
;;   email + format + length + confirmation + unique email + hash

;; change password from inside the app (current pw required)
(change-password-changeset data attrs)
;;   :current-password verified -> length + confirmation -> hash
;;   :credentials-changed telemetry fires

;; change email from inside the app (current pw required, no re-verify)
;; — for the mailer-confirmed variant, use deliver-change-email-instructions
(change-email-changeset data attrs)

;; reset/forgotten password (no current-password — token IS the auth)
(password-changeset data attrs)
```

`update-password!` / `update-email!` are one-call helpers that
combine the changeset, the `repo-update`, and the
`revoke-all-tokens-for-user` purge inside a single transaction —
match the contract of Phoenix's `Accounts.update_user_password/3`.

### Sessions

A login flow:

```lisp
(let ((user (authenticate *repo* 'user email password)))
  (when user
    (login conn user :repo *repo* :token-schema 'auth-token)))
```

What happens:
1. `build-session-token` mints a random 32-byte token, stores the
   SHA-256 hash + user-id + context `"session"` in `auth_tokens`.
2. The raw token goes into the clug session under `:user-token`.
3. `clug:rotate-session-id` issues a fresh sid (fixation defense).

`load-current-user repo user-schema :token-schema 'auth-token` is the
plug for downstream routes: it reads the raw token off the session,
looks up the row, loads the user, and reissues the token if it's
older than 7 days.

### Account lockout

```lisp
(multiple-value-bind (user reason)
    (authenticate-with-lockout *repo* 'user email password
                               :max-attempts 5
                               :lockout-seconds 900)
  (case reason
    ((nil)            (login-flow user))
    (:wrong-password  (render-bad-creds))
    (:locked          (render-locked-page))))
```

The failed-attempt counter is bumped via an atomic SQL
`failed_login_count + 1` (no read-modify-write race). On success the
counter resets.

### Role-based access

```lisp
(scope "/admin"
  :pipe-through (list (load-current-user *repo* 'user
                                         :token-schema 'auth-token)
                      'require-auth
                      (require-role "admin"))
  ...)
```

Role storage is the app's choice; default reader is `(getf user :role)`,
override via `:reader`. Multi-role readers (`(list :admin :editor)`)
are accepted. NIL / empty `allowed` is rejected at construction.

### Remember-me

```lisp
(login-with-remember-me conn user *repo* 'auth-token)

;; on the request pipeline:
(load-current-user-or-remember-me *repo*
                                  :user-schema 'user
                                  :token-schema 'auth-token)
```

One session token, two cookies: the short-lived session cookie + the
long-lived remember-me cookie carry the same raw value. The
remember-me cookie just outlives the browser session. Same auth_tokens
row backs both.

### Logout

```lisp
(logout conn :repo *repo* :token-schema 'auth-token)
```

Deletes the session token row, clears the cookie session, revokes the
remember-me cookie + its row. Idempotent if the session and
remember-me cookies carried the same token.

### Logout everywhere

```lisp
(logout-all-sessions *repo* 'user 'auth-token user-id)
```

Purges every `auth_tokens` row for the user — every device's next
request fails to load and re-prompts for login.

---

## Mail flows (`clauth/mail`)

```lisp
(ql:quickload :clauth/mail)
(setf clauth:*from-address* '("My App" . "noreply@example.com"))
```

### Confirmation

```lisp
(deliver-confirmation-instructions
  :repo *repo* :token-schema 'auth-token :user user
  :url-builder (lambda (raw) (format nil "https://app/confirm/~a" raw))
  :mailer *mailer*)

;; on /confirm/:token:
(confirm-user! :repo *repo* :user-schema 'user :token-schema 'auth-token
               :raw-token raw)
;; => (values user nil)  | (values nil :invalid)
```

### Password reset

```lisp
(deliver-reset-instructions :repo ... :user user :url-builder ... :mailer *mailer*)

;; on /reset/:token POST:
(reset-password! :repo ... :user-schema 'user :token-schema 'auth-token
                 :raw-token raw
                 :attrs '(:password "..." :password-confirmation "..."))
;; => (values user nil) | (values nil :invalid) | (values nil invalid-cs)
```

15-minute TTL by default. The token's context is bound to the user's
current email, so an email rotation invalidates pre-issued reset links.

### Change email (with mail confirmation)

```lisp
(deliver-change-email-instructions
  :repo ... :user user :new-email "new@example.com"
  :url-builder ... :mailer *mailer*)

(apply-email-change! :repo ... :user-schema 'user :token-schema 'auth-token
                     :raw-token raw)
;; => (values user nil) | (values nil :invalid) | (values nil :email-taken)
```

### Magic-link login

```lisp
(deliver-magic-link :repo ... :user user :url-builder ... :mailer *mailer*)

(multiple-value-bind (user reason)
    (log-in-by-magic-link! :repo ... :user-schema 'user
                           :token-schema 'auth-token :raw-token raw)
  (when user
    (login-and-redirect conn user :repo ... :token-schema 'auth-token)))
```

---

## Auth telemetry

```lisp
(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (log:info "auth ~a ~a" event payload)))
```

Catalog: `:login`, `:logout`, `:auth-success`, `:auth-failure`,
`:auth-locked`, `:account-locked`, `:credentials-changed`,
`:confirmation-sent`, `:confirmed`, `:reset-sent`, `:password-reset`,
`:change-email-sent`, `:email-changed`, `:magic-link-sent`,
`:magic-link-used`, `:token-created`, `:token-revoked`.

Payload keys depend on the event; never includes passwords or raw
tokens. Email appears in failure events because audit trails need it.

The callback runs INLINE on the request thread; queue slow sinks off
to a worker. Errors from the callback are swallowed and reported
once to `*error-output*` so a misconfigured backend can't break auth.

---

## Source layout

| File | Role |
|------|------|
| `src/password.lisp`    | Argon2id hash + parse + verify (bounded params) |
| `src/token.lisp`       | Generic random tokens (raw + SHA-256) |
| `src/schema.lisp`      | `defschema`, `auth-fields`, `now-utc-datetime`, `generate-uuid` / `generate-secure-token` (CSPRNG-backed) |
| `src/changeset.lisp`   | `register-*`, `password-*`, `change-*` changesets + validators |
| `src/repo.lisp`        | `authenticate`, `authenticate-with-lockout`, dummy verify, atomic counter bump |
| `src/api-token.lisp`   | DB-backed token primitives + session tokens + `update-password!` / `update-email!` / `logout-all-sessions` |
| `src/plug.lisp`        | `login`, `logout`, `load-current-user`, `require-auth`, `require-role`, `redirect-if-authenticated`, `log-in-and-redirect`, return-to flow |
| `src/remember-me.lisp` | Remember-me cookie tied to the session token |
| `src/telemetry.lisp`   | `*auth-telemetry*` + event helpers |
| `src/mail.lisp`        | Mail flows (loaded by `clauth/mail`) |
| `src/util.lisp`        | Internal `->` macro |

Each module is small; read whichever one you're using.

---

## Run the tests

```sh
sbcl --non-interactive --load ~/quicklisp/setup.lisp \
     --eval '(ql:quickload :clauth/tests)' \
     --eval '(asdf:test-system :clauth)'
```

206 tests. Coverage includes:
- argon2 hash format / tampered params / bypass attempts
- registration validation + unique-email collision surfacing
- authenticate (happy, wrong-password, missing-user, nil-stored-hash, timing parity)
- lockout (threshold + reset + custom threshold + atomic counter)
- session token roundtrip + reissue + per-device revocation
- remember-me roundtrip + post-credential-change invalidation
- `login` / `logout` / `log-in-and-redirect` (with return-to capture, GET-only, query-string included, open-redirect guard)
- `require-auth` (JSON + redirect modes), `redirect-if-authenticated`
- `require-role` (allowed/forbidden, multi-role, empty rejection, reader-errors fail-closed)
- email confirmation, password reset, change-email, magic-link — happy + email-rotation invalidation + collision handling
- `*auth-telemetry*` fires + handler errors silenced

---

## License

MIT
