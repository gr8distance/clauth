# clauth

A small authentication toolkit for Common Lisp web apps.
Composable functions and plugs, no scaffolding, no code
generation, no magic.

clauth ships what `mix phx.gen.auth` produces in Phoenix —
registration, password handling, sessions, role-based
authorization, the four email-driven flows (confirm, reset,
change-email, magic-link), and the audit/telemetry hooks — as a
set of helpers you wire into your own routes.

It sits on top of [clug](https://github.com/gr8distance/clug)
(routing / sessions), [clecto](https://github.com/gr8distance/clecto)
(schema / changeset / repo), and optionally
[cliam](https://github.com/gr8distance/cliam) (mailer).

> **Goal: everything `phx.gen.auth` ships, minus the LiveView /
> asset pipeline / scaffolding pieces. Nothing extra unless it
> earns its keep.**

---

## Install

Not on Quicklisp yet — symlink the checkout:

```sh
git clone https://github.com/gr8distance/clauth.git ~/src/clauth
ln -s ~/src/clauth ~/quicklisp/local-projects/clauth
```

```lisp
(ql:quickload :clauth)         ; core
(ql:quickload :clauth/mail)    ; opt-in: cliam-backed mail flows
```

Dependencies pulled in automatically: ironclad, babel,
alexandria, bordeaux-threads,
[clug](https://github.com/gr8distance/clug),
[clecto](https://github.com/gr8distance/clecto).  `clauth/mail`
adds [cliam](https://github.com/gr8distance/cliam).

---

## Database schema

clauth needs two tables in your database: `users` and
`auth_tokens`. It does **not** ship a migration runner — pick
the tool you already use (dbmate, golang-migrate, goose,
anything that runs SQL).

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
  (:use #:cl)
  (:shadowing-import-from #:clecto #:union))
(in-package #:demo)

(ql:quickload '(:clauth :clecto))

;; --- 1. Schemas ----------------------------------------------------

(clecto:defschema user "users"
  (:id :integer :primary-key t)
  ,@(clauth:auth-fields)
  (:timestamps))

(clecto:defschema auth-token "auth_tokens"
  (:id :integer :primary-key t)
  ,@(clauth:auth-token-fields)
  (:timestamps))

(defparameter *repo*
  (clecto:make-repo (clecto:make-sqlite-adapter ":memory:")))

;; (apply the DDL — see docs/schema-sqlite.md)
(clecto:repo-execute *repo* "CREATE TABLE users (...)")
(clecto:repo-execute *repo* "CREATE TABLE auth_tokens (...)")

;; --- 2. Register / authenticate / log in --------------------------

(multiple-value-bind (user err)
    (clecto:repo-insert *repo* (clauth:register-changeset
                                 'user '(:email "alice@example.com"
                                         :password "correct-horse-battery-staple"
                                         :password-confirmation "correct-horse-battery-staple")))
  (when err
    (format t "rejected: ~a~%" (clecto:cs-errors err))))

(let ((user (clauth:authenticate *repo* 'user
                                 "alice@example.com"
                                 "correct-horse-battery-staple")))
  (when user
    (format t "welcome, user ~a~%" (getf user :id))))
```

That's the whole shape. Build a changeset, hand it to the repo;
authenticate by email+password; mint a session via `login`; gate
routes with `require-auth` / `require-role`.

---

## Documentation

clauth is documented as topic pages under [`docs/`](./docs/).

**Core**

- [Overview](./docs/overview.md) — pieces, lifecycle, what's in / out of scope
- [passwords](./docs/passwords.md) — Argon2id, cost tuning, defense-in-depth
- [changesets](./docs/changesets.md) — register / password / email helpers
- [sessions](./docs/sessions.md) — `authenticate`, `login`, `logout`, `load-current-user`
- [plugs](./docs/plugs.md) — `require-auth`, `require-role`, redirect helpers
- [schema](./docs/schema.md) — the DB tables clauth needs

**Tokens & cookies**

- [tokens](./docs/tokens.md) — the underlying `auth_tokens` primitives
- [remember-me](./docs/remember-me.md) — long-lived cookie flow

**Mail flows** (opt-in `clauth/mail`)

- [mail](./docs/mail.md) — confirm / reset / change-email / magic-link

**Observability**

- [telemetry](./docs/telemetry.md) — audit-event catalogue and sinks

**Cross-cutting**

- [Cookbook](./docs/cookbook.md) — full patterns end-to-end
- [Testing](./docs/testing.md) — testing auth flows fast

---

## What's intentionally out of scope

| not in clauth | reason / alternative |
| ------------- | -------------------- |
| HTTP bearer auth                | `create-token` + `find-and-validate-token` make a 10-line plug; see [tokens](./docs/tokens.md) |
| Idle session timeout            | Use `clug/session`'s cookie `:max-age` |
| CSRF                            | `lack-middleware-csrf` |
| Mail composition primitives     | Use `cliam` directly if you need raw control |
| OAuth / SSO                     | Different concern; pair with a separate OAuth library |
| Code generation / scaffolding   | `phx.gen.auth`'s `--gen.html` shape isn't shipped |
| LiveView-style mounts           | LiveView isn't in this stack |

---

## Source layout

```
src/
  schema.lisp          ; auth-fields helper for users table
  changeset.lisp       ; register-/password-/change-*-changeset
  password.lisp        ; argon2id hashing + format
  token.lisp           ; generate-token / token-hash / verify-token-hash
  api-token.lisp       ; create-/find-/revoke-token, update-password!, etc.
  repo.lisp            ; authenticate, authenticate-with-lockout
  plug.lisp            ; login/logout, require-auth, require-role, ...
  remember-me.lisp     ; long-lived cookie flow
  mail.lisp            ; opt-in clauth/mail: confirm/reset/change-email/magic
  telemetry.lisp       ; *auth-telemetry* hook + event catalog
  util.lisp            ; small helpers
```

Each file is small and orthogonal — read whichever covers what
you're touching.

---

## Run the tests

```sh
sbcl --non-interactive --load ~/quicklisp/setup.lisp \
     --eval '(ql:quickload :clauth/tests)' \
     --eval '(asdf:test-system :clauth)'
```

Tests bind `*argon2-block-count*` and `*argon2-iterations*` low,
so the suite finishes in a few seconds despite touching the
Argon2id path many times.

---

## License

MIT
