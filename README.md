# clauth

Phoenix-flavored authentication for clack-based apps. Sits on top of
[clug](https://github.com/gr8distance/clug) (routing / session) and
[clecto](https://github.com/gr8distance/clecto) (schema / changeset / repo).

> **Goal: cover what `mix phx.gen.auth` covers, as a small set of
> composable functions and plugs. No code generation, no magic.**

Out of scope: LiveView, PubSub, OAuth (separate library).

---

## What's in v0.1

- Argon2id password hashing (via [ironclad](https://github.com/sharplispers/ironclad)) with a self-describing hash format so cost factors can be raised without breaking existing hashes.
- Single-use tokens (password reset / email verify): raw hex to the user, SHA-256 hash to the DB, constant-time verify.
- A `register-changeset` that does `cast → validate-* → hash` in one call.
- A `password-changeset` for changing an existing user's password.
- `authenticate` with a dummy-verify branch so missing emails take the same time as wrong passwords (no user-enumeration via timing).
- `login` / `logout` / `current-user-id` on top of `clug/session`.
- `load-current-user` and `require-auth` as plugs you compose into a pipeline.

## Not in v0.1 (planned)

- Email verification flow (needs a mailer — see [`clailer`](https://github.com/gr8distance/clailer) when that exists).
- Password-reset flow (same dependency).
- "Remember me" persistent cookies.
- Role-based access control beyond `require-auth`.

---

## Install

```sh
git clone https://github.com/gr8distance/clauth.git ~/src/clauth
ln -s ~/src/clauth ~/quicklisp/local-projects/clauth
```

```lisp
(ql:quickload :clauth)
```

You'll also need clug + clecto on your load path (clauth's dependencies pull them in).

---

## Quickstart

```lisp
(defpackage #:demo (:use #:cl #:clauth #:clug #:clecto))
(in-package #:demo)

;; 1. Schema: splice clauth's user fields into a clecto defschema.
(defschema user "users"
  (:id :integer :primary-key t)
  (:email                 :string)
  (:password-hash         :string)
  (:confirmed-at          :naive-datetime)
  (:password              :string :virtual t)
  (:password-confirmation :string :virtual t)
  (:timestamps))

(defparameter *repo* (make-repo (make-sqlite-adapter ":memory:")))

(repo-execute *repo*
 "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                      password_hash TEXT, confirmed_at TEXT,
                      inserted_at TEXT, updated_at TEXT)")

;; 2. Register a user from form params.
(multiple-value-bind (record err)
    (repo-insert *repo* (register-changeset
                         'user '(:email "a@b" :password "hunter22"
                                 :password-confirmation "hunter22")))
  (if record
      (format t "registered: ~a~%" (getf record :email))
      (format t "rejected: ~a~%" (cs-errors err))))

;; 3. Authenticate from a login form.
(let ((user (authenticate *repo* 'user "a@b" "hunter22")))
  (when user
    (format t "welcome, user ~a~%" (getf user :id))))
```

---

## Wiring into a clug app

```lisp
(defroutes *routes*
  (:get  "/login"   'login-page)
  (:post "/login"   'login-action)
  (:post "/logout"  'logout-action)
  (scope "/account" :pipe-through (list (load-current-user *repo* 'user)
                                        'require-auth)
    (:get "/"        'show-account)
    (:put "/email"   'change-email)))

(defun login-action (conn)
  (let* ((attrs (clug:get-assign conn :json-body))   ; or your form parser
         (user  (authenticate *repo* 'user
                              (getf attrs :email)
                              (getf attrs :password))))
    (if user
        (-> conn
            (login user)
            (put-resp 200 "ok"))
        (put-resp conn 401 "{\"error\":\"invalid credentials\"}"
                  (list "content-type" "application/json")))))

(defun logout-action (conn)
  (-> conn (logout) (put-resp 204 "")))
```

`load-current-user` returns a plug. Place it before `require-auth` in
any `scope` that protects authenticated routes. Inside a handler, the
loaded record is reachable via `(current-user conn)`.

---

## Password storage format

```
clauth$argon2id$m=4096,t=3$<hex-salt>$<hex-hash>
```

- `m` — `:block-count` (ironclad parameter; 1 block = 1024 bytes)
- `t` — iteration count
- Both salt and hash are hex-encoded for legibility

Parameters live **inside** the stored string. `verify-password` reads
them from there, not from the current `*argon2-*` specials, so raising
your default cost doesn't invalidate old hashes — they just verify with
their original parameters until the user logs in next and you re-hash.

Tunable via specials (set before hashing):

```lisp
(setf clauth:*argon2-block-count* 8192   ; 8 MiB
      clauth:*argon2-iterations*  3)
```

OWASP 2024 minimum for Argon2id is around 7 MiB / t=3. The defaults
shipped here (4 MiB / t=3) are on the low side; raise for production.

---

## Timing-safe authenticate

```lisp
(authenticate *repo* 'user email password)
```

When EMAIL exists, `verify-password` runs against the stored hash.
When it doesn't, the function runs `verify-password` against a *dummy*
hash so the response time is roughly the same — preventing user-
enumeration via timing channels.

---

## Tokens

```lisp
(multiple-value-bind (raw stored) (generate-token)
  ;; e-mail RAW to the user (in a URL).
  ;; persist STORED on a row that knows the user and an expiry.
  ...)

(verify-token-hash raw-from-url stored-from-db)
```

Use this for password-reset links, email-confirmation links, magic-login
codes, etc. The raw token is 32 random bytes hex-encoded (~256 bits);
the DB only sees the SHA-256 hash.

---

## Source layout

```
src/
  package.lisp         ; exports
  password.lisp        ; argon2id hash + parse + verify
  token.lisp           ; raw/hash tokens
  schema.lisp          ; auth-fields helper
  changeset.lisp       ; register-changeset, password-changeset
  repo.lisp            ; authenticate (timing-safe)
  plug.lisp            ; login/logout, load-current-user, require-auth
```

---

## Run the tests

```sh
sbcl --non-interactive --load ~/quicklisp/setup.lisp \
     --eval '(ql:quickload :clauth/tests)' \
     --eval '(asdf:test-system :clauth)'
```

28 tests covering password hashing edge cases, token round-trip,
schema shape, registration validation, unique-email constraint
surfacing, and authenticate against a SQLite in-memory DB.

---

## License

MIT
