# tokens

clauth ships two layers of token primitives:

1. **The hashing primitives** — `generate-token`, `token-hash`,
   `verify-token-hash`. Pure functions over strings.
2. **The repo-aware primitives** — `create-token`,
   `find-and-validate-token`, `revoke-token`,
   `revoke-all-tokens-for-user`. These read and write
   `auth_tokens` rows.

Most of clauth (session, remember-me, mail) is built on these.
You'd touch them directly for: implementing your own
authenticated-by-token API surface, building admin tools that
list / revoke tokens, or implementing a new flow that needs a
single-use link.

---

## The hashing primitives

### `(generate-token &optional (BYTE-LENGTH 32)) → (values RAW HASH)`

Mint a fresh random token. Returns two values:

- **RAW** — the human-handleable string. Hand to the user (in an
  email link, response body, etc.). Don't store it.
- **HASH** — the SHA-256 hex string. Store this in the database.

```lisp
(multiple-value-bind (raw stored) (clauth:generate-token)
  ;; email RAW to the user
  ;; insert STORED in the DB
  )
```

Default 32 bytes = 256 bits of entropy. The raw output is 64
hex characters; the stored hash is also 64 hex (SHA-256 output).

Use a longer token only if you have a specific reason — 256 bits
is far past brute-force territory and a longer string makes URLs
uglier.

### `(token-hash RAW-TOKEN) → STRING`

SHA-256 of a raw token, as a hex string. Useful when you're
looking up a token presented by the user: hash it client-side
and query the column directly.

```lisp
(let ((hash (clauth:token-hash incoming-raw)))
  (clecto:repo-one *repo*
                   (-> (clecto:from :auth-tokens)
                       (clecto:where `(= :token-hash ,hash)))))
```

### `(verify-token-hash RAW-TOKEN STORED-HASH) → BOOLEAN`

Constant-time equality of the recomputed hash and the stored
hash. Use this when comparing two values that came from
different sources — defense against any timing oracle in the
comparison.

```lisp
(clauth:verify-token-hash candidate-raw row-hash)
```

In practice you'd use `find-and-validate-token` (below) instead;
it already does this check.

---

## Why hash and not store raw

`clug` cookies aren't signed by default, and `auth_tokens` is
read by the application without further verification. If we
stored raw tokens, a DB dump or read-only SQL access would hand
the attacker working session tokens. Hashing means:

- DB dump → attacker has hashes, can't redeem
- A token leaking via Referer / log file / server output is
  game-over for **that one** token; the rest are safe
- Compromised DB can't be replayed against the live app

The cost: lookups by hash (still O(log n) on the unique index)
plus one SHA-256 per request. Cheap.

---

## The repo-aware primitives

These live in `api-token.lisp` and require an `auth_tokens`
table. See [schema](./schema.md) for the required columns and
the unique index on `token-hash` that's mandatory for
correctness.

### `(create-token REPO TOKEN-SCHEMA USER &key context expires-in) → (values RAW RECORD)`

Mint a new token bound to USER. Returns the raw value (to hand
out) and the DB record (rarely needed, returned for
introspection).

```lisp
(multiple-value-bind (raw record)
    (clauth:create-token *repo* 'auth-token user
                         :context "session"
                         :expires-in (* 60 60 24 14))   ; 14 days
  ...)
```

USER must be a **loaded record** (a plist with `:id`).
`create-token` errors on a bare ID:

```lisp
(create-token *repo* 'auth-token 42 ...)
;; → error: create-token requires a loaded user record
```

The `:context` argument differentiates token kinds in the same
table. clauth uses:

| Context | Used by |
| ------- | ------- |
| `"session"`                     | session cookie + remember-me cookie (same raw value, two cookies) |
| `"confirm:<email>"`             | email confirmation links |
| `"reset-password:<email>"`      | password reset links |
| `"login:<email>"`               | magic-link login |
| `"change:<new-email>"`          | change-email confirmation links |
| `"api"`                         | default; for caller-defined API tokens |

The email-suffixed contexts are how clauth implements
"invalidate the token if the user's email rotates after the
link was issued."

`:expires-in` is in seconds. Pass `NIL` for a non-expiring
token (rare; typical use is API tokens with a manual revocation
flow).

Default `:context "api"` and `:expires-in *default-api-token-ttl-seconds*`
(30 days) — convenient for a quick API token.

### `(find-and-validate-token REPO TOKEN-SCHEMA RAW-TOKEN &key context) → ROW | NIL`

Look up RAW-TOKEN's row. Returns the row when:

- A row exists with the matching hash
- Its `:context` equals CONTEXT
- Its `:expires-at` is in the future (or NIL)

`NIL` otherwise. The hash lookup hits the unique index, so this
is O(log n) — and there's no timing oracle from the lookup
because hash equality on an indexed column is constant-ish.

```lisp
(let ((row (clauth:find-and-validate-token *repo* 'auth-token
                                            incoming-token
                                            :context "api")))
  (when row
    (let ((user (clecto:repo-get *repo* 'user (getf row :user-id))))
      ...)))
```

### `(revoke-token REPO TOKEN-SCHEMA TOKEN-ID)`

Delete a token by its primary key:

```lisp
(clauth:revoke-token *repo* 'auth-token (getf row :id))
```

Used internally by `logout`, `confirm-user!`, etc. — single-use
tokens get revoked on consumption.

### `(revoke-all-tokens-for-user REPO TOKEN-SCHEMA USER-ID &key context)`

Bulk-delete every token row for a user. With CONTEXT, only
tokens of that context are removed:

```lisp
;; all sessions
(clauth:revoke-all-tokens-for-user *repo* 'auth-token user-id)

;; only API tokens, keep session + remember-me
(clauth:revoke-all-tokens-for-user *repo* 'auth-token user-id
                                    :context "api")
```

This is the underlying primitive behind credential-change
invalidation (below).

### `(revoke-tokens-on-credential-change REPO TOKEN-SCHEMA USER-ID)`

A named alias for "drop every token row for this user, across
all contexts." Convention: call this from a controller that
just ran `change-password-changeset` or `change-email-changeset`.

```lisp
(let* ((user (clecto:repo-get *repo* 'user uid))
       (cs   (clauth:change-password-changeset data attrs))
       (record (clecto:repo-update *repo* cs)))
  (when record
    (clauth:revoke-tokens-on-credential-change *repo* 'auth-token uid)))
```

`update-password!` and `update-email!` (below) do this for you.

---

## High-level update helpers

These are full "do the thing in one transaction" wrappers. They
build the right changeset, persist it, and purge tokens — all
atomically.

### `(update-password! REPO USER-SCHEMA TOKEN-SCHEMA USER ATTRS &key min-length max-length)`

```lisp
(let ((user (clecto:repo-get *repo* 'user 1)))
  (clauth:update-password! *repo* 'user 'auth-token user
                            (list :current-password "old"
                                  :password "new-pass"
                                  :password-confirmation "new-pass")))
;; → (values updated-record nil)   on success
;; → (values nil invalid-cs)        on failure
```

Inside one `repo-transaction`:

1. Build a `change-password-changeset`
2. `repo-update` the user
3. `revoke-all-tokens-for-user` (purges every device's session)

**Important**: the calling session is also killed. After a
successful update, the user's *current* session cookie no longer
matches any DB row — they'll be logged out on the very device
they're using.

Phoenix's controller calls `log_in_user` immediately after a
successful password update to re-establish a session on the
same device. Mirror that:

```lisp
(multiple-value-bind (rec err)
    (clauth:update-password! *repo* 'user 'auth-token u attrs)
  (cond
    (rec (let ((c (clauth:login conn rec
                                :repo *repo*
                                :token-schema 'auth-token)))
           (render-success c)))
    (t   (render-form-errors conn err))))
```

Without that re-login, the user clicks "Save" and is bounced to
the login page from the very device they were using.

### `(update-email! REPO USER-SCHEMA TOKEN-SCHEMA USER ATTRS)`

```lisp
(clauth:update-email! *repo* 'user 'auth-token user
                       (list :current-password "old"
                             :email "new@example.com"))
```

Immediate email change (no link-confirmation flow). Same shape
as `update-password!` — builds `change-email-changeset`,
updates, purges. Same "kill the calling session" caveat.

For the more typical flow with email-confirmation on the new
address before the swap, use `deliver-change-email-instructions`
+ `apply-email-change!` from [mail](./mail.md).

### `(logout-all-sessions REPO USER-SCHEMA TOKEN-SCHEMA USER-ID) → T`

Force every device this user is signed in on to log out on its
next request:

```lisp
(clauth:logout-all-sessions *repo* 'user 'auth-token user-id)
```

Implementation: deletes every `auth_tokens` row for the user.
The next request from any device finds nothing in
`load-current-user` and gets dropped.

The USER-SCHEMA argument is reserved for future use (clearing an
`:authenticated-at` column when sudo-mode lands). Pass it anyway
— it's a one-character placeholder today.

Note: the **calling** session is not killed in-request. Render a
"you've been signed out everywhere" page directly; the user
re-logs in on their next action.

---

## Session-token primitives

These are the building blocks of `login` / `logout` /
`load-current-user`. You normally don't touch them — the
higher-level helpers do — but they're exported for the rare
case where you want to mint a session token outside the normal
login flow (e.g. an "impersonate user X" admin tool).

### `(build-session-token REPO TOKEN-SCHEMA USER) → (values RAW RECORD)`

Mint a session-context token. Equivalent to
`(create-token repo token-schema user :context "session" :expires-in 14d)`.

### `(load-user-by-session-token REPO USER-SCHEMA TOKEN-SCHEMA RAW-TOKEN) → (values USER RECORD) | NIL`

Reverse of the above: find the token by hash, then fetch the
user. Returns both the user record and the token record (the
latter is what `load-current-user` checks for half-life reissue).

### `(delete-session-token REPO TOKEN-SCHEMA RAW-TOKEN)`

Look up the session row by the raw token and delete it.
Idempotent if the row is already gone. Used by `logout`.

---

## A custom API-token plug

clauth doesn't ship an HTTP-bearer auth plug — `phx.gen.auth`
doesn't, and Phoenix treats programmatic API auth as a separate
concern. But the primitives are general enough that a plug is
~10 lines:

```lisp
(defun bearer-auth (repo user-schema token-schema)
  (lambda (conn)
    (let* ((header (clug:get-req-header conn "authorization"))
           (raw (and header
                     (alexandria:starts-with-subseq "Bearer " header)
                     (subseq header 7)))
           (row (and raw
                     (clauth:find-and-validate-token
                      repo token-schema raw :context "api"))))
      (let ((user (and row (clecto:repo-get repo user-schema
                                             (getf row :user-id)))))
        (cond
          ((null user)
           (clug:halt
            (clug:put-resp conn 401 "{\"error\":\"unauthorized\"}"
                           (list "content-type" "application/json"))))
          (t (clug:assign conn :current-user user)))))))

;; usage
(clug:scope "/api"
  :pipe-through (list (bearer-auth *repo* 'user 'auth-token))
  ...)
```

Add session-vs-API distinction via the `:context` argument if
you want to issue separate token kinds.

---

## Snippets

**Issuing an API token from an admin tool:**

```lisp
(multiple-value-bind (raw record)
    (clauth:create-token *repo* 'auth-token user
                         :context "api"
                         :expires-in (* 60 60 24 90))    ; 90 days
  (declare (ignore record))
  (format nil "Bearer token (show once, store it now): ~a" raw))
```

**Listing a user's tokens** (no clauth helper for this; query
directly):

```lisp
(defun user-tokens (user-id)
  (clecto:repo-all
   *repo*
   (-> (clecto:from :auth-tokens)
       (clecto:where `(= :user-id ,user-id))
       (clecto:order-by '((:desc :inserted-at))))))
```

Show the user `:context`, `:inserted-at`, `:expires-at` —
**not** the hash and not the raw value (you don't have the raw
value anymore; that's the point of hashing).

**A "logout everywhere except this device" pattern:**

```lisp
(defun logout-others (conn)
  (let ((current (clauth:current-session-token conn))
        (uid     (getf (clauth:current-user conn) :id)))
    (when (and current uid)
      (clecto:repo-delete-all
       *repo*
       (-> (clecto:from :auth-tokens)
           (clecto:where `(= :user-id ,uid))
           (clecto:where `(<> :token-hash ,(clauth:token-hash current))))))
    conn))
```

Delete every row for the user **except** the one this request
is using. Useful as a "compromise response" — log out the
suspected other devices without bumping the user out of the
session they're currently in.

---

## Gotchas

- **`auth_tokens.token_hash` must have a unique index.** clauth's
  performance and the "no duplicate token" invariant both
  collapse without it. Migration tools sometimes drop the index
  if you're not careful — verify after each migration. See
  [schema](./schema.md).
- **`create-token` requires a loaded record.** Pass the plist,
  not the ID. The check is there because most "I forgot to look
  up the user" bugs would otherwise silently mint tokens for
  nobody.
- **The raw token only exists for one moment.** `create-token`
  is your one chance to hand it to the user. The DB never sees
  the raw form.
