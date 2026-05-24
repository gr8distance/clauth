# passwords

Password hashing and verification, plus the parameters that
control the cost / security tradeoff.

clauth uses **Argon2id** via `ironclad`. Hashes are stored as a
self-describing string so future parameter changes don't break
old hashes — verification reads the parameters embedded in the
stored value, never the current globals.

---

## Quick example

```lisp
(setf *repo* (make-repo (make-sqlite-adapter ...)))

(let ((hash (clauth:hash-password "correct-horse-battery-staple")))
  ;; store hash in users.password_hash
  ...)

(let ((stored (getf (clecto:repo-get *repo* 'user 1) :password-hash)))
  (clauth:verify-password "guess" stored))
;; => T or NIL, constant-time
```

In practice you rarely call `hash-password` directly — the
changeset helpers ([changesets](./changesets.md)) put the hash on
`:password-hash` automatically. You'd call it manually for an
admin-driven password set or for a custom auth surface.

---

## API

### `(hash-password PASSWORD) → STRING`

Hash PASSWORD with Argon2id. PASSWORD can be a string or an
octet vector. Returns a self-describing string:

```
clauth$argon2id$m=4096,t=3$<32-hex-salt>$<64-hex-hash>
```

Parameters come from `*argon2-block-count*`, `*argon2-iterations*`,
and `*argon2-key-length*` at the moment of the call. Ramp them by
binding new values for new hashes; old hashes keep verifying
against their stored parameters.

### `(verify-password PASSWORD ENCODED-HASH) → BOOLEAN`

Constant-time check. Returns `T` iff PASSWORD matches the hash
encoded in ENCODED-HASH.

Verification uses the parameters baked into the stored hash, so
this still verifies after you raise the globals.

A tampered stored hash (an attacker who can write to
`users.password_hash`) cannot:

- Pin a 4 GiB block-count to stall the worker
- Force a zero-length hash that lets constant-time equality
  trivially return `T`
- Drive `parse-integer` into a bignum DoS

Hard caps live in module-level parameters (see "Defense in depth"
below).

---

## Tuning knobs

These are `defvar`s — bind per-call when you can, set globally
once at boot when you know the steady state.

### `*argon2-block-count*`

Memory cost in 1 KiB blocks. Default `4096` (= 4 MiB).

OWASP 2024 recommends ≥ 7 MiB for argon2id. Default is on the
low side for high-security apps — raise to `8192` (8 MiB) or
`16384` (16 MiB) if your machines can afford it. The tradeoff is
straightforward: linear memory cost and roughly linear CPU cost.

```lisp
(setf clauth:*argon2-block-count* 16384)
;; new hashes go to 16 MiB; old hashes keep verifying at their
;; stored values
```

### `*argon2-iterations*`

Time cost (passes over memory). Default `3`. OWASP 2024
recommends ≥ 3.

### `*argon2-key-length*`

Output hash length in bytes. Default `32` (256 bits). No reason
to lower this; raising it costs a bit more memory but isn't
useful unless you have an unusual threat model.

### Binding per-call

For tests, bind temporarily so the suite doesn't pay full cost:

```lisp
(test create-user-with-cheap-hash
  (let ((clauth:*argon2-block-count* 8)         ; 8 KiB
        (clauth:*argon2-iterations*  1))
    ...))
```

Don't `setf` these globally "just for one test" — they affect
every subsequent hash in the process. Use `let`.

### Why a defvar instead of a plist

The cost parameters are deliberately global rather than
threaded through every call. Two reasons:

1. They're set once at boot; the steady state is whatever you
   picked.
2. Phoenix's argon2 binding (`argon2_elixir`) does the same —
   the cost is configured globally and a hash captures the
   parameters at creation time.

If you have a use case for two simultaneous tiers (e.g. fast for
service accounts, slow for human users), bind locally and call
`hash-password` inside the binding.

---

## Defense in depth

Verifying a stored hash is a parsing exercise. The parser is
strict to prevent a tampered DB row from steering verification
into a memory blow-up or trivial bypass:

| Cap | Default | What it stops |
| --- | ------- | ------------- |
| `*max-block-count*`   | 65536 (64 MiB) | hash rows that say `m=4194304` (4 GiB) to stall the worker |
| `*max-iterations*`    | 10 | hash rows that say `t=1000000000` |
| `*min-salt-length*` / `*max-salt-length*` | 8 / 64 bytes | empty / unbounded salts |
| `*min-hash-length*` / `*max-hash-length*` | 16 / 64 bytes | zero-length hash trivial-bypass against constant-time equality |
| `*max-param-string*`  | 24 chars | numeric param tokens long enough to bignum-DoS `parse-integer` before validation |

These are `defparameter`s — not normally tuned. They exist for
"someone wrote to `password_hash` via SQL injection / privileged
admin script / replay log" scenarios.

---

## What's NOT in here

- **Password strength validation.** Length checks come from the
  changeset layer. For dictionary checks against common passwords
  (zxcvbn-style), use an external library and call from a custom
  validator.
- **Password rotation policies.** "Force password change every N
  days" isn't shipped. If you want it, store `password-set-at`
  and check at `require-auth`.
- **Breached-password lookup.** Add as a validator (calling
  `haveibeenpwned` k-anonymity API or similar). Not shipped
  because that's a network call clauth doesn't want to make on
  your behalf.

---

## Migrating off a different hash format

If you have a legacy table with bcrypt / scrypt / plain-MD5
(don't…) hashes, the migration is:

1. Keep the legacy column. Add a `password-hash` column for the
   new clauth-format hashes.
2. On login: try `verify-password` against the new column first;
   if absent, fall back to your legacy verify; on success, write
   the clauth hash and clear the legacy column.

A 4-line `authenticate` wrapper handles this. After a few months,
flip the table — anyone who hasn't logged in by then can reset
their password via the email flow.

---

## Snippets

**Single-use hash without going through changesets** (e.g. for a
fixture / seed):

```lisp
(let ((u (clecto:repo-insert *repo*
                              (clecto:cast 'user
                                           (list :email "alice@example.com"
                                                 :password-hash (clauth:hash-password "..."))
                                           '(:email :password-hash)))))
  ...)
```

**Verify a candidate without doing a full authenticate** (useful
in admin "double-check your password" prompts):

```lisp
(defun user-confirms-password-p (user supplied)
  (let ((stored (getf user :password-hash)))
    (and stored (clauth:verify-password supplied stored))))
```

**Temporarily lower cost for an integration test suite:**

```lisp
(defun with-cheap-hashing (thunk)
  (let ((clauth:*argon2-block-count* 8)
        (clauth:*argon2-iterations*  1))
    (funcall thunk)))

(with-cheap-hashing
  (lambda ()
    (asdf:test-system :my-app)))
```
