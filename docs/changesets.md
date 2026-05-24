# changesets

clecto changesets pre-loaded with the standard auth patterns:
**register**, **password change** (with and without current
password), and **email change**.

Each helper is a regular function returning a clecto changeset.
You hand the result to `clecto:repo-insert` or
`clecto:repo-update` — clauth doesn't introduce a new persistence
path; everything routes through clecto's repo.

The validations baked into these helpers match
`mix phx.gen.auth`'s shape:

- Email is normalized to lowercase + trimmed before any unique
  check
- Email shape is checked with a Phoenix-style regex equivalent
  (`one-or-more non-(@,;\s)` + `@` + same), not just "contains
  `@`"
- Password is length-bounded (default 12-1024) — bind the
  arguments to tighten
- Password confirmation matches
- Argon2id hash lands on `:password-hash` automatically

---

## `(register-changeset SCHEMA ATTRS &key min-length max-length)`

The signup changeset. ATTRS is a plist with `:email`,
`:password`, and `:password-confirmation`. SCHEMA is the
clecto schema symbol (typically `'user`).

```lisp
(repo-insert
 *repo*
 (clauth:register-changeset 'user
                            (list :email "Alice@Example.com"
                                  :password "correct-horse-battery"
                                  :password-confirmation "correct-horse-battery")))
;; → (:id 1 :email "alice@example.com" :password-hash "clauth$argon2id$..." ...), NIL
```

What it does:

1. Lowercase + trim `:email`.
2. `cast` `:email`, `:password`, `:password-confirmation`.
3. `validate-required` on `:email` and `:password`.
4. `validate-email-shape` on `:email` (see below).
5. `validate-length` `:password` between MIN-LENGTH and MAX-LENGTH.
6. `validate-confirmation` for `:password`.
7. `unique-constraint` `:email` — DB violation maps to a field
   error.
8. `put-change :password-hash` — only if the changeset is still
   valid.

MIN-LENGTH defaults to 12, MAX-LENGTH to 1024. Override for
domain-specific requirements:

```lisp
(register-changeset 'user attrs :min-length 16)
```

---

## `(password-changeset DATA ATTRS &key min-length max-length)`

Set a password **without** requiring the current password. Use
this when you've already verified the user some other way — most
commonly right after a password-reset link was redeemed.

DATA is the loaded user record. It must carry `:__schema__`
because cast needs to find the schema. The convenient pattern is
to splice it in:

```lisp
(let ((data (list* :__schema__ 'user user)))
  (clauth:password-changeset data
                             (list :password "newpass"
                                   :password-confirmation "newpass")))
```

Validations: required + length + confirmation, then hash.

`reset-password!` (in [mail](./mail.md)) uses this internally —
the token is the proof of email control, so the current password
isn't needed.

---

## `(change-password-changeset DATA ATTRS &key min-length max-length)`

The user-facing "change my password" form. ATTRS supplies:

- `:current-password` — the user's existing password (must verify
  against `:password-hash`)
- `:password` — the new password
- `:password-confirmation`

```lisp
(let* ((user (clecto:repo-get *repo* 'user 1))
       (data (list* :__schema__ 'user user))
       (cs   (clauth:change-password-changeset
              data
              (list :current-password "old"
                    :password "new-correct-horse"
                    :password-confirmation "new-correct-horse"))))
  (clecto:repo-update *repo* cs))
```

If `:current-password` doesn't match the stored hash, the error
attaches to `:current-password` (not to `:password`) so a form
can highlight the right input.

The current-password check runs **before** the other validations
but doesn't short-circuit — the user sees all errors at once.

**Known gap**: no optimistic locking. Two simultaneous requests
can both pass the current-password check (using the OLD hash),
and last-write wins on the new password. The losing tab sees a
silent success. Phoenix has the same default behavior; the usual
mitigation at the controller layer is CSRF — one form, one
token. clauth will gain `WHERE`-augmented updates when clecto
exposes them.

### Pair with `update-password!`

For the full flow including session invalidation, see
[tokens](./tokens.md). The `update-password!` wrapper builds this
changeset, applies it, and purges every `auth_tokens` row for the
user — so other devices are forced to re-auth on their next
request.

---

## `(change-email-changeset DATA ATTRS)`

Immediate email change, gated by the user's current password. No
confirmation-by-link. ATTRS supplies `:email` (the new address)
and `:current-password`.

```lisp
(let* ((user (clecto:repo-get *repo* 'user 1))
       (data (list* :__schema__ 'user user))
       (cs   (clauth:change-email-changeset
              data
              (list :email "Alice2@Example.com"
                    :current-password "old"))))
  (clecto:repo-update *repo* cs))
```

Validations: current-password check, required `:email`, shape
check, "actually changed" check, unique constraint.

For the more typical flow with email-confirmation **on the new
address** before swapping (so a typo can't lock a user out),
use `deliver-change-email-instructions` + `apply-email-change!`
from the mail subsystem. See [mail](./mail.md).

---

## `(valid-email-shape-p STRING) → BOOLEAN`

Predicate. Phoenix-style email shape check:

> one or more non-`@,;\s` characters, then `@`, then one or more
> non-`@,;\s` characters

```lisp
(clauth:valid-email-shape-p "alice@example.com")  ; T
(clauth:valid-email-shape-p "@x.com")             ; NIL — no chars before @
(clauth:valid-email-shape-p "a@b@c")              ; NIL — two @
(clauth:valid-email-shape-p "alice example.com")  ; NIL — whitespace
```

This is stricter than the older "contains `@`" check but
deliberately not a full RFC 5322 parse. Real-world email
validation needs an MX lookup or send-and-confirm — the
[mail](./mail.md) flow does the latter.

---

## `(validate-email-shape CS FIELD &key message) → CS'`

The plug-form of the predicate, returning a changeset with an
error attached on failure. Used inside `register-changeset` and
`change-email-changeset`.

```lisp
(-> cs
    (clauth:validate-email-shape :email))
```

Drop into custom changesets when you want clauth's email shape
check without using the full register/change-email helpers.

---

## Composing your own changesets

The helpers are convenience wrappers. When your app needs
something different — extra fields, an admin-side create, a
"second factor" challenge — write the changeset directly:

```lisp
(defun admin-create-user-changeset (attrs)
  (-> (clecto:cast 'user attrs '(:email :password :role :display-name))
      (clecto:validate-required '(:email :password :role))
      (clauth:validate-email-shape :email)
      (clecto:validate-length :password :min 12)
      (clecto:validate-inclusion :role '("user" "moderator" "admin"))
      (clecto:unique-constraint :email)
      ;; manually put the hash since we're not using register-changeset
      (clecto:put-change :password-hash
                         (clauth:hash-password (getf attrs :password)))))
```

Things clauth's helpers do that you'll want to copy:

- **Lowercase + trim** the email before any unique check or
  validation (`(normalize-email-attrs attrs)` internally; reach
  for it if you're outside the package, otherwise duplicate the
  3 lines)
- **Run the hash only when the changeset is valid** — hashing a
  password and discarding it because the form failed elsewhere
  is a free CPU burn for an attacker
- **Cast `:password` and `:password-confirmation` but never
  persist them** — declare them `:virtual t` in your schema so
  the cast layer drops them at insert time

---

## Snippets

**Custom min-length for an enterprise tier:**

```lisp
(defun enterprise-register (attrs)
  (clauth:register-changeset 'user attrs :min-length 16))
```

**Adding a "must contain a number" check to the standard
register pipeline:**

```lisp
(defun stronger-register-changeset (attrs)
  (let ((cs (clauth:register-changeset 'user attrs)))
    (if (and (clecto:cs-valid-p cs)
             (let ((p (clecto:get-change cs :password)))
               (some #'digit-char-p (or p ""))))
        cs
        (clecto:add-error cs :password "must contain a digit"))))
```

**Renaming the password field for a UI that uses `passphrase`
instead** — easiest path is to remap in the controller before
calling the changeset:

```lisp
(defun map-attrs (attrs)
  (list :email                 (getf attrs :email)
        :password              (getf attrs :passphrase)
        :password-confirmation (getf attrs :passphrase-confirmation)))
```

clauth's changesets read fixed keys; rename in your transport
layer rather than parameterising the helpers.
