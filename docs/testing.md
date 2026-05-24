# Testing

Auth code is famously easy to get subtly wrong, and integration
tests against a live mailer + DB are slow. clauth is designed so
most of its pieces test as pure functions; the parts that touch
I/O test against an in-memory SQLite database.

This page shows the testing surface, how to fake the conn for
plug tests, and which Argon2 / DB / mailer parameters to bind so
the suite runs in seconds.

---

## Make the suite fast

Argon2id is the dominant cost in clauth tests. Cap it before
the suite touches `hash-password`:

```lisp
(defun with-cheap-argon (thunk)
  (let ((clauth:*argon2-block-count* 8)        ; 8 KiB (default 4096)
        (clauth:*argon2-iterations*  1))       ; 1 pass (default 3)
    (funcall thunk)))

(test-suite-runner
  (lambda () (with-cheap-argon #'run-all-tests)))
```

Or wrap individual tests:

```lisp
(test register-creates-hash
  (let ((clauth:*argon2-block-count* 8)
        (clauth:*argon2-iterations*  1))
    ...))
```

Don't `setf` these — they affect every subsequent call in the
process. Use `let`.

The clauth test suite uses an even more extreme `*argon2-block-count*
8` because Common Lisp test discovery typically loads + runs in
one process; you want the suite to finish in single seconds.

---

## An in-memory repo

For repo-touching tests, spin up a SQLite `:memory:` database
per test (or per suite):

```lisp
(defparameter *test-repo* nil)

(defun setup-test-repo ()
  (setf *test-repo* (clecto:make-repo (clecto:make-sqlite-adapter ":memory:")))
  (clecto:repo-execute *test-repo* "
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      password_hash TEXT,
      confirmed_at TEXT,
      failed_login_count INTEGER,
      locked_until TEXT,
      role TEXT,
      inserted_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )")
  (clecto:repo-execute *test-repo*
    "CREATE UNIQUE INDEX users_email_idx ON users(email)")
  (clecto:repo-execute *test-repo* "
    CREATE TABLE auth_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      context TEXT NOT NULL,
      authenticated_at TEXT NOT NULL,
      expires_at TEXT,
      inserted_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )")
  (clecto:repo-execute *test-repo*
    "CREATE UNIQUE INDEX auth_tokens_token_hash_idx ON auth_tokens(token_hash)"))

(defun teardown-test-repo ()
  (when *test-repo*
    (clecto:sqlite-close (clecto:repo-adapter *test-repo*))
    (setf *test-repo* nil)))

;; fiveam fixture
(def-fixture clauth-repo ()
  (setup-test-repo)
  (unwind-protect (&body)
    (teardown-test-repo)))
```

`:memory:` databases are fresh per test (because each test gets
a fresh adapter), so no cross-test contamination.

Don't share the same `*test-repo*` across tests that mutate. Use
`with-fixture` and accept the per-test cost — the fresh DDL is
microseconds.

---

## Password hashing tests

```lisp
(test password-roundtrip
  (let ((clauth:*argon2-block-count* 8)
        (clauth:*argon2-iterations*  1))
    (let ((h (clauth:hash-password "secret")))
      (is (clauth:verify-password "secret" h))
      (is (not (clauth:verify-password "wrong" h))))))

(test verify-resists-tampered-params
  (signals error
    (clauth:verify-password
     "x"
     "clauth$argon2id$m=99999999,t=3$abcd$ef")))    ; m out of range
```

The hash format is human-readable enough to test by string
inspection — see `password.lisp` for the format.

---

## Changeset tests

```lisp
(test register-changeset-requires-email
  (let ((cs (clauth:register-changeset 'user (list :password "x") '())))
    (is (not (clecto:cs-valid-p cs)))
    (is (assoc :email (clecto:cs-errors cs)))))

(test register-changeset-rejects-malformed-email
  (let ((cs (clauth:register-changeset 'user
                                       (list :email "no-at"
                                             :password "correct-horse-battery-staple"
                                             :password-confirmation "correct-horse-battery-staple"))))
    (is (not (clecto:cs-valid-p cs)))
    (is (assoc :email (clecto:cs-errors cs)))))

(test register-changeset-hashes-password
  (let ((clauth:*argon2-block-count* 8)
        (clauth:*argon2-iterations*  1))
    (let ((cs (clauth:register-changeset 'user
                                         (list :email "a@b.com"
                                               :password "correct-horse-battery-staple"
                                               :password-confirmation "correct-horse-battery-staple"))))
      (is (clecto:cs-valid-p cs))
      (is (alexandria:starts-with-subseq
           "clauth$argon2id$"
           (clecto:get-change cs :password-hash))))))
```

Changesets are pure — no DB needed.

---

## Authenticate tests

```lisp
(test authenticate-success
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8)
          (clauth:*argon2-iterations* 1))
      (clecto:repo-insert *test-repo*
                          (clauth:register-changeset
                           'user (list :email "alice@example.com"
                                       :password "secret-secret-1"
                                       :password-confirmation "secret-secret-1")))
      (let ((user (clauth:authenticate *test-repo* 'user
                                       "alice@example.com"
                                       "secret-secret-1")))
        (is (not (null user)))
        (is (equal "alice@example.com" (getf user :email)))))))

(test authenticate-wrong-password
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8)
          (clauth:*argon2-iterations* 1))
      (clecto:repo-insert *test-repo*
                          (clauth:register-changeset
                           'user (list :email "alice@example.com"
                                       :password "secret-secret-1"
                                       :password-confirmation "secret-secret-1")))
      (is (null (clauth:authenticate *test-repo* 'user
                                     "alice@example.com" "wrong"))))))

(test authenticate-missing-user-runs-dummy-hash
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8))
      ;; doesn't matter what we pass; we just want to verify it returns
      ;; NIL without raising (which would happen if dummy-hash were unset)
      (is (null (clauth:authenticate *test-repo* 'user
                                     "missing@example.com" "x"))))))
```

The dummy-hash verify path is important: it makes the missing-user
branch take a similar amount of time as a real verify, so timing
doesn't enumerate users. Test it by asserting the call returns
gracefully.

---

## Lockout tests

```lisp
(test lockout-after-max-attempts
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8)
          (clauth:*argon2-iterations* 1)
          (clauth:*lockout-max-attempts* 3))
      (clecto:repo-insert *test-repo*
                          (clauth:register-changeset
                           'user (list :email "alice@example.com"
                                       :password "right"
                                       :password-confirmation "right")))
      ;; 3 wrong attempts
      (dotimes (i 3)
        (clauth:authenticate-with-lockout
         *test-repo* 'user "alice@example.com" "wrong"))
      ;; 4th attempt — even with the right password — is locked
      (multiple-value-bind (user reason)
          (clauth:authenticate-with-lockout
           *test-repo* 'user "alice@example.com" "right")
        (is (null user))
        (is (eq :locked reason))))))
```

Bind `*lockout-max-attempts*` low for tests — the default 5
makes the loop slower.

---

## Session / plug tests

To test plugs without a real Clack handler, construct a conn
manually and call the plug as a function.

```lisp
(test require-auth-halts-without-user
  (let* ((conn (clug:make-conn))
         (out  (clauth:require-auth conn)))
    (is (clug:conn-halted-p out))
    (is (= 401 (clug:conn-status out)))))

(test require-auth-passes-with-user
  (let* ((conn (clug:assign (clug:make-conn) :current-user '(:id 1)))
         (out  (clauth:require-auth conn)))
    (is (not (clug:conn-halted-p out)))))

(test require-auth-redirect-mode-302
  (let* ((conn (clug:make-conn :method :get :path "/secret"))
         (out  (clauth:require-auth conn :redirect-to "/login")))
    (is (clug:conn-halted-p out))
    (is (= 302 (clug:conn-status out)))
    (is (equal "/login" (clug:get-resp-header out "location")))))
```

The conn struct ships with `:assigns`, `:halted-p`, etc. — set
slots directly to fixture-build any state you need.

### Faking a session

For tests that need a session-backed plug to find the user, set
`:current-user` directly:

```lisp
(let ((conn (clug:assign (clug:make-conn) :current-user user-record)))
  (clauth:require-role "admin"))
```

For the full integration path through `load-current-user`,
you'd:

1. Insert a user
2. Call `login` (or `build-session-token` directly) to mint a
   token row
3. Build a conn with the token in the session value

This is more setup; reach for it only when testing the full
path matters (e.g. testing token-reissue at half-life).

---

## Mail flow tests

cliam ships a local-adapter that writes `.eml` files. Use it for
mail-flow tests so the test asserts on filesystem state:

```lisp
(defparameter *test-mailbox* #P"/tmp/clauth-test-mail/")

(defun fresh-mailbox ()
  (uiop:delete-directory-tree *test-mailbox* :validate t :if-does-not-exist :ignore)
  (ensure-directories-exist *test-mailbox*)
  (cliam:make-local-adapter *test-mailbox*))

(test confirmation-roundtrip
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8)
          (clauth:*from-address* '("Test" . "noreply@test"))
          (mailer (fresh-mailbox)))
      (multiple-value-bind (user _)
          (clecto:repo-insert
           *test-repo*
           (clauth:register-changeset
            'user (list :email "alice@example.com"
                        :password "secret-12345" :password-confirmation "secret-12345")))
        (declare (ignore _))
        (let ((raw (clauth:deliver-confirmation-instructions
                    :repo *test-repo* :token-schema 'auth-token
                    :user user
                    :url-builder (lambda (raw) (format nil "http://x/c/~a" raw))
                    :mailer mailer)))
          ;; the .eml was written
          (is (= 1 (length (directory (merge-pathnames "*.eml" *test-mailbox*)))))
          ;; and consuming the token confirms
          (multiple-value-bind (user err)
              (clauth:confirm-user! :repo *test-repo*
                                    :user-schema 'user
                                    :token-schema 'auth-token
                                    :raw-token raw)
            (declare (ignore err))
            (is (not (null (getf user :confirmed-at))))))))))
```

For tests that don't care about email format, the **return
value** of `deliver-*` is the raw token — capture it directly
and skip the filesystem check.

---

## Telemetry tests

`*auth-telemetry*` is dynamic. Bind it inside the test to
capture events:

```lisp
(test login-emits-event
  (with-fixture clauth-repo ()
    (let ((clauth:*argon2-block-count* 8))
      (let* ((user (... insert user ...))
             (events nil)
             (clauth:*auth-telemetry*
              (lambda (e p) (push (list e p) events)))
             (conn (clug:make-conn))
             (_ (clauth:login conn user
                              :repo *test-repo* :token-schema 'auth-token)))
        (declare (ignore _))
        (is (assoc :login (mapcar #'first events)))))))
```

The pattern: capture into a closure variable, assert on its
contents after the call.

---

## What NOT to test

- **Argon2's correctness.** ironclad's tests cover it; verify
  password-roundtrip in your test and stop there.
- **clecto's repo semantics.** clecto's suite covers
  insert / update / delete. Test your **clauth-specific** wiring,
  not the underlying CRUD.
- **clug's plug composition.** clug's suite covers
  `pipeline` / `halt` / etc. Test your **clauth plugs'** specific
  behavior — that they halt with the right status, set the
  right session keys.
- **The output of `traverse-errors` against a specific
  message string.** Match by field, not by message — error
  messages may evolve.

---

## Quick reference

| What to test | How |
| ------------ | --- |
| Password hashing | `(let ((*argon2-block-count* 8)) ...)` + `verify-password` |
| Email shape | `(valid-email-shape-p "...")` directly |
| Register changeset | `(register-changeset 'user attrs)` + `cs-valid-p` |
| Current-password gate | `change-password-changeset` with wrong `:current-password` |
| Authenticate | `:memory:` repo, insert user, call `authenticate` |
| Lockout threshold | bind `*lockout-max-attempts*`, loop wrong attempts |
| Plug halt status | `(funcall #'require-auth conn)` + `conn-halted-p` |
| Session integration | mint token via `build-session-token`, attach to conn |
| Mail flow | cliam local adapter writes `.eml`; capture `raw` return |
| Telemetry | bind `*auth-telemetry*` to a closure that appends |
