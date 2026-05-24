# telemetry

clauth emits events for every lifecycle moment: login, logout,
auth success / failure, lockouts, credential changes, token
mints / revokes, mail flow milestones. You hook in by setting
`*auth-telemetry*` to a function; clauth calls it with an event
name and a payload. No backend shipped — bring your own.

This is the audit-trail / metrics surface. For DB query
telemetry (the layer below), see clecto's `*telemetry*`.

---

## The hook

### `*auth-telemetry*`

A function `(event payload)` called from every clauth lifecycle
hook. Defaults to `NIL` (disabled).

```lisp
(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (log:info "auth ~a ~a" event payload)))
```

A bad handler is contained: if the callback signals, clauth
prints a warning the first time and silently swallows the rest
— so a mis-wired sink can't take down authentication. The
latch lives in `*auth-telemetry-handler-failed*`; reset it to
`NIL` after fixing the sink to re-enable error reporting.

### Threading note

The callback runs **inline on the request thread**. A slow sink
(DB write, HTTP call, file IO) adds its latency to every login,
authenticate, and token operation.

For production, queue the payload onto a worker thread (via
`bordeaux-threads` or a job library) and return immediately:

```lisp
(defvar *audit-queue* (make-instance 'queue ...))

(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (enqueue *audit-queue* (cons event payload))))

(start-worker #'consume-audit-queue)
```

---

## Event catalog

| Event | Fires when | Payload keys |
| ----- | ---------- | ------------ |
| `:login`               | User logged in | `:user-id` |
| `:logout`              | Logged out (or session destroyed) | `:user-id` (may be `NIL`) |
| `:auth-success`        | `authenticate-with-lockout` succeeded | `:user-id` |
| `:auth-failure`        | Wrong credentials / missing user | `:email`, `:reason` |
| `:auth-locked`         | Attempt blocked because account is locked | `:user-id`, `:email` |
| `:account-locked`      | This attempt is what *tripped* the lock | `:user-id`, `:email`, `:reason` |
| `:credentials-changed` | Password or email changed (legacy) | `:user-id` |
| `:token-created`       | API / session / remember-me token minted | `:user-id`, `:context` |
| `:token-revoked`       | Token explicitly revoked | `:user-id`, `:context-or-:all` |
| `:confirmation-sent`   | Confirmation email delivered | `:user-id`, `:email` |
| `:confirmed`           | `confirm-user!` set `:confirmed-at` | `:user-id` |
| `:reset-sent`          | Password-reset email delivered | `:user-id`, `:email` |
| `:password-reset`      | `reset-password!` applied successfully | `:user-id` |
| `:change-email-sent`   | Change-email link delivered | `:user-id`, `:new-email` |
| `:email-changed`       | `apply-email-change!` swapped the address | `:user-id`, `:new-email` |
| `:magic-link-sent`     | Magic-link email delivered | `:user-id` |
| `:magic-link-used`     | Magic-link consumed | `:user-id` |

### `:auth-failure` `:reason` values

| Reason | Meaning |
| ------ | ------- |
| `:no-user`          | No user matched the supplied email |
| `:no-password-hash` | User exists but has no password hash |
| `:wrong-password`   | User exists, has a hash, but the password didn't match |

---

## What's NOT in payloads

clauth deliberately never includes:

- **Passwords** — even on failed attempts
- **Raw token values** — the user's link / cookie content
- **Token hashes** — they're not secrets, but they're not
  useful to a human either

Email **is** included in failure events because the audit trail
needs it to correlate brute-force attempts. Note that failed
attempts may contain emails the user **mistyped** — so an
adjacent third party's address might appear in your audit log.
Apply retention limits accordingly.

---

## A DB-backed audit log

If you want auth events persisted, `clauth:auth-event-fields`
splices the canonical column list into a clecto schema:

```lisp
(clecto:defschema auth-event "auth_events"
  (:id :integer :primary-key t)
  ,@(clauth:auth-event-fields)
  (:timestamps))

;; auth-event-fields gives you:
;;   (:event      :string)
;;   (:user-id    :integer)
;;   (:email      :string)
;;   (:reason     :string)
;;   (:ip         :string)         ; populate from your conn layer
;;   (:user-agent :string)         ; populate from your conn layer
;;   (:metadata   :string)         ; freeform JSON
```

Then wire `*auth-telemetry*` to insert rows:

```lisp
(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (clecto:repo-insert
         *repo*
         (clecto:cast 'auth-event
                      (list :event (string event)
                            :user-id (getf payload :user-id)
                            :email (getf payload :email)
                            :reason (when-let ((r (getf payload :reason)))
                                      (string r)))
                      '(:event :user-id :email :reason)))))
```

Add `:ip` and `:user-agent` by stashing them on the conn before
the auth event fires and reading them from a dynamic variable
(or wrapping `*auth-telemetry*` in a closure that captures the
conn for the duration of the request).

---

## Custom wire-up patterns

### Composing multiple subscribers

`*auth-telemetry*` is a single function. For multiple subscribers
(audit + metrics + slack), compose yourself:

```lisp
(defparameter *audit-subscribers* nil)

(defun multi-audit (event payload)
  (dolist (sub *audit-subscribers*)
    (handler-case (funcall sub event payload)
      (error (e)
        (log:warn "subscriber ~a errored: ~a" sub e)))))

(setf clauth:*auth-telemetry* #'multi-audit)

(push (lambda (e p) (db-write-audit e p))   *audit-subscribers*)
(push (lambda (e p) (statsd-counter e p))   *audit-subscribers*)
(push (lambda (e p) (alert-on-lockout e p)) *audit-subscribers*)
```

Per-subscriber error handling lets a metrics blip not take down
the audit-log write.

### Conditional sinks per event type

```lisp
(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (case event
          ;; failures + lockouts go to the security log
          ((:auth-failure :account-locked :auth-locked)
           (log:warn "security ~a ~a" event payload))
          ;; successes + state changes go to the audit DB
          ((:login :logout :confirmed :password-reset :email-changed)
           (db-audit-write event payload))
          ;; everything else is debug
          (t (log:debug "auth ~a ~a" event payload)))))
```

### Alert on suspicious patterns

```lisp
(let ((fail-counter (make-hash-table :test 'equal)))
  (setf clauth:*auth-telemetry*
        (lambda (event payload)
          (when (eq event :auth-failure)
            (let* ((email (getf payload :email))
                   (n (incf (gethash email fail-counter 0))))
              (when (zerop (mod n 100))
                (alert "100 failures against ~a" email)))))))
```

(For real rate-limit / alert work, use a proper time-windowed
counter, not a monotonic one.)

---

## Snippets

**Counting login successes in StatsD:**

```lisp
(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (declare (ignore payload))
        (case event
          (:login         (statsd:incr "auth.login.ok"))
          (:auth-failure  (statsd:incr "auth.login.fail"))
          (:account-locked (statsd:incr "auth.lock")))))
```

**Capturing into a thread-local trace buffer for tests:**

```lisp
(defvar *captured-events* nil)

(setf clauth:*auth-telemetry*
      (lambda (event payload) (push (list event payload) *captured-events*)))

(test login-emits-event
  (let ((*captured-events* nil))
    (clauth:login conn user :repo *repo* :token-schema 'auth-token)
    (is (assoc :login (mapcar #'first *captured-events*)))))
```

**Disable temporarily inside a binding:**

```lisp
(let ((clauth:*auth-telemetry* nil))
  ;; bulk operations — no audit log entries
  (dolist (cs candidate-changesets)
    (clecto:repo-insert *repo* cs)))
```

Useful in migrations / backfills where you don't want a million
events.

---

## What about `emit-auth-event`?

```lisp
(clauth:emit-auth-event :custom-event (list :data "..."))
```

Public-but-private: clauth uses it internally; it's exported so
applications can fire their **own** auth-flavored events through
the same channel. Useful when you have higher-level auth events
that don't map to clauth's catalogue ("user reset their MFA
device", "user invited to org X").

The contract:

- Pass a keyword EVENT
- PAYLOAD is a plist of whatever your sinks want to see

clauth's catalogue is the recommended starting point; add your
own with separate keywords (don't reuse `:login` for a different
meaning).

---

## Gotchas

- **The sink runs on the request thread.** Slow sink = slow auth.
  Queue for production.
- **Failed-sink suppression latches at process boot.** Setting
  `*auth-telemetry-handler-failed*` to `NIL` re-enables warning
  output after you fix the sink.
- **`emit-auth-event` errors are swallowed** — by design, so a
  busted sink doesn't break auth. The first failure is reported
  to `*error-output*`; the rest are silent.
- **The catalog can grow.** If you write a custom event with a
  reserved name, future clauth versions might collide. Prefix
  custom events with your app's name (`:myapp/...`) to be safe.
- **Email values in failure events may be third-party PII.** A
  user who mistypes their email enters someone else's address
  into your audit log. Apply retention.
