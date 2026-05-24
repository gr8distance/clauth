# mail

The `clauth/mail` subsystem implements the four token-by-email
flows: **confirmation**, **password reset**, **change email**,
and **magic-link login**. Each flow is a pair of functions —
`deliver-*` mints the token + sends the email, and the
`*!`-suffixed function validates and applies.

Opt-in: `(ql:quickload :clauth/mail)`. Pulls in
[cliam](https://github.com/gr8distance/cliam) for actual mail
delivery.

---

## Shared shape

Every flow follows the same pattern:

```lisp
;; Step 1 — mint + send
(deliver-* :repo *repo* :token-schema 'auth-token
           :user user
           :url-builder (lambda (raw) (format nil "https://app/path/~a" raw))
           :mailer *mailer*
           [:from ...]
           [:subject ...] [:text-body ...] [:html-body ...])
;; → raw token (for tests; the user gets the link)

;; Step 2 — validate + apply
(<flow>! :repo *repo*
         :user-schema 'user
         :token-schema 'auth-token
         :raw-token (extract-token-from-url))
;; → (values user nil) on success, (values nil reason) on failure
```

Tokens are bound to the user's **current email address** via the
context column — see [tokens](./tokens.md) for the contract. An
address rotation invalidates any in-flight token issued under
the old address. This is `mix phx.gen.auth`'s behavior and the
reason these are not "verify against user_id and trust the
context" — the context **is** the binding.

---

## Setup

### Mailer

```lisp
(ql:quickload :clauth/mail)

;; cliam's local-file adapter — for dev / demo
(setf *mailer* (cliam:make-local-adapter #P"/tmp/myapp-mail/"))

;; cliam's SMTP adapter — for production
(setf *mailer* (cliam:make-smtp-adapter
                :host "smtp.sendgrid.net"
                :port 587
                :user "apikey"
                :password (uiop:getenv "SENDGRID_KEY")))
```

The mailer is passed as `:mailer` to each `deliver-*` call.
Alternatively, omit `:mailer` and cliam will use its global
default — convenient when you set the default at boot.

### `*from-address*`

The default From address for clauth's `deliver-*` helpers:

```lisp
(setf clauth:*from-address* '("My App" . "noreply@example.com"))
```

Each `deliver-*` also accepts an explicit `:from` that
overrides. Missing both (and a fresh process where the
parameter hasn't been set) signals an error rather than silently
dropping the mail — preserves the "failed loudly" invariant.

### URL builder

You hand each `deliver-*` a `:url-builder` lambda that maps a
raw token string to a full URL. clauth doesn't know your route
table, so it doesn't know what URL to embed in the email.

```lisp
(defun confirmation-url (raw)
  (format nil "https://app.example.com/confirm/~a" raw))

(clauth:deliver-confirmation-instructions
 :repo *repo* :token-schema 'auth-token
 :user user
 :url-builder #'confirmation-url
 :mailer *mailer*)
```

**Put the token in a path segment, not a query string.** Query
strings leak via `Referer` headers when the link is clicked —
a Referer-respecting browser would send the token to whatever
third-party assets the post-login page loads. Path segments
don't have this leak.

---

## Confirmation

Verify a freshly-registered user's email address.

### `(deliver-confirmation-instructions &key repo token-schema user url-builder mailer from subject text-body html-body) → RAW-TOKEN`

Mint a confirmation token bound to the user's current email,
send the link to that address.

```lisp
(defun register-handler (conn)
  (let ((attrs (parse-attrs conn)))
    (multiple-value-bind (user err)
        (clecto:repo-insert *repo* (clauth:register-changeset 'user attrs))
      (cond
        (err   (render-form-errors conn err))
        (user  (clauth:deliver-confirmation-instructions
                :repo *repo* :token-schema 'auth-token
                :user user
                :url-builder #'confirmation-url
                :mailer *mailer*)
               (render-please-check-your-email conn))))))
```

Defaults:

- Subject: `"Confirm your account"`
- Validity: 7 days (`*confirmation-validity-seconds*`)

Pass `:text-body` and/or `:html-body` to override the default
templates. They're interpolated **raw** — if you thread user
input into them, escape first.

### `(confirm-user! &key repo user-schema token-schema raw-token) → (values USER NIL) | (values NIL :invalid)`

Validate the token and set `:confirmed-at` on the user. Returns
the updated user record on success, or `(values nil :invalid)`
when:

- The token doesn't exist
- The token is expired
- The bound email no longer matches the user's current address
  (an admin rotated their email after the link was issued, or
  the user themselves changed the address)

```lisp
(defun confirm-handler (conn)
  (let ((raw (getf (clug:conn-params conn) :token)))
    (multiple-value-bind (user err)
        (clauth:confirm-user! :repo *repo*
                              :user-schema 'user
                              :token-schema 'auth-token
                              :raw-token raw)
      (case err
        ((nil)     (render-confirmed conn user))
        (:invalid  (render-invalid-link conn))))))
```

The token is deleted on success — single-use, no replay.

---

## Password reset

Email-driven password change without requiring the current
password.

### `(deliver-reset-instructions &key ...) → RAW-TOKEN`

Mint a short-lived (15 min) reset token bound to the user's
current email.

```lisp
(defun forgot-password-handler (conn)
  (let ((email (getf (parse-attrs conn) :email)))
    (when-let ((user (clecto:repo-get-by *repo* 'user (list :email email))))
      (clauth:deliver-reset-instructions
       :repo *repo* :token-schema 'auth-token
       :user user
       :url-builder (lambda (raw)
                      (format nil "https://app/reset/~a" raw))
       :mailer *mailer*))
    ;; Always respond 200 — leaking "email exists" via 404
    ;; defeats the whole "don't enumerate users" stance.
    (render-please-check-your-email conn)))
```

Notice the "always respond OK" — even if no user matched, the
handler returns a uniform success message. Otherwise a casual
attacker can enumerate registered users by checking which
emails yield "we sent a link" vs "no such user."

Defaults:

- Subject: `"Reset your password"`
- Validity: 15 minutes (`*reset-password-validity-seconds*`)

### `(reset-password! &key repo user-schema token-schema raw-token attrs min-length max-length)`

Validate the token, apply the password change, purge every
token for the user. All in one `repo-transaction`.

```lisp
(defun reset-handler (conn)
  (let ((raw (getf (clug:conn-params conn) :token))
        (a   (parse-attrs conn)))
    (multiple-value-bind (user err)
        (clauth:reset-password! :repo *repo*
                                :user-schema 'user
                                :token-schema 'auth-token
                                :raw-token raw
                                :attrs (list :password (getf a :password)
                                             :password-confirmation
                                             (getf a :password-confirmation)))
      (cond
        ((eq err :invalid) (render-invalid-link conn))
        (err               (render-form-errors conn err))
        (t                 (render-password-changed conn))))))
```

Returns:

- `(values updated-user nil)` — success
- `(values nil :invalid)` — bad / expired / re-bound token
- `(values nil invalid-cs)` — password validation failed
  (too short, confirmation mismatch, etc.)

No current-password required — the token **is** the proof of
email control.

After success, all of the user's session tokens are purged. The
calling browser ends up on a logged-out state; typical UX is to
redirect to the login page where the user signs in fresh.

---

## Change email

Email-confirmed change: the link is sent to the **new** address;
clicking it swaps `users.email`.

This is the safer flow vs `change-email-changeset` (which
swaps immediately and risks locking the user out if they made a
typo).

### `(deliver-change-email-instructions &key ... new-email ...) → RAW-TOKEN`

Mint a token whose context encodes the NEW-EMAIL (so the token
is bound to *that specific change*), send the link to NEW-EMAIL
— the user must control the new address to confirm.

```lisp
(defun request-email-change-handler (conn)
  (let* ((u  (clauth:current-user conn))
         (a  (parse-attrs conn))
         (new-email (getf a :new-email))
         (current-pw (getf a :current-password)))
    (cond
      ((null (clauth:authenticate *repo* 'user (getf u :email) current-pw))
       (render-error conn 401 "Current password incorrect"))
      ((not (clauth:valid-email-shape-p new-email))
       (render-error conn 422 "Bad email"))
      (t
       (clauth:deliver-change-email-instructions
        :repo *repo* :token-schema 'auth-token
        :user u :new-email new-email
        :url-builder (lambda (raw) (format nil "https://app/change-email/~a" raw))
        :mailer *mailer*)
       (render-please-confirm-from-new-address conn new-email)))))
```

Pattern: verify the current password **before** sending the link
— prevents an attacker who briefly grabbed the user's session
from initiating an email change to their own address.

`deliver-change-email-instructions` rejects an invalid NEW-EMAIL
shape with an error (rather than silently sending nothing) —
malformed input is a programming bug, not user error here
(the controller should have validated).

Defaults:

- Subject: `"Confirm your new email address"`
- Validity: 7 days (`*change-email-validity-seconds*`)

### `(apply-email-change! &key repo user-schema token-schema raw-token)`

Validate the token, swap `users.email`, purge tokens.

```lisp
(defun apply-email-change-handler (conn)
  (let ((raw (getf (clug:conn-params conn) :token)))
    (multiple-value-bind (user err)
        (clauth:apply-email-change!
         :repo *repo*
         :user-schema 'user
         :token-schema 'auth-token
         :raw-token raw)
      (case err
        ((nil)         (render-email-changed conn user))
        (:invalid      (render-invalid-link conn))
        (:email-taken  (render-error conn 409 "Email already taken"))))))
```

Returns:

- `(values user nil)` — success
- `(values nil :invalid)` — bad / expired token
- `(values nil :email-taken)` — the new email is now used by
  another user (someone registered it during the window between
  request and confirm — rare but possible)

After success, every session token for the user is purged. The
user gets logged out everywhere; they re-log in with the new
email.

---

## Magic link

Passwordless login.

### `(deliver-magic-link &key ...) → RAW-TOKEN`

Mint a 15-minute magic-link token.

```lisp
(defun request-magic-handler (conn)
  (let ((email (getf (parse-attrs conn) :email)))
    (when-let ((user (clecto:repo-get-by *repo* 'user (list :email email))))
      (clauth:deliver-magic-link
       :repo *repo* :token-schema 'auth-token
       :user user
       :url-builder (lambda (raw) (format nil "https://app/magic/~a" raw))
       :mailer *mailer*))
    ;; Same "always respond OK" treatment as forgot-password
    (render-please-check-your-email conn)))
```

Defaults:

- Subject: `"Your sign-in link"`
- Validity: 15 minutes (`*magic-link-validity-seconds*`)

### `(log-in-by-magic-link! &key repo user-schema token-schema raw-token)`

Validate the token and return the user. The caller then runs
`login` / `log-in-and-redirect` to establish the session.

```lisp
(defun consume-magic-handler (conn)
  (let ((raw (getf (clug:conn-params conn) :token)))
    (multiple-value-bind (user err)
        (clauth:log-in-by-magic-link!
         :repo *repo*
         :user-schema 'user
         :token-schema 'auth-token
         :raw-token raw)
      (cond
        (user (clauth:log-in-and-redirect
               conn user
               :repo *repo*
               :token-schema 'auth-token
               :default-path "/dashboard"))
        (t    (render-invalid-link conn))))))
```

The token is consumed on success — single-use. A user who
shares the magic URL can't replay it.

---

## Tunables

| Variable | Default | What |
| -------- | ------- | ---- |
| `*from-address*` | NIL (must set) | Default From for all deliver-* calls |
| `*confirmation-validity-seconds*` | 7 days | Confirm-email token TTL |
| `*reset-password-validity-seconds*` | 15 minutes | Reset-password TTL |
| `*magic-link-validity-seconds*` | 15 minutes | Magic-link TTL |
| `*change-email-validity-seconds*` | 7 days | Change-email TTL |

The short TTLs (15 min) match `phx.gen.auth` and reflect the
threat model — a leaked reset link in chat history shouldn't
remain redeemable for days.

The long TTLs (7 days) for confirmation / change-email reflect
the user-side reality: an email might sit in an inbox unread
over a weekend.

Override via `let` for tests, or `setf` for production tuning.

---

## Snippets

**Custom mail template:**

```lisp
(clauth:deliver-confirmation-instructions
 :repo *repo* :token-schema 'auth-token
 :user user
 :url-builder #'confirmation-url
 :mailer *mailer*
 :subject "Welcome to MyApp — please confirm"
 :text-body (format nil "Hi ~a,~%~%Click here to confirm: ~a~%"
                    (getf user :display-name)
                    (funcall #'confirmation-url raw)))
```

Wait — `:text-body` needs the URL pre-computed. The helpers
don't expose the URL to the caller of `:text-body`; they pass it
in. For custom text/html that interpolates the URL, the helper
doesn't have a single-step path — your options are:

```lisp
;; (a) accept the helper's default text but a custom subject
(clauth:deliver-confirmation-instructions
 :repo *repo* :token-schema 'auth-token :user user
 :url-builder #'url
 :subject "Hey there"
 :mailer *mailer*)

;; (b) bypass the helper and do it by hand with create-token + cliam
;;     (when you need full control over the email)
```

For (b), see [tokens](./tokens.md) for `create-token`; the
context is `"confirm:<email>"`, where `<email>` is the user's
current address.

**Detect a token-context mismatch separately** (because the
default `:invalid` lumps several cases together):

```lisp
(defun confirm-with-diagnostics (raw-token)
  (let ((row (clecto:repo-one
              *repo*
              (-> (clecto:from :auth-tokens)
                  (clecto:where `(= :token-hash ,(clauth:token-hash raw-token)))))))
    (cond
      ((null row)                          :not-found)
      ((string< (getf row :expires-at)
                (clecto:now-utc-datetime)) :expired)
      ((not (alexandria:starts-with-subseq
             "confirm:" (getf row :context)))  :wrong-context)
      (t                                   :ok))))
```

Useful when designing the error UX (a "this link expired"
message reads differently than "this link is malformed").

**Running the demo without real SMTP** — cliam's local adapter
writes `.eml` files to a directory:

```lisp
(setf *mailer* (cliam:make-local-adapter #P"/tmp/myapp-mail/"))
(setf clauth:*from-address* '("Demo" . "noreply@demo.local"))

;; trigger a flow; check /tmp/myapp-mail/*.eml for the result
```

---

## Gotchas

- **The token-to-email binding is enforced at validation
  time.** If the user changes their email between deliver and
  confirm, the old link silently stops working. That's the
  intended behavior — but it means "I clicked the link but
  nothing happened" can be a legitimate state.
- **Always respond 200 from "request-something-via-email"
  endpoints.** Don't return 404 when the email isn't found.
  Enumeration via response code defeats the privacy you'd
  otherwise get from the email channel itself being private.
- **`:text-body` / `:html-body` are not template-rendered.** They
  go out as-is. If you thread user input (display names from
  the DB), HTML-escape first.
- **`*from-address*` must be set before any `deliver-*` call.**
  No default. The error is loud: "no FROM address" rather than
  silently sending malformed mail.
- **The mailer adapter must be in cliam's expected form.** A
  raw function won't work; you need a `cliam:make-*-adapter`
  result.
- **Mail delivery happens synchronously.** A slow SMTP server
  blocks the request thread. For production, do the actual
  send in a background worker (queue the cliam-built email; the
  worker calls `cliam:deliver` with the configured adapter).
