# remember-me

Long-lived cookie that keeps the user logged in across browser
restarts. It carries the **same session token** as the regular
session cookie — one `auth_tokens` row, two cookies. The
remember-me cookie just outlives the browser session.

This matches `phx.gen.auth`'s design: a "remember me" checkbox
extends the cookie lifetime, doesn't create a separate token
class. Less code, less surface area, one revocation path.

---

## Quick example

```lisp
(defun login-submit (conn)
  (let ((attrs (parse-attrs conn)))
    (multiple-value-bind (user reason)
        (clauth:authenticate-with-lockout *repo* 'user
                                          (getf attrs :email)
                                          (getf attrs :password))
      (case reason
        ((nil)
         (let ((c (if (getf attrs :remember-me)
                      (clauth:login-with-remember-me conn user *repo* 'auth-token)
                      (clauth:login                 conn user :repo *repo* :token-schema 'auth-token))))
           (clug:put-resp c 302 "" (list "location" "/dashboard"))))
        ;; ... error branches
        ))))

;; on every request:
(defparameter *load-user*
  (clauth:load-current-user-or-remember-me
   *repo* :user-schema 'user :token-schema 'auth-token))
```

---

## How it works

1. **On login**, `login-with-remember-me` does the same thing as
   `login`, *plus* writes a second cookie under
   `clauth.remember-me` containing the same raw session token.
2. **On a request without the session cookie** (browser
   discarded it / new browser session),
   `load-current-user-or-remember-me`:
   - Tries `load-current-user` first.
   - If that fails, reads the remember-me cookie, validates the
     token, loads the user, and re-establishes the session
     cookie carrying the same raw value.
3. **On logout**, `logout` deletes the auth_tokens row and
   revokes the remember-me cookie.

Because both cookies carry the same raw value, the validation
path is identical — there's no separate "remember-me token
verification" code. The only differences are the cookie lifetime
and the fallback ordering.

---

## API

### `(login-with-remember-me CONN USER REPO TOKEN-SCHEMA &key ttl-seconds secure) → CONN'`

Log in **and** write a remember-me cookie. TTL-SECONDS defaults
to `*remember-me-ttl-seconds*` (14 days, matches Phoenix).
SECURE defaults to `T` — keep it that way unless you're
deliberately running over plain HTTP for development.

```lisp
(clauth:login-with-remember-me conn user *repo* 'auth-token)
;; → conn with:
;;   - session cookie (clug.session=...) carrying the SID
;;   - clauth.remember-me cookie carrying the raw session token
;;   - new auth_tokens row, context "session"
```

The remember-me cookie attributes:

- `Max-Age=1209600` (TTL_SECONDS)
- `HttpOnly` — JS can't read it
- `Secure` — HTTPS only (unless you pass `:secure nil`)
- `SameSite=Lax` — matches Phoenix; cross-site GETs include it
  but POSTs don't. Lax is enough because clauth never mutates
  state on GET; mutation routes require CSRF tokens (use
  `lack-middleware-csrf`).

### `(clear-remember-me-cookie CONN) → CONN'`

Set an expiring (`Max-Age=0`) remember-me cookie. Browser drops
it on receipt. Used internally by `logout`.

Browsers identify cookies by name + path + domain, so the
expiring directive doesn't need to re-specify `:secure` or
`:same-site` — same name on the same domain at the same path is
enough.

### `(revoke-remember-me CONN REPO TOKEN-SCHEMA) → CONN'`

Server-side counterpart of `clear-remember-me-cookie`: when the
request carries a remember-me cookie, *delete the auth_tokens
row* the cookie points at AND set the clearing cookie on the
response.

```lisp
(clauth:revoke-remember-me conn *repo* 'auth-token)
```

Idempotent — calling it without a remember-me cookie just sets
the clearing cookie.

`logout` calls this internally; you'd reach for it directly only
if you want to drop the remember-me cookie without also clearing
the regular session (rare).

### `(load-current-user-or-remember-me REPO &key user-schema token-schema) → PLUG`

The combined load plug. Order of operations on each request:

1. Run `load-current-user`. If a session is found, return the
   conn with `:current-user` attached.
2. Otherwise, look up the `clauth.remember-me` cookie.
3. If it carries a valid token, load the user, **rewrite the
   session cookie** to carry the raw token, and attach
   `:current-user`.
4. If the cookie is present but invalid (token revoked, user
   deleted), expire the remember-me cookie via
   `clear-remember-me-cookie`.

```lisp
(clug:defroutes routes
  (clug:scope "/me"
    :pipe-through
    (list (clauth:load-current-user-or-remember-me
           *repo* :user-schema 'user :token-schema 'auth-token)
          #'clauth:require-auth)
    (:get "" 'me-handler)))
```

This is the loader to use **everywhere** if your app offers
remember-me. There's no per-route choice between session-only
and session-plus-remember; the plug always prefers session and
falls back to remember-me.

---

## Tunables

### `*remember-me-cookie-key*`

Default `"clauth.remember-me"`. The cookie name.

### `*remember-me-ttl-seconds*`

Default 14 days. Match this to your security stance:

- Shorter (e.g. 7 days) for sensitive apps: users re-log in
  more often.
- Longer (e.g. 90 days) for low-stakes apps with strong
  per-device revocation: convenience wins.

The DB row's `expires_at` is set from
`*session-token-validity-seconds*` (also default 14 days). If
you make the cookie lifetime longer than the DB row's, the
cookie outlives the row and the remember-me silently no-ops
after the row expires. That's not a bug, but it's worth knowing
— keep them roughly aligned.

### `*remember-me-context*`

Now an alias of `*session-context*` (`"session"`). Kept exported
for backward compat. Don't reach for it; the remember-me cookie
uses the same context as the session.

---

## Snippets

**Conditional remember-me from a checkbox:**

```lisp
(defun login-with-or-without-remember (conn user remember-p)
  (if remember-p
      (clauth:login-with-remember-me conn user *repo* 'auth-token)
      (clauth:login                 conn user :repo *repo*
                                          :token-schema 'auth-token)))
```

**Logging out everywhere — including remember-me on this
device:**

```lisp
(defun logout-everywhere (conn)
  (let ((uid (getf (clauth:current-user conn) :id)))
    (when uid
      (clauth:logout-all-sessions *repo* 'user 'auth-token uid))
    (clauth:logout conn :repo *repo* :token-schema 'auth-token)))
```

`logout-all-sessions` purges every token row for the user;
`logout` then clears the current device's cookies (including
the remember-me).

**Custom max-age** (e.g. for a public-kiosk-friendly variant):

```lisp
(clauth:login-with-remember-me conn user *repo* 'auth-token
                                :ttl-seconds (* 60 60 8))   ; 8 hours
```

The DB row still uses `*session-token-validity-seconds*`. If you
need a shorter row lifetime too, bind the parameter:

```lisp
(let ((clauth:*session-token-validity-seconds* (* 60 60 8)))
  (clauth:login-with-remember-me conn user *repo* 'auth-token
                                  :ttl-seconds (* 60 60 8)))
```

---

## Gotchas

- **The cookies share a raw token.** A leak of either cookie is
  equivalent. Treat both as session credentials. Don't log
  them. Set `HttpOnly` (the default) so JS can't read them.
- **Remember-me extends the auth_tokens row TTL implicitly.**
  Each `load-current-user-or-remember-me` invocation might
  reissue (at half-life) — so a remember-me user effectively has
  rolling re-issuance. Force-logout still works (delete the row).
- **`:secure nil` is for development.** Production-over-HTTPS
  must set `:secure t`. Otherwise a network-MITM can read the
  cookie even on the user's "secure" page if any sub-resource is
  loaded over plain HTTP.
- **Don't put a remember-me on a shared / kiosk device.** The
  cookie persists across users on the same browser profile. The
  UI is responsible for the "trust this device" checkbox; clauth
  honors whatever the caller passes.
- **A revoked remember-me clears itself on next request.** The
  fallback path in `load-current-user-or-remember-me` calls
  `clear-remember-me-cookie` when the token lookup misses, so a
  stale cookie disappears on its first read. No user action
  needed.
