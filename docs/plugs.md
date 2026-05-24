# plugs

Conn-level helpers that gate routes on the authentication state.
Each is a [clug](https://github.com/gr8distance/clug) plug — a
function `(conn) → conn`. They compose with `pipeline` and
`scope` like any other plug.

This page covers the route-gating side. The "establish a session"
side lives in [sessions](./sessions.md).

---

## `(load-current-user REPO USER-SCHEMA &key token-schema) → PLUG`

The workhorse. Returns a plug that:

1. Reads the raw session token from the cookie session.
2. Looks up the matching `auth_tokens` row.
3. Loads the user record.
4. Assigns it on the conn as `:current-user`.
5. Reissues the token if it's past half-life.

Silent on miss — if there's no valid session, the conn is
returned unchanged. The next plug (`require-auth`) decides
whether that's an error.

```lisp
(defun authed-pipe ()
  (list (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
        #'clauth:require-auth))

(clug:defroutes routes
  (:get  "/"          'home)
  (clug:scope "/me"
    :pipe-through (authed-pipe)
    (:get  ""            'me)
    (:post "/password"   'change-password)))
```

See [sessions](./sessions.md) for the lookup details (token
reissue half-life, legacy mode, etc.).

---

## `(require-auth CONN &key redirect-to flash) → CONN'`

Halt the request if there's no `:current-user` attached. Two
modes:

### JSON mode (default)

Returns 401 with `application/json` body
`{"error":"unauthorized"}`:

```lisp
(clug:scope "/api"
  :pipe-through (list (clauth:load-current-user *repo* 'user
                                                :token-schema 'auth-token)
                      #'clauth:require-auth)
  (:get "/me" 'api-me))
```

### Redirect mode

```lisp
(clauth:require-auth conn
                     :redirect-to "/login"
                     :flash "Please sign in to continue.")
```

Halts with `302 Location: /login`. Also:

- Captures the original GET path under
  `*session-return-to-key*` (`:user-return-to`). The post-login
  flow's `log-in-and-redirect` reads it.
- Writes FLASH (if supplied) under `:flash` in the session for
  the next page's UI to render.

For HTML routes, prefer redirect mode — a JSON 401 in the
browser is opaque. For JSON APIs, the default is right: a 401
lets the SPA decide what to do.

Helper to wire both into the pipeline:

```lisp
(defun require-auth-redirect (conn)
  (clauth:require-auth conn :redirect-to "/login"))

(clug:scope "/dashboard"
  :pipe-through (list (clauth:load-current-user ...)
                      #'require-auth-redirect)
  ...)
```

(The plug protocol expects `(conn) → conn`, so we wrap the
`(conn &key)` call in a single-argument lambda / defun. Same
pattern for any of these helpers that take keyword args.)

---

## `(redirect-if-authenticated &key redirect-to) → PLUG`

Inverse of `require-auth`: if the user **is** logged in, bounce
them away from this route. Standard guard on login / register
pages.

```lisp
(clug:defroutes routes
  (clug:scope "/sessions"
    :pipe-through (list (clauth:load-current-user ...)
                        (clauth:redirect-if-authenticated :redirect-to "/dashboard"))
    (:get  "/new"     'login-form)
    (:post ""         'login-submit)))
```

Default REDIRECT-TO is `"/"`. Pass whatever the "you're already
in" landing page is.

Note: this is a **higher-order** plug — calling it returns the
plug. The other helpers on this page are plugs themselves.

---

## `(require-role ALLOWED &key reader) → PLUG`

Higher-order plug for role-based authorization. Halts with 403
unless the current user's role is in ALLOWED.

```lisp
(clug:scope "/admin"
  :pipe-through (list (clauth:load-current-user ...)
                      #'clauth:require-auth
                      (clauth:require-role "admin"))
  (:get "" 'admin-dashboard))
```

ALLOWED is a single role value or a list:

```lisp
(clauth:require-role "admin")
(clauth:require-role '("admin" "moderator"))
```

The plug:

- Halts with **401** when no `:current-user` is attached (a
  defensive default — usually `require-auth` already ran).
- Halts with **403** when the role doesn't match.
- Passes the conn through otherwise.

### Custom `:reader`

Default reader is `(getf user :role)`. Override for multi-role
users / join tables / external authz:

```lisp
(defun multi-role-reader (user)
  (getf user :roles))   ; a list like '("admin" "billing")

(clauth:require-role '("admin" "billing-admin")
                     :reader #'multi-role-reader)
```

When `:reader` returns a list, the check passes if **any**
element of that list is in ALLOWED. `NIL` roles never match.

If the reader signals an error, the plug halts with 403 (fails
**closed**) rather than 500-ing — a misconfigured reader doesn't
accidentally grant access.

### `NIL` ALLOWED is rejected

```lisp
(clauth:require-role nil)
;; → error: require-role: ALLOWED is empty. Pass at least one role.
```

A deny-all "role" is almost always a typo (an unbound config
variable). If you genuinely want one, write a one-line plug
that halts unconditionally — but you probably don't.

---

## `(log-in-and-redirect CONN USER &key repo token-schema default-path) → CONN'`

Establish a session for USER and redirect to the captured
return-to (or DEFAULT-PATH).

```lisp
(defun login-submit (conn)
  (let ((user (clauth:authenticate *repo* 'user ...)))
    (if user
        (clauth:log-in-and-redirect
         conn user
         :repo *repo* :token-schema 'auth-token
         :default-path "/dashboard")
        (render-login-error conn))))
```

What it does:

1. Read `:user-return-to` from the session (set by
   `require-auth` in redirect mode).
2. Validate the return-to path with `safe-internal-path-p`.
3. Call `login` to mint the session token + rotate session id.
4. Clear `:user-return-to` from the session.
5. Halt with `302 Location: <target>`.

### Open-redirect defense

`safe-internal-path-p` accepts only same-origin relative paths:

- Must start with exactly one `/`
- Second character must not be `/` or `\`

This blocks:

- Protocol-relative URLs (`//evil.com`) — would otherwise
  redirect off-site
- Backslash-bypass (`/\evil.com`) — some browsers normalise `\`
  to `/`

An unsafe return-to value (e.g. one planted via a manipulated
referer or query string) silently falls back to DEFAULT-PATH.

`mix phx.gen.auth` relies on Phoenix's verified-routes for the
same guarantee; clauth checks explicitly because we don't have a
route compiler.

---

## `(maybe-store-return-to CONN) → CONN'`

Called internally by `require-auth` when redirecting. Stores
the original path so the post-login flow can return the user.

**Only stores GET paths**:

- POST / PUT / DELETE are skipped because (a) they typically
  can't be replayed safely after login, and (b) a captured POST
  URL is a target for CSRF redirection.
- Query string is included so deep links like
  `/dashboard?tab=billing` survive the round-trip.

You wouldn't call this directly unless you're building a custom
auth-required flow that doesn't use `require-auth`.

---

## Putting it together

A typical pipeline for a route that requires authentication:

```lisp
(clug:scope "/me"
  :pipe-through
  (list
   (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
   #'clauth:require-auth)
  (:get "/" 'me))
```

For role-gated routes:

```lisp
(clug:scope "/admin"
  :pipe-through
  (list
   (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
   #'clauth:require-auth
   (clauth:require-role "admin"))
  (:get "/users" 'admin-users))
```

For HTML login / register pages where you want logged-in users
redirected away:

```lisp
(clug:scope "/sessions"
  :pipe-through
  (list
   (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
   (clauth:redirect-if-authenticated :redirect-to "/dashboard"))
  (:get  "/new"  'login-form)
  (:post ""      'login-submit))
```

The patterns compose without surprise. Plug ordering matters
(load before require; require before role-check); within those
constraints, you can slot in whatever else you need —
`tag-request-id`, telemetry, custom middleware.

---

## Tunables

### `*session-return-to-key*`

Default `:user-return-to`. The session key under which the
return-to path is stashed.

If you have an existing app that already uses this key for
something else, set it to a different keyword before mounting
your routes.

### `*current-user-key*`

Internal default `:current-user`. Not exported as a special;
hard-coded in `load-current-user` and `current-user`. If you
need a different key (because something else in your app already
uses `:current-user`), there's no public knob — refactor your
naming or wrap the plugs.

---

## Snippets

**JSON API auth — both 401 and `:current-user` on the conn:**

```lisp
(clug:scope "/api"
  :pipe-through
  (list
   (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
   #'clauth:require-auth)            ; JSON 401 on miss
  (:get "/me" 'api-me))

(defun api-me (conn)
  (let ((u (clauth:current-user conn)))
    (render-json conn 200 (list :id (getf u :id) :email (getf u :email)))))
```

**HTML auth with redirect:**

```lisp
(defun require-login-redirect (conn)
  (clauth:require-auth conn
                       :redirect-to "/login"
                       :flash "Please sign in to continue."))

(clug:scope "/account"
  :pipe-through
  (list (clauth:load-current-user *repo* 'user :token-schema 'auth-token)
        #'require-login-redirect)
  (:get "" 'account-home))
```

**Multi-role check using a custom reader:**

```lisp
(defun user-roles (user)
  (clecto:repo-all
   *repo*
   (-> (from :user-roles)
       (where `(= :user-id ,(getf user :id)))
       (select :role))))

(clauth:require-role '("billing" "admin")
                     :reader #'user-roles)
```

**Skipping require-auth for some HTTP verbs** (e.g. `OPTIONS`
preflight requests for CORS) — clug auto-handles `OPTIONS` so
you typically don't need this, but if you do:

```lisp
(defun require-auth-except-options (conn)
  (if (eq (clug:conn-method conn) :options)
      conn
      (clauth:require-auth conn)))
```

---

## Gotchas

- **Always pair `load-current-user` with `require-auth`.** The
  loader is silent on miss — without `require-auth` your "protected"
  route runs with `:current-user` set to `NIL` and your handler
  thinks "no user logged in" is normal.
- **Plug order matters.** `load → auth → role`. If you swap
  any pair the failure mode is wrong (401 before load means
  always 401; role before auth means always 403 for anonymous).
- **`require-auth` with `:redirect-to` calls
  `maybe-store-return-to` for you.** Don't call it manually
  unless you're not using `require-auth`.
- **`safe-internal-path-p` blocks `//evil.com`.** If you have a
  legitimate use case for off-site redirects from your login
  flow (you probably don't), you'll need a separate code path
  that doesn't go through `log-in-and-redirect`.
