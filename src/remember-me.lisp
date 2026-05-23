(in-package #:clauth)

;;; Remember-me cookie — survive the session cookie for a long-lived
;;; "stay signed in" experience. Reuses the auth_tokens table from
;;; api-token.lisp with a distinct context, so a remember-me cookie
;;; cannot be smuggled in as an API bearer or vice versa.
;;;
;;; The cookie carries the RAW token; the DB only stores SHA-256(raw).
;;; Cookie defaults are aggressive: HttpOnly, Secure (HTTPS),
;;; SameSite=Lax. Override per-call if you genuinely need different.
;;;
;;; SameSite=Lax matches Phoenix gen.auth, but **Lax does not replace
;;; CSRF tokens**: a top-level GET from an attacker-controlled site
;;; still ships the cookie. Never mutate state on GET, and keep
;;; lack-middleware-csrf in front of POST/PUT/DELETE handlers.

(defvar *remember-me-cookie-key* "clauth.remember-me")
(defvar *remember-me-ttl-seconds* (* 60 60 24 60)   ; 60 days
  "Lifetime of a remember-me token + its cookie.")
(defvar *remember-me-context* "remember-me"
  "Token-row :context value separating remember-me from API tokens.")

(defun login-with-remember-me (conn user repo token-schema
                               &key (ttl-seconds *remember-me-ttl-seconds*)
                                    (secure t))
  "Log in + mint a remember-me token + set its cookie. Call from the
login controller when the user checked the 'remember me' box.

SECURE defaults to T (cookie only over HTTPS). Set NIL for dev over
plain HTTP, but never in production."
  (let ((raw (nth-value 0 (create-token repo token-schema user
                                        :context *remember-me-context*
                                        :expires-in ttl-seconds))))
    (clug:put-resp-cookie
     (login conn user)
     *remember-me-cookie-key* raw
     :max-age ttl-seconds
     :http-only t
     :secure secure
     :same-site :lax)))

(defun clear-remember-me-cookie (conn)
  "Set an expiring remember-me cookie so the browser drops it on the
next response. Doesn't pass :SECURE because browsers identify cookies
by name+path+domain and the expiring directive itself needs no
attribute matching."
  (clug:put-resp-cookie conn *remember-me-cookie-key* ""
                        :max-age 0
                        :http-only t :same-site :lax))

(defun revoke-remember-me (conn repo token-schema)
  "Server-side counterpart of CLEAR-REMEMBER-ME-COOKIE: look up the
token by the cookie value, delete its row in auth_tokens, and clear
the client cookie. Idempotent when the cookie is absent or stale."
  (multiple-value-bind (cookies c) (clug:fetch-req-cookies conn)
    (let* ((raw (cdr (assoc *remember-me-cookie-key* cookies :test #'equal)))
           (row (and raw (find-and-validate-token repo token-schema raw
                                                  :context *remember-me-context*))))
      (when row (revoke-token repo token-schema (getf row :id))))
    (clear-remember-me-cookie c)))

(defun load-current-user-or-remember-me (repo
                                         &key user-schema token-schema)
  "Plug: load the user from the cookie session first; if no logged-in
user, fall back to the remember-me cookie. On a successful remember-me
load, RE-ESTABLISH the session (calling login) so subsequent requests
take the fast path again — and so session-version + lockout checks
apply.

Place this in lieu of LOAD-CURRENT-USER when remember-me is enabled."
  (let ((session-loader (load-current-user repo user-schema)))
    (lambda (conn)
      (let ((c (funcall session-loader conn)))
        (if (current-user c)
            c
            (try-remember-me-load c repo user-schema token-schema))))))

(defun try-remember-me-load (conn repo user-schema token-schema)
  "Inspect the remember-me cookie. If valid, load the user and
re-establish a session. If absent / expired / version-stale, return
the conn unchanged."
  (multiple-value-bind (cookies c) (clug:fetch-req-cookies conn)
    (let* ((raw (cdr (assoc *remember-me-cookie-key* cookies :test #'equal)))
           (token (and raw
                       (find-and-validate-token
                        repo token-schema raw
                        :context *remember-me-context*)))
           (user (and token (clecto:repo-get
                             repo user-schema (getf token :user-id)))))
      (cond
        ((or (null token) (null user)) c)
        ((token-session-version-stale-p token user)
         ;; Credentials changed since this remember-me was issued; drop
         ;; the row and the cookie so the browser stops sending it.
         (revoke-token repo token-schema (getf token :id))
         (clear-remember-me-cookie c))
        (t
         (clug:assign (login c user) *current-user-key* user))))))
