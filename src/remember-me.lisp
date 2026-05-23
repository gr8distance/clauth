(in-package #:clauth)

;;; Remember-me cookie — long-lived client-side persistence of the
;;; SAME session token already in clug/session. Mirrors Phoenix gen.auth:
;;; one auth_tokens row (context "session"), two cookies carrying the
;;; same raw value. The remember-me cookie just outlives the browser
;;; session.
;;;
;;; SameSite=Lax matches phx.gen.auth. Lax doesn't replace CSRF tokens —
;;; never mutate state on GET; keep CSRF middleware in front of writes.

(defvar *remember-me-cookie-key* "clauth.remember-me")
(defvar *remember-me-ttl-seconds* (* 14 24 60 60)   ; 14 days, matches Phoenix
  "Lifetime of the remember-me cookie. Phoenix's @max_cookie_age_in_days.")

;;; Legacy: old code used a separate context for remember-me tokens.
;;; Kept exported for backward compat; new code uses *session-context*.
(defvar *remember-me-context* "session"
  "Now an alias of *SESSION-CONTEXT*. Phoenix uses one context for both
session and remember-me — the cookie just persists longer.")

(defun login-with-remember-me (conn user repo token-schema
                               &key (ttl-seconds *remember-me-ttl-seconds*)
                                    (secure t))
  "Log the user in AND write a remember-me cookie carrying the same
session token. Phoenix-style: one auth_tokens row, two cookies."
  (let* ((c (login conn user :repo repo :token-schema token-schema))
         (token (clug:get-session-value c *session-token-key*)))
    (clug:put-resp-cookie
     c *remember-me-cookie-key* token
     :max-age ttl-seconds
     :http-only t
     :secure secure
     :same-site :lax)))

(defun clear-remember-me-cookie (conn)
  "Set an expiring remember-me cookie so the browser drops it. Browsers
identify cookies by name+path+domain so :SECURE / :SAME-SITE on the
expiring directive aren't needed."
  (clug:put-resp-cookie conn *remember-me-cookie-key* ""
                        :max-age 0
                        :http-only t :same-site :lax))

(defun revoke-remember-me (conn repo token-schema)
  "Server-side counterpart of CLEAR-REMEMBER-ME-COOKIE: when the request
carries a remember-me cookie, delete the row it points at AND clear the
response cookie. Idempotent."
  (multiple-value-bind (cookies c) (clug:fetch-req-cookies conn)
    (let ((raw (cdr (assoc *remember-me-cookie-key* cookies :test #'equal))))
      (when raw (delete-session-token repo token-schema raw)))
    (clear-remember-me-cookie c)))

(defun load-current-user-or-remember-me (repo
                                         &key user-schema token-schema)
  "Plug: load current user from session first; on a miss, try the
remember-me cookie. Both cookies carry the same session token so the
validation path is identical — the remember-me cookie just persists
across browser sessions."
  (let ((session-loader (load-current-user repo user-schema
                                           :token-schema token-schema)))
    (lambda (conn)
      (let ((c (funcall session-loader conn)))
        (if (current-user c)
            c
            (try-remember-me-load c repo user-schema token-schema))))))

(defun try-remember-me-load (conn repo user-schema token-schema)
  "Inspect the remember-me cookie. If it carries a valid session token,
load the user, re-establish the session cookie, and return the conn
with :current-user attached. Otherwise return the conn untouched."
  (multiple-value-bind (cookies c) (clug:fetch-req-cookies conn)
    (let ((raw (cdr (assoc *remember-me-cookie-key* cookies :test #'equal))))
      (multiple-value-bind (user record)
          (and raw
               (load-user-by-session-token repo user-schema token-schema raw))
        (declare (ignore record))
        (cond
          ((null user)
           (if raw (clear-remember-me-cookie c) c))
          (t
           (let ((c2 (clug:put-session-value c *session-token-key* raw)))
             (clug:assign c2 *current-user-key* user))))))))
