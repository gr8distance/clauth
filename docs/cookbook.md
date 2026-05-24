# Cookbook

End-to-end auth patterns with all the pieces wired together.

---

## A full JSON auth API

Registration + email confirmation + login + logout + password
reset + magic link + role-gated admin.

```lisp
(defpackage #:myapi
  (:use #:cl)
  (:shadowing-import-from #:clecto #:union))
(in-package #:myapi)

(ql:quickload '(:clack :clack-handler-hunchentoot
                :clug :clug/parsers :clug/errors :clug/session
                :clecto :clauth :clauth/mail))

;; --- repo + mailer ---

(defparameter *repo* (clecto:make-repo (clecto:make-sqlite-adapter ":memory:")))
(defparameter *mailer* (cliam:make-local-adapter #P"/tmp/myapi-mail/"))
(setf clauth:*from-address* '("MyAPI" . "noreply@example.com"))

;; --- schemas ---

(clecto:defschema user "users"
  (:id :integer :primary-key t)
  ,@(clauth:auth-fields)
  (:role :string)
  (:timestamps))

(clecto:defschema auth-token "auth_tokens"
  (:id :integer :primary-key t)
  ,@(clauth:auth-token-fields)
  (:timestamps))

;; --- handlers ---

(defun render-error (conn status msg)
  (clug:render-json conn status (clug:obj "error" msg)))

(defun stringify-errors (cs)
  (let ((h (make-hash-table :test 'equal)))
    (dolist (pair (clecto:traverse-errors cs))
      (setf (gethash (string-downcase (string (car pair))) h)
            (cdr pair)))
    h))

(defun register-handler (conn)
  (let ((a (clug:get-assign conn :json-body)))
    (multiple-value-bind (user err)
        (clecto:repo-insert
         *repo*
         (clauth:register-changeset 'user
                                    (list :email (gethash "email" a)
                                          :password (gethash "password" a)
                                          :password-confirmation
                                          (gethash "password_confirmation" a))))
      (cond
        (err (clug:render-json conn 422 (clug:obj "errors" (stringify-errors err))))
        (user
         (clauth:deliver-confirmation-instructions
          :repo *repo* :token-schema 'auth-token
          :user user
          :url-builder (lambda (raw)
                         (format nil "http://localhost:5000/confirm/~a" raw))
          :mailer *mailer*)
         (clug:render-json conn 200 (clug:obj "id" (getf user :id))))))))

(defun confirm-handler (conn)
  (let ((raw (getf (clug:conn-params conn) :token)))
    (multiple-value-bind (user err)
        (clauth:confirm-user! :repo *repo*
                              :user-schema 'user
                              :token-schema 'auth-token
                              :raw-token raw)
      (case err
        ((nil)     (clug:render-json conn 200 (clug:obj "ok" t)))
        (:invalid  (render-error conn 400 "invalid token"))))))

(defun login-handler (conn)
  (let ((a (clug:get-assign conn :json-body)))
    (multiple-value-bind (user reason)
        (clauth:authenticate-with-lockout
         *repo* 'user
         (gethash "email" a) (gethash "password" a))
      (case reason
        ((nil) (let ((c (clauth:login conn user
                                      :repo *repo*
                                      :token-schema 'auth-token)))
                 (clug:render-json c 200 (clug:obj "id" (getf user :id)))))
        (:locked          (render-error conn 423 "locked"))
        (:wrong-password  (render-error conn 401 "invalid credentials"))))))

(defun logout-handler (conn)
  (clug:render-json
   (clauth:logout conn :repo *repo* :token-schema 'auth-token)
   200 (clug:obj "ok" t)))

(defun me-handler (conn)
  (let ((u (clauth:current-user conn)))
    (clug:render-json conn 200
                      (clug:obj "id" (getf u :id)
                                "email" (getf u :email)
                                "role" (or (getf u :role) "user")))))

(defun admin-handler (conn)
  (clug:render-json conn 200 (clug:obj "ok" t "secret" "...")))

;; --- routes ---

(clug:defroutes routes
  (:post "/register"          'register-handler)
  (:get  "/confirm/:token"    'confirm-handler)
  (:post "/login"             'login-handler)
  (:post "/logout"            'logout-handler)

  (clug:scope "/me"
    :pipe-through (list (clauth:load-current-user *repo* 'user
                                                  :token-schema 'auth-token)
                        #'clauth:require-auth)
    (:get "" 'me-handler))

  (clug:scope "/admin"
    :pipe-through (list (clauth:load-current-user *repo* 'user
                                                  :token-schema 'auth-token)
                        #'clauth:require-auth
                        (clauth:require-role "admin"))
    (:get "" 'admin-handler)))

;; --- app assembly ---

(defparameter *app*
  (clug:with-session
   (lambda (env)
     (let ((conn (clug::env->conn env)))
       (clug::conn->clack
        (funcall (clug::router-as-plug routes)
                 (handler-case (clug:parse-json conn)
                   (error () conn))))))
   :store (clug:make-memory-store)
   :secure nil))

(clack:clackup *app* :port 5000)
```

This is essentially what [onogoro](https://github.com/gr8distance/onogoro)
ships — pluck out the handler logic for your own app, keep the
wiring shape.

---

## HTML login + redirect with return-to

```lisp
(defun login-form (conn)
  (clug:put-resp conn 200
                 "<form method=post>
                    <input name=email>
                    <input name=password type=password>
                    <button>Sign in</button>
                  </form>"
                 (list "content-type" "text/html; charset=utf-8")))

(defun login-submit (conn)
  (let ((a (parse-form-attrs conn)))
    (multiple-value-bind (user reason)
        (clauth:authenticate-with-lockout
         *repo* 'user (getf a :email) (getf a :password))
      (case reason
        ((nil)            (clauth:log-in-and-redirect
                           conn user
                           :repo *repo* :token-schema 'auth-token
                           :default-path "/dashboard"))
        (:locked          (render-html-error conn 423 "Locked"))
        (:wrong-password  (render-html-error conn 401 "Invalid credentials"))))))

(defun require-login-redirect (conn)
  (clauth:require-auth conn :redirect-to "/login"
                            :flash "Please sign in."))

(clug:defroutes routes
  (:get  "/"             'home)
  (:get  "/login"        'login-form)
  (:post "/login"        'login-submit)

  (clug:scope "/dashboard"
    :pipe-through (list (clauth:load-current-user *repo* 'user
                                                  :token-schema 'auth-token)
                        #'require-login-redirect)
    (:get "" 'dashboard)))
```

`require-auth :redirect-to` stashes the GET path as
`:user-return-to` on the session; `log-in-and-redirect` reads
it and bounces the user back to where they were trying to go.

---

## Remember-me with a checkbox

```lisp
(defun login-submit (conn)
  (let ((a (parse-form-attrs conn)))
    (multiple-value-bind (user reason)
        (clauth:authenticate *repo* 'user (getf a :email) (getf a :password))
      (cond
        ((null user) (render-html-error conn 401 "Invalid credentials"))
        (t
         (let ((c (if (getf a :remember-me)
                      (clauth:login-with-remember-me conn user *repo* 'auth-token)
                      (clauth:login                 conn user
                                                     :repo *repo*
                                                     :token-schema 'auth-token))))
           (clug:put-resp c 302 "" (list "location" "/dashboard"))))))))

;; load plug includes remember-me fallback
(defparameter *load-user*
  (clauth:load-current-user-or-remember-me
   *repo* :user-schema 'user :token-schema 'auth-token))
```

---

## Force-logout after a sensitive change

After a password or email change, every session for that user
should be invalidated. The `update-password!` / `update-email!`
helpers do that automatically:

```lisp
(defun change-password-handler (conn)
  (let ((a (clug:get-assign conn :json-body))
        (u (clauth:current-user conn)))
    (multiple-value-bind (rec err)
        (clauth:update-password!
         *repo* 'user 'auth-token u
         (list :current-password (gethash "current_password" a)
               :password (gethash "password" a)
               :password-confirmation (gethash "password_confirmation" a)))
      (cond
        (err (clug:render-json conn 422 (clug:obj "errors" (stringify-errors err))))
        (t
         ;; All sessions (including this one) were just nuked.
         ;; Re-login on the calling device.
         (let ((c (clauth:login conn rec
                                :repo *repo* :token-schema 'auth-token)))
           (clug:render-json c 200 (clug:obj "ok" t))))))))
```

The `(clauth:login ...)` after a successful `update-password!`
is the "stay logged in on this device" pattern. Without it the
user gets bounced to the login page from the very device they
were on.

---

## Magic-link login on a marketing email click

```lisp
;; Step 1: request — typically wired to an email-only form
(defun magic-request (conn)
  (let ((a (clug:get-assign conn :json-body)))
    (when-let ((user (clecto:repo-get-by
                      *repo* 'user
                      (list :email (gethash "email" a)))))
      (clauth:deliver-magic-link
       :repo *repo* :token-schema 'auth-token
       :user user
       :url-builder (lambda (raw)
                      (format nil "https://app.example.com/magic/~a" raw))
       :mailer *mailer*))
    ;; Always 200 — don't leak user existence
    (clug:render-json conn 200 (clug:obj "ok" t))))

;; Step 2: consume — usually a GET so a direct click works
(defun magic-consume (conn)
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
               :repo *repo* :token-schema 'auth-token
               :default-path "/welcome"))
        (t    (render-html-error conn 400 "Link expired or invalid"))))))
```

---

## Bulk admin: revoke all sessions for an org

```lisp
(defun revoke-all-sessions-for-org (org-id)
  (let ((user-ids
          (mapcar (lambda (r) (getf r :id))
                  (clecto:repo-all *repo*
                                   (-> (clecto:from :users)
                                       (clecto:where `(= :org-id ,org-id))
                                       (clecto:select :id))))))
    (dolist (uid user-ids)
      (clauth:logout-all-sessions *repo* 'user 'auth-token uid))))
```

Use after an org-wide policy change or a suspected breach. Each
user is logged out everywhere on their next request.

---

## "Show me my devices" panel

A view showing every active session for the current user:

```lisp
(defun list-sessions (user-id)
  (clecto:repo-all
   *repo*
   (-> (clecto:from :auth-tokens)
       (clecto:where `(= :user-id ,user-id))
       (clecto:where `(= :context "session"))
       (clecto:where `(>= :expires-at ,(clecto:now-utc-datetime)))
       (clecto:order-by '((:desc :inserted-at))))))

(defun revoke-session (token-id)
  (clauth:revoke-token *repo* 'auth-token token-id))
```

Show `:inserted-at`, `:authenticated-at`, `:expires-at` per row;
let the user revoke individual ones. Don't show `:token-hash` —
not a credential, but no value to the user either.

---

## Email change with confirmation on the new address

```lisp
;; Step 1: request change (gated by current password)
(defun request-email-change (conn)
  (let* ((a  (clug:get-assign conn :json-body))
         (u  (clauth:current-user conn))
         (current-pw (gethash "current_password" a))
         (new-email  (gethash "new_email" a)))
    (cond
      ((null (clauth:authenticate *repo* 'user (getf u :email) current-pw))
       (render-error conn 401 "Wrong password"))
      ((not (clauth:valid-email-shape-p new-email))
       (render-error conn 422 "Bad email"))
      (t
       (clauth:deliver-change-email-instructions
        :repo *repo* :token-schema 'auth-token
        :user u :new-email new-email
        :url-builder (lambda (raw)
                       (format nil "https://app/change-email/~a" raw))
        :mailer *mailer*)
       (clug:render-json conn 200
                         (clug:obj "ok" t "sent_to" new-email))))))

;; Step 2: apply on link click
(defun apply-email-change (conn)
  (let ((raw (getf (clug:conn-params conn) :token)))
    (multiple-value-bind (user err)
        (clauth:apply-email-change!
         :repo *repo*
         :user-schema 'user
         :token-schema 'auth-token
         :raw-token raw)
      (case err
        ((nil)         (clug:render-json conn 200 (clug:obj "ok" t)))
        (:invalid      (render-error conn 400 "Invalid or expired"))
        (:email-taken  (render-error conn 409 "Already taken"))))))
```

After success, the user is logged out everywhere (the swap
purges tokens). They log in fresh with the new email.

---

## DB-backed audit log

```lisp
(clecto:defschema auth-event "auth_events"
  (:id :integer :primary-key t)
  ,@(clauth:auth-event-fields)
  (:timestamps))

;; (apply the SCHEMA SQL — see clauth/docs/schema.md)

(setf clauth:*auth-telemetry*
      (lambda (event payload)
        (clecto:repo-insert
         *repo*
         (clecto:cast
          'auth-event
          (list :event   (string event)
                :user-id (getf payload :user-id)
                :email   (getf payload :email)
                :reason  (when-let ((r (getf payload :reason)))
                           (string r)))
          '(:event :user-id :email :reason)))))
```

For a real audit log you'd also capture `:ip` and `:user-agent`.
Set them on a dynamic variable at the top of each request (or
in a custom plug); read them in the telemetry callback.

---

## Production startup checklist

```lisp
(defun start-app (&key port db-url smtp-cfg)
  (setf clauth:*from-address* '("App" . "noreply@example.com"))

  ;; Argon2 cost: pick what your machine can afford
  (setf clauth:*argon2-block-count* 16384)    ; 16 MiB
  (setf clauth:*argon2-iterations*  3)

  ;; Lockout: tune for your audience
  (setf clauth:*lockout-max-attempts*       8)
  (setf clauth:*lockout-duration-seconds* 1800)   ; 30 min

  ;; Telemetry sink (queue, don't block)
  (setf clauth:*auth-telemetry* #'enqueue-audit-event)

  ;; Repo + mailer
  (setf *repo* (clecto:make-repo (make-pg-adapter db-url)))
  (setf *mailer* (cliam:make-smtp-adapter ...))

  ;; clecto telemetry: log slow queries
  (setf clecto:*telemetry* #'log-slow-queries)

  ;; Mount the app
  (start-server :port port))
```

Variables you should review per environment:

- `*argon2-block-count*` / `*argon2-iterations*` — cost ramp
- `*lockout-max-attempts*` / `*lockout-duration-seconds*`
- `*session-token-validity-seconds*` (default 14 days) and
  `*session-token-reissue-after-seconds*` (default 7 days)
- `*reset-password-validity-seconds*` (default 15 minutes)
- `*magic-link-validity-seconds*` (default 15 minutes)
- `*from-address*`

---

## Anti-patterns

A few things to **not** do:

- **Don't return 404 from /forgot-password when the email
  isn't found.** Enumeration via status code defeats the
  privacy you'd otherwise get.
- **Don't store the raw session token in your DB for "easier
  debugging."** The hash is the storage form; the raw value
  exists for one moment.
- **Don't log raw cookie values / authorization headers** at
  any verbosity. They're credentials for whatever window the
  log is retained.
- **Don't pass the user ID to `login`.** Pass the loaded
  record. The ID-only error message is there because that's a
  common bug.
- **Don't reuse `password` and `password_confirmation` as
  non-virtual columns.** Declare them `:virtual t` in your
  schema or they leak to the DB.
- **Don't share a single auth_tokens row across users.** Bind
  to user_id at create time and let the DB index do its job.
