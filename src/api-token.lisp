(in-package #:clauth)

;;; API tokens — bearer auth, separate from cookie sessions.
;;;
;;; Schema: the user defines a clecto schema (typical name AUTH-TOKEN)
;;; with the fields we touch:
;;;
;;;   (clecto:defschema auth-token "auth_tokens"
;;;     (:id         :integer :primary-key t)
;;;     (:user-id    :integer)
;;;     (:token-hash :string)
;;;     (:context    :string)
;;;     (:expires-at :naive-datetime)
;;;     (:timestamps))
;;;
;;; A token-hash column-name unique index is REQUIRED — without it the
;;; lookup performance and the 'no duplicate token' invariant both
;;; collapse. CREATE UNIQUE INDEX in your migration.

(defun auth-token-fields ()
  "Splice into a clecto schema body to declare the auth-token table.
:SESSION-VERSION mirrors the user's value at mint time so a credential
change (which bumps the user's version) instantly invalidates every
existing token — see LOAD-CURRENT-USER-FROM-BEARER for the check."
  '((:user-id        :integer)
    (:token-hash     :string)
    (:context        :string)
    (:session-version :integer)
    (:expires-at     :naive-datetime)))

(defvar *default-api-token-ttl-seconds* (* 60 60 24 30)
  "Default lifetime for API tokens. 30 days.")

(defun create-token (repo token-schema user
                     &key (context "api")
                          (expires-in *default-api-token-ttl-seconds*))
  "Mint a new token bound to USER. USER must be a loaded record (a plist
with at least :ID and ideally :SESSION-VERSION) — we stamp the user's
current session-version onto the token so credential changes invalidate
it. Pass a freshly-loaded record; don't recycle a stale one.

Returns (values raw-token record). Hand RAW-TOKEN to the user once
(never re-display it); the DB only stores its SHA-256 hash. EXPIRES-IN
is in seconds; pass NIL for a non-expiring token (use sparingly)."
  (unless (consp user)
    (error "create-token requires a loaded user record (got ~s). ~
            Look it up with repo-get first." user))
  (let* ((user-id (or (getf user :id)
                      (error "create-token: user record has no :id")))
         (version (or (getf user :session-version) 0))
         (raw    (generate-token))
         (hash   (token-hash raw))
         (expiry (when expires-in
                   (universal-time-to-naive
                    (+ (get-universal-time) expires-in))))
         (cs (clecto:cast token-schema
                          (list :user-id user-id
                                :token-hash hash
                                :context context
                                :session-version version
                                :expires-at expiry)
                          '(:user-id :token-hash :context
                            :session-version :expires-at))))
    (multiple-value-bind (record err) (clecto:repo-insert repo cs)
      (when err (error "create-token: insert failed: ~a"
                       (clecto:cs-errors err)))
      (emit-auth-event :token-created
                       (list :user-id user-id :context context))
      (values raw record))))

(defun find-and-validate-token (repo token-schema raw-token
                                &key (context "api"))
  "Look up RAW-TOKEN by hash. Returns the token row when:
- a row exists with the matching hash,
- its :context equals CONTEXT,
- its :expires-at is in the future (or NIL).
Returns NIL otherwise — no timing oracle from this side because the
lookup is a direct hash-equality on a unique index."
  (let* ((schema (clecto::find-schema token-schema))
         (table  (clecto::intern-table schema))
         (hash   (token-hash raw-token))
         (row    (clecto:repo-one
                  repo
                  (clecto:where (clecto:from table)
                                (list '= :token-hash hash)))))
    (cond
      ((null row) nil)
      ((not (equal context (getf row :context))) nil)
      ((token-expired-p row) nil)
      (t row))))

(defun token-expired-p (token-row)
  ;; Expiry strings are minted by UNIVERSAL-TIME-TO-NAIVE in UTC, so
  ;; we compare against NOW-UTC-DATETIME to match.
  (let ((exp (getf token-row :expires-at)))
    (and exp (string< exp (clecto:now-utc-datetime)))))

(defun revoke-token (repo token-schema token-id)
  "Delete a token by its primary key."
  (clecto:repo-delete repo token-schema token-id))

(defun revoke-tokens-on-credential-change (repo token-schema user-id)
  "Convenience wrapper: drop every token row for USER-ID across all
contexts. Phoenix's contract on a password/email change is 'kill
every credential the prior password authenticated' — call this from
the controller that just ran change-password-changeset or
change-email-changeset.

The session-version check in LOAD-CURRENT-USER-FROM-BEARER already
makes existing tokens invalid; this helper purges the now-dead rows
so they don't accumulate in the DB."
  (revoke-all-tokens-for-user repo token-schema user-id))

(defun logout-all-sessions (repo user-schema token-schema user-id)
  "Force EVERY device this user is signed in on to log out on its next
request. Implementation:
  - bump :session-version on the user row (the version stamped on
    every existing cookie / bearer token now compares stale)
  - purge bearer/remember-me tokens from the DB so they stop taking
    up space

Use cases: 'log me out everywhere' button, panic 'my account was
hacked', admin-forced logout.

NOTE: the CALLING session is not killed — the conn handling this
request still sees the (now-stale) :session-version on its in-memory
session data. The next request from this user's browser will see the
bumped value and load-current-user will logout. Render a 'you've been
signed out everywhere — sign in again' page directly; the user will
hit re-login on their next action."
  (let* ((schema (clecto::find-schema user-schema))
         (table  (clecto::intern-table schema)))
    (clecto:repo-update-all
     repo
     (clecto:where (clecto:from table) (list '= :id user-id))
     (list :session-version
           (list :fragment "\"session_version\" + 1")))
    (revoke-all-tokens-for-user repo token-schema user-id)
    ;; "all" as a string for consistency with other :context values
    ;; ("api", "remember-me", "reset-password") that sinks see.
    (emit-auth-event :token-revoked (list :user-id user-id :context "all"))
    t))

(defun revoke-all-tokens-for-user (repo token-schema user-id
                                   &key (context nil context-supplied-p))
  "Delete every token row belonging to USER-ID. When CONTEXT is given,
only tokens of that context are removed — handy for 'log out my API
sessions but keep my remember-me cookie'."
  (let* ((schema (clecto::find-schema token-schema))
         (table  (clecto::intern-table schema))
         (where  (if context-supplied-p
                     `(and (= :user-id ,user-id) (= :context ,context))
                     `(= :user-id ,user-id))))
    (clecto:repo-delete-all
     repo (clecto:where (clecto:from table) where))))

;;; --- bearer plug ---

(defun parse-bearer (header)
  "Return the token portion of an Authorization: Bearer header, or NIL.
Strips spaces, tabs, CR, LF so a quoted-printable header doesn't slip
in a stray byte that turns a valid token into a non-match."
  (when (and header
             (>= (length header) 7)
             (string-equal "Bearer " (subseq header 0 7)))
    (string-trim '(#\Space #\Tab #\Return #\Newline)
                 (subseq header 7))))

(defun load-current-user-from-bearer (repo
                                      &key user-schema token-schema
                                           (context "api"))
  "Plug: read the Authorization header, validate the bearer token, load
the corresponding user, and attach it under *current-user-key*. No-op
when the header is absent, the token is invalid, the user no longer
exists, or the user's :session-version has advanced past the value
stamped onto the token (credential change elsewhere invalidates the
token). Pair with REQUIRE-AUTH downstream for the 401."
  (lambda (conn)
    (let* ((header (clug:get-req-header conn "authorization"))
           (raw    (parse-bearer header))
           (token  (and raw (find-and-validate-token
                             repo token-schema raw :context context)))
           (user   (and token (clecto:repo-get repo user-schema
                                               (getf token :user-id)))))
      (cond
        ((or (null token) (null user)) conn)
        ((token-session-version-stale-p token user) conn)
        (t (clug:assign conn *current-user-key* user))))))

(defun token-session-version-stale-p (token user)
  "T when the token was minted before the user's current
:session-version — i.e. the user has changed credentials and this
token must die."
  (< (or (getf token :session-version) 0)
     (or (getf user  :session-version) 0)))
