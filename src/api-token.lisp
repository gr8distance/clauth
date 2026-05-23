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

Contexts used by clauth:
  \"session\"      — DB-backed session token (per device, per browser)
  \"remember-me\"  — long-lived cookie token
  \"api\"          — bearer / programmatic access (when wired up)

:authenticated-at records when the token was minted; reserved for
sudo-mode style re-auth checks. :session-version is legacy and kept
for backward compat — credential changes now invalidate sessions by
DELETING token rows (see Phoenix gen.auth), not by bumping a version."
  '((:user-id          :integer)
    (:token-hash       :string)
    (:context          :string)
    (:authenticated-at :naive-datetime)
    (:session-version  :integer)
    (:expires-at       :naive-datetime)))

;;; --- session-token primitives (mirror Phoenix's build_session_token) ---

(defvar *session-context* "session"
  "Context value identifying session tokens in auth_tokens. Must match
phx.gen.auth's expectation for symmetry of behavior.")

(defvar *session-token-validity-seconds* (* 14 24 60 60)
  "Lifetime of a session token. Matches phx.gen.auth's 14-day default.")

(defvar *session-token-reissue-after-seconds* (* 7 24 60 60)
  "Half-life past which load-current-user reissues a new token (and
deletes the old one). 7 days, matching Phoenix.")

(defun build-session-token (repo token-schema user)
  "Mint a fresh session-context token for USER. Returns (values raw record).
RAW goes into the clug/session cookie; the DB row is what the next
request looks up. SHA-256 storage (not raw like Phoenix) because clug
cookies are not signed."
  (create-token repo token-schema user
                :context *session-context*
                :expires-in *session-token-validity-seconds*))

(defun load-user-by-session-token (repo user-schema token-schema raw-token)
  "Look up the session token by hash, then fetch the user it points at.
Returns (values user token-record) on hit, NIL otherwise.

In the phx.gen.auth model, invalidation is row deletion (no
session-version dance). UPDATE-PASSWORD! / UPDATE-EMAIL! delete every
token row for the user; subsequent requests find nothing here and the
plug logs the user out."
  (let* ((token (and raw-token
                     (find-and-validate-token
                      repo token-schema raw-token
                      :context *session-context*)))
         (user (and token (clecto:repo-get
                           repo user-schema (getf token :user-id)))))
    (when (and token user)
      (values user token))))

(defun delete-session-token (repo token-schema raw-token)
  "Look up the session row by hash and delete it. Idempotent if the
row is already gone."
  (when raw-token
    (let ((row (find-and-validate-token repo token-schema raw-token
                                        :context *session-context*)))
      (when row (revoke-token repo token-schema (getf row :id))))))

(defvar *default-api-token-ttl-seconds* (* 60 60 24 30)
  "Default lifetime for API tokens. 30 days.")

(defun create-token (repo token-schema user
                     &key (context "api")
                          (expires-in *default-api-token-ttl-seconds*))
  "Mint a new token bound to USER. USER must be a loaded record (a plist
with at least :ID and ideally :SESSION-VERSION).

Returns (values raw-token record). Hand RAW-TOKEN to the user once
(never re-display it); the DB only stores its SHA-256 hash. EXPIRES-IN
is in seconds; pass NIL for a non-expiring token."
  (unless (consp user)
    (error "create-token requires a loaded user record (got ~s). ~
            Look it up with repo-get first." user))
  (let* ((user-id (or (getf user :id)
                      (error "create-token: user record has no :id")))
         (version (or (getf user :session-version) 0))
         (raw    (generate-token))
         (hash   (token-hash raw))
         ;; UTC throughout — :authenticated-at is compared against
         ;; cutoffs derived from UNIVERSAL-TIME-TO-NAIVE (also UTC),
         ;; so the reissue half-life is stable across timezones / DST.
         (now    (clecto:now-utc-datetime))
         (expiry (when expires-in
                   (universal-time-to-naive
                    (+ (get-universal-time) expires-in))))
         (cs (clecto:cast token-schema
                          (list :user-id user-id
                                :token-hash hash
                                :context context
                                :authenticated-at now
                                :session-version version
                                :expires-at expiry)
                          '(:user-id :token-hash :context :authenticated-at
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

(defun update-password! (repo user-schema token-schema user attrs
                         &key (min-length 12) (max-length 1024))
  "One-shot password change: build a change-password-changeset from
ATTRS, update the user, and delete every auth_tokens row so other
devices are forced to re-auth. Mirrors Phoenix's
Accounts.update_user_password/3.

USER may be a loaded record plist (we splice :__schema__ in for the
changeset). Returns (values updated-record NIL) on success or
(values NIL invalid-cs) on validation/constraint failure.

Atomicity: the user update and the token purge run inside a single
repo-transaction.

IMPORTANT — the CALLING session is also killed. Phoenix's controller
calls log_in_user immediately after a successful password update to
re-establish a session on the same device. Mirror that:

  (multiple-value-bind (rec err) (update-password! ...)
    (when rec
      (setf conn (login conn rec :repo r :token-schema 'auth-token))))

Without this, the user clicks 'Save' and is logged out from the very
device they were using."
  (let* ((data (list* :__schema__ user-schema user))
         (cs (change-password-changeset data attrs
                                        :min-length min-length
                                        :max-length max-length))
         (result-rec nil) (result-err nil))
    (cond
      ((not (clecto:cs-valid-p cs)) (values nil cs))
      (t
       (clecto:repo-transaction (repo)
         (multiple-value-bind (rec err) (clecto:repo-update repo cs)
           (setf result-rec rec result-err err)
           (cond
             (err (clecto:rollback))
             (rec (revoke-all-tokens-for-user repo token-schema
                                              (getf rec :id))))))
       (values result-rec result-err)))))

(defun update-email! (repo user-schema token-schema user attrs)
  "One-shot email change: gate on current password, update email,
purge tokens. Mirrors Phoenix Accounts.update_user_email/3 (the
in-app form path; the confirmation-by-link path needs a mailer)."
  (let* ((data (list* :__schema__ user-schema user))
         (cs (change-email-changeset data attrs))
         (result-rec nil) (result-err nil))
    (cond
      ((not (clecto:cs-valid-p cs)) (values nil cs))
      (t
       (clecto:repo-transaction (repo)
         (multiple-value-bind (rec err) (clecto:repo-update repo cs)
           (setf result-rec rec result-err err)
           (cond
             (err (clecto:rollback))
             (rec (revoke-all-tokens-for-user repo token-schema
                                              (getf rec :id))))))
       (values result-rec result-err)))))

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
request. Implementation: purge all auth_tokens rows for the user. The
next request from any device that holds a (now-invalid) token finds
nothing in the table and load-current-user logs it out.

USER-SCHEMA is reserved for future use (e.g. clearing an :authenticated-at
column when sudo-mode lands). Currently unused.

NOTE: the CALLING session is not killed in-request — render a
'you've been signed out everywhere' page directly; the user re-logs
in on their next action."
  (declare (ignore user-schema))
  (revoke-all-tokens-for-user repo token-schema user-id)
  (emit-auth-event :token-revoked (list :user-id user-id :context "all"))
  t)

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

;;; HTTP API / bearer-token authentication is intentionally NOT
;;; provided here. phx.gen.auth doesn't ship it, and the Phoenix
;;; convention treats programmatic API auth as a separate concern
;;; (Phoenix.Token in core, with libraries like Joken / Guardian for
;;; richer cases). clauth's token primitives — CREATE-TOKEN,
;;; FIND-AND-VALIDATE-TOKEN, REVOKE-TOKEN — are general enough that
;;; a bearer plug, if needed, is ~10 lines of caller code.
