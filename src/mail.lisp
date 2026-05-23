(in-package #:clauth)

;;; Mail-driven auth flows. Mirrors phx.gen.auth's Notifier + Accounts
;;; functions for the four token-by-email patterns:
;;;
;;;   confirmation       — verify a new user's email address
;;;   reset-password     — short-lived link that lets the user pick
;;;                        a new password without their current one
;;;   change-email       — verify a NEW address before swapping
;;;   magic-link login   — passwordless re-entry
;;;
;;; Each flow is a (deliver-* / *!) pair: deliver mints the token + URL
;;; + sends the email; the !-suffixed function validates the token and
;;; applies the action. URLs are app-route-specific so we take a
;;; URL-BUILDER lambda rather than hard-coding any path.

;;; Token contexts bind the address into the context string itself
;;; (Phoenix-style). This means a token issued to ADDR is invalid once
;;; the account's email is no longer ADDR — preventing the "admin
;;; rotates email, attacker still confirms the new address with an old
;;; link" laundering path.
;;;
;;; Wire format: "<kind>:<address>". Examples:
;;;   "confirm:alice@example.com"
;;;   "reset-password:alice@example.com"
;;;   "login:alice@example.com"
;;;   "change:alice-new@example.com"   (change-email = NEW address)

(defvar *confirmation-context-prefix*   "confirm:")
(defvar *reset-password-context-prefix* "reset-password:")
(defvar *magic-link-context-prefix*     "login:")
(defvar *change-email-context-prefix*   "change:")

;; Backward-compat aliases for callers that referenced the old plain
;; context names. Deprecated; will go away in 0.2.
(defvar *confirmation-context*   "confirm:"        )
(defvar *reset-password-context* "reset-password:" )
(defvar *magic-link-context*     "login:"          )

(defvar *confirmation-validity-seconds*   (* 60 60 24 7)   "7 days.")
(defvar *reset-password-validity-seconds* (* 60 15)        "15 minutes.")
(defvar *magic-link-validity-seconds*     (* 60 15)        "15 minutes.")
(defvar *change-email-validity-seconds*   (* 60 60 24 7)   "7 days.")

(defvar *from-address* nil
  "Default From address for clauth's deliver-* helpers. Bind at app
boot, e.g.:

  (setf clauth:*from-address* '(\"My App\" . \"noreply@example.com\"))

Each deliver-* function also accepts an explicit :FROM that overrides.")

;;; --- helpers ---

(defun %from-or-default (from)
  (or from *from-address*
      (error "clauth mail: no FROM address. Set CLAUTH:*FROM-ADDRESS* or pass :FROM.")))

(defun %compose (from to subject text html)
  (let ((email (cliam:make-email)))
    (setf email (cliam:from email (or (cdr-or from) from)
                            (and (consp from) (car from))))
    (setf email (cliam:to email to))
    (setf email (cliam:subject email subject))
    (when text (setf email (cliam:text-body email text)))
    (when html (setf email (cliam:html-body email html)))
    email))

(defun cdr-or (x)
  (and (consp x) (cdr x)))

(defun %deliver (email mailer)
  (if mailer
      (cliam:deliver email :adapter mailer)
      (cliam:deliver email)))

(defun %bound-context (prefix email)
  (concatenate 'string prefix email))

(defun %extract-bound-email (context prefix)
  "Pull the email out of \"<PREFIX><email>\" or return NIL."
  (when (and (stringp context)
             (>= (length context) (length prefix))
             (string= context prefix :end1 (length prefix)))
    (subseq context (length prefix))))

(defun %find-token-by-hash (repo token-schema raw-token)
  "Look up a token row by hash WITHOUT context filtering. Returns NIL
when missing or expired. Used by flows that need to inspect the
context before validating."
  (let* ((hash (token-hash raw-token))
         (schema (clecto::find-schema token-schema))
         (table  (clecto::intern-table schema))
         (row (clecto:repo-one
               repo (clecto:where (clecto:from table)
                                  (list '= :token-hash hash)))))
    (when (and row (not (token-expired-p row))) row)))

(defun %validate-bound-token (repo token-schema raw-token prefix expected-email)
  "Find the token by hash, then assert its context is \"<PREFIX><email>\"
where <email> equals EXPECTED-EMAIL (the user's CURRENT address).
Returns the row on hit, NIL otherwise."
  (let* ((row (%find-token-by-hash repo token-schema raw-token))
         (bound (and row (%extract-bound-email (getf row :context) prefix))))
    (when (and bound expected-email (string-equal bound expected-email))
      row)))

(defun %default-text (action url)
  (format nil "Hi,~%~%~a~%~%~a~%~%If you didn't request this, ignore this email.~%"
          action url))

(defun %default-html (action url)
  (format nil "<p>Hi,</p><p>~a</p><p><a href=\"~a\">~:*~a</a></p>~
              <p>If you didn't request this, ignore this email.</p>"
          action url))

;;; --- confirmation ---

(defun deliver-confirmation-instructions
    (&key repo token-schema user url-builder mailer from
          (subject "Confirm your account")
          text-body html-body)
  "Mint a confirmation token bound to the user's current email
address, build the URL via URL-BUILDER, send the email. Returns the
raw token (handy for tests).

URL placement: put the token in a PATH segment, not a query string.
Tokens in query strings leak via Referer headers when the link is
clicked. SUBJECT / TEXT-BODY / HTML-BODY are interpolated raw — if
you thread user input, escape first."
  (let* ((email-addr (getf user :email))
         (raw (nth-value 0
                (create-token repo token-schema user
                              :context (%bound-context *confirmation-context-prefix*
                                                       email-addr)
                              :expires-in *confirmation-validity-seconds*)))
         (url (funcall url-builder raw))
         (msg (%compose (%from-or-default from) email-addr subject
                        (or text-body (%default-text "Click the link below to confirm your account:" url))
                        (or html-body (%default-html "Click the link below to confirm your account." url)))))
    (%deliver msg mailer)
    (emit-auth-event :confirmation-sent
                     (list :user-id (getf user :id) :email email-addr))
    raw))

(defun confirm-user! (&key repo user-schema token-schema raw-token)
  "Validate RAW-TOKEN, set :confirmed-at on the user, delete the token.
Returns (values user nil) on success or (values nil :invalid) when the
token is missing, expired, or its bound email no longer matches the
user's current address (an address rotation after issue invalidates
the link — Phoenix's contract)."
  (let* ((maybe-row (%find-token-by-hash repo token-schema raw-token))
         (bound (and maybe-row (%extract-bound-email
                                (getf maybe-row :context)
                                *confirmation-context-prefix*)))
         (uid (and maybe-row (getf maybe-row :user-id)))
         (user (and uid (clecto:repo-get repo user-schema uid))))
    (cond
      ((or (null maybe-row) (null bound) (null user)
           (not (string-equal bound (getf user :email))))
       (values nil :invalid))
      (t
       (let* ((schema (clecto::find-schema user-schema))
              (table  (clecto::intern-table schema)))
         (clecto:repo-transaction (repo)
           (clecto:repo-update-all
            repo
            (clecto:where (clecto:from table) (list '= :id uid))
            (list :confirmed-at (clecto:now-utc-datetime)))
           (revoke-token repo token-schema (getf maybe-row :id)))
         (emit-auth-event :confirmed (list :user-id uid))
         (values (clecto:repo-get repo user-schema uid) nil))))))

;;; --- reset password ---

(defun deliver-reset-instructions
    (&key repo token-schema user url-builder mailer from
          (subject "Reset your password")
          text-body html-body)
  "Mint a short-lived (15 min) reset token bound to the user's email.
Same URL / body conventions as DELIVER-CONFIRMATION-INSTRUCTIONS."
  (let* ((email-addr (getf user :email))
         (raw (nth-value 0
                (create-token repo token-schema user
                              :context (%bound-context *reset-password-context-prefix*
                                                       email-addr)
                              :expires-in *reset-password-validity-seconds*)))
         (url (funcall url-builder raw))
         (msg (%compose (%from-or-default from) email-addr subject
                        (or text-body (%default-text "Use the link below to reset your password (valid 15 minutes):" url))
                        (or html-body (%default-html "Use the link below to reset your password (valid 15 minutes)." url)))))
    (%deliver msg mailer)
    (emit-auth-event :reset-sent
                     (list :user-id (getf user :id) :email email-addr))
    raw))

(defun reset-password! (&key repo user-schema token-schema raw-token
                             attrs (min-length 12) (max-length 1024))
  "Validate RAW-TOKEN (bound to the user's CURRENT email), apply the
password change, purge every token for the user — all in one
repo-transaction. No current-password required because the token IS
the proof of email control.

Returns (values updated-user nil) | (values nil :invalid) |
(values nil invalid-cs)."
  (let* ((maybe-row (%find-token-by-hash repo token-schema raw-token))
         (bound (and maybe-row (%extract-bound-email
                                (getf maybe-row :context)
                                *reset-password-context-prefix*)))
         (uid  (and maybe-row (getf maybe-row :user-id)))
         (user (and uid (clecto:repo-get repo user-schema uid))))
    (cond
      ((or (null maybe-row) (null bound) (null user)
           (not (string-equal bound (getf user :email))))
       (values nil :invalid))
      (t
       (let* ((data (list* :__schema__ user-schema user))
              (cs (password-changeset data attrs
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
                  (rec (revoke-all-tokens-for-user repo token-schema uid)))))
            (when result-rec
              (emit-auth-event :password-reset (list :user-id uid)))
            (values result-rec result-err))))))))

;;; --- change email (confirmation by link) ---

(defun deliver-change-email-instructions
    (&key repo token-schema user new-email url-builder mailer from
          (subject "Confirm your new email address")
          text-body html-body)
  "Mint a token whose context encodes the NEW-EMAIL (so the token is
bound to that specific change), then send the link to NEW-EMAIL — the
user must control the new address to confirm. Mirrors Phoenix's
\"change:NEW@EMAIL\" context pattern."
  (unless (valid-email-shape-p new-email)
    (error "deliver-change-email-instructions: invalid NEW-EMAIL ~s" new-email))
  (let* ((ctx (concatenate 'string *change-email-context-prefix* new-email))
         (raw (nth-value 0
                (create-token repo token-schema user
                              :context ctx
                              :expires-in *change-email-validity-seconds*)))
         (url (funcall url-builder raw))
         (email (%compose (%from-or-default from) new-email subject
                          (or text-body (%default-text "Confirm your new email address:" url))
                          (or html-body (%default-html "Confirm your new email address." url)))))
    (%deliver email mailer)
    (emit-auth-event :change-email-sent
                     (list :user-id (getf user :id) :new-email new-email))
    raw))

(defun apply-email-change! (&key repo user-schema token-schema raw-token)
  "Validate the change-email token, swap the user's :email + purge
every existing token. All in one repo-transaction so a collision on
the unique-email constraint can't leave the row half-updated.

Returns (values updated-user nil) | (values nil :invalid) on bad
token / shape / expiry. If the new email is taken by another user
(unique-constraint violation), returns (values nil :email-taken)."
  (let* ((row (%find-token-by-hash repo token-schema raw-token))
         (new-email (and row (%extract-bound-email
                              (getf row :context)
                              *change-email-context-prefix*))))
    (cond
      ((or (null row) (null new-email)
           (not (valid-email-shape-p new-email)))
       (values nil :invalid))
      (t
       (let* ((uid (getf row :user-id))
              (user (clecto:repo-get repo user-schema uid))
              (cs (clecto:unique-constraint
                   (clecto:cast (list* :__schema__ user-schema user)
                                (list :email new-email)
                                '(:email))
                   :email
                   :message "already taken"))
              (result-rec nil) (result-err nil))
         (clecto:repo-transaction (repo)
           (multiple-value-bind (rec err) (clecto:repo-update repo cs)
             (setf result-rec rec result-err err)
             (cond
               (err (clecto:rollback))
               (rec (revoke-all-tokens-for-user repo token-schema uid)))))
         (cond
           (result-err
            (if (assoc :email (clecto:cs-errors result-err))
                (values nil :email-taken)
                (values nil result-err)))
           (result-rec
            (emit-auth-event :email-changed
                             (list :user-id uid :new-email new-email))
            (values (clecto:repo-get repo user-schema uid) nil))
           (t (values nil :invalid))))))))

;;; --- magic link login ---

(defun deliver-magic-link
    (&key repo token-schema user url-builder mailer from
          (subject "Your sign-in link")
          text-body html-body)
  "Mint a short-lived (15 min) magic-link token bound to the user's
email. Use for passwordless sign-in. Returns the raw token."
  (let* ((email-addr (getf user :email))
         (raw (nth-value 0
                (create-token repo token-schema user
                              :context (%bound-context *magic-link-context-prefix*
                                                       email-addr)
                              :expires-in *magic-link-validity-seconds*)))
         (url (funcall url-builder raw))
         (msg (%compose (%from-or-default from) email-addr subject
                        (or text-body (%default-text "Use the link below to sign in (valid 15 minutes):" url))
                        (or html-body (%default-html "Use the link below to sign in (valid 15 minutes)." url)))))
    (%deliver msg mailer)
    (emit-auth-event :magic-link-sent (list :user-id (getf user :id)))
    raw))

(defun log-in-by-magic-link! (&key repo user-schema token-schema raw-token)
  "Validate the magic-link token (bound to the user's CURRENT email)
and return the user. The caller calls LOGIN / LOG-IN-AND-REDIRECT to
establish the session. The token is consumed on success so it can't
be replayed."
  (let* ((row (%find-token-by-hash repo token-schema raw-token))
         (bound (and row (%extract-bound-email
                          (getf row :context)
                          *magic-link-context-prefix*)))
         (uid (and row (getf row :user-id)))
         (user (and uid (clecto:repo-get repo user-schema uid))))
    (cond
      ((or (null row) (null bound) (null user)
           (not (string-equal bound (getf user :email))))
       (values nil :invalid))
      (t
       (revoke-token repo token-schema (getf row :id))
       (emit-auth-event :magic-link-used (list :user-id (getf user :id)))
       (values user nil)))))
