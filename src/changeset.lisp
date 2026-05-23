(in-package #:clauth)

;;; Changeset helpers that wrap clecto's primitives with the standard
;;; registration / password-change patterns. Each returns a clecto
;;; changeset that's ready for repo-insert / repo-update.

(defun register-changeset (schema attrs &key (min-length 12) (max-length 1024))
  "Build a changeset for a fresh signup. Validates email + password +
:password-confirmation match, then puts the argon2id hash on
:password-hash. Emails are normalized to lowercase before any
comparison so users can't register the same address twice with
different casing."
  (let* ((normalized (normalize-email-attrs attrs))
         (cs (clecto:cast schema normalized
                          '(:email :password :password-confirmation))))
    (-> cs
        (clecto:validate-required '(:email :password))
        (validate-email-shape :email)
        (clecto:validate-length :password :min min-length :max max-length)
        (clecto:validate-confirmation :password)
        (clecto:unique-constraint :email)
        (put-password-hash))))

(defun valid-email-shape-p (s)
  "Match Phoenix's ~r/^[^@,;\\s]+@[^@,;\\s]+$/: one or more
non-(@,;\\s) chars, @, one or more non-(@,;\\s) chars. Stricter than
the old '@' substring check."
  (when (stringp s)
    (let* ((at (position #\@ s)))
      (and at
           (plusp at)
           (< (1+ at) (length s))
           (not (find #\@ s :start (1+ at)))
           (notany (lambda (c)
                     (find c '(#\Space #\Tab #\Newline #\, #\;)))
                   s)))))

(defun validate-email-shape (cs field
                             &key (message "must have the @ sign and no spaces"))
  "Replacement for the old (clecto:validate-format :email \"@\")
substring check. Mirrors Phoenix's regex."
  (if (valid-email-shape-p (clecto:get-field cs field))
      cs
      (clecto:add-error cs field message)))

(defun normalize-email-attrs (attrs)
  "Return a fresh attrs plist with :email lowercased + trimmed."
  (let ((email (getf attrs :email)))
    (if (stringp email)
        (list* :email (string-downcase (string-trim " " email))
               (alexandria:remove-from-plist attrs :email))
        attrs)))

(defun password-changeset (data attrs &key (min-length 12) (max-length 1024))
  "Build a changeset for setting an existing user's password without
re-authentication. Use this from a flow that already verified the
user some other way (e.g. just-completed password reset). For the
user-facing 'change my password' form, see CHANGE-PASSWORD-CHANGESET."
  (let* ((with-schema (list* :__schema__ (or (getf data :__schema__)
                                             (error "DATA needs :__schema__"))
                             data))
         (cs (clecto:cast with-schema attrs
                          '(:password :password-confirmation))))
    (-> cs
        (clecto:validate-required '(:password))
        (clecto:validate-length :password :min min-length :max max-length)
        (clecto:validate-confirmation :password)
        (put-password-hash))))

(defun change-password-changeset (data attrs &key (min-length 12)
                                                  (max-length 1024))
  "Build a changeset for the user-facing 'change my password' form.
DATA is the loaded user record (with :password-hash and :__schema__).
ATTRS supplies :current-password, :password, :password-confirmation.

If :current-password doesn't match the stored hash, the error lands on
:current-password (not on :password) so forms can highlight the right
field. The current-password check runs even when other fields are also
invalid so the user sees all errors at once.

KNOWN GAP: no optimistic locking. Two simultaneous requests can both
pass the current-password check (using the OLD hash), and last-write
wins on the new password. The other tab silently loses its change but
sees success. Phoenix has the same default behavior; mitigate at the
controller level with CSRF (one form, one token) until clecto grows
WHERE-augmented updates."
  (let* ((with-schema (list* :__schema__ (or (getf data :__schema__)
                                             (error "DATA needs :__schema__"))
                             data))
         (cs (clecto:cast with-schema attrs
                          '(:current-password :password :password-confirmation))))
    (-> cs
        (validate-current-password data)
        (clecto:validate-required '(:password))
        (clecto:validate-length :password :min min-length :max max-length)
        (clecto:validate-confirmation :password)
        (put-password-hash)
        (bump-session-version data))))

(defun change-email-changeset (data attrs)
  "Build a changeset for an immediate email change, gated by the user's
current password. DATA is the loaded user record; ATTRS supplies
:email and :current-password.

NOTE: this updates the email in place. A production flow should send a
confirmation link to the NEW address before activating it — that needs
a mailer and lands when clailer ships. Until then, prefer this only
for low-stakes accounts or admin-driven updates."
  (let* ((with-schema (list* :__schema__ (or (getf data :__schema__)
                                             (error "DATA needs :__schema__"))
                             data))
         (normalized (normalize-email-attrs attrs))
         (cs (clecto:cast with-schema normalized '(:email :current-password))))
    (-> cs
        (validate-current-password data)
        (clecto:validate-required '(:email))
        (validate-email-shape :email)
        (validate-email-changed data)
        (clecto:unique-constraint :email)
        (bump-session-version data))))

(defun validate-email-changed (cs data)
  "Reject a 'change' that doesn't actually change the address.
Stops accidental no-op writes from cycling through the audit log later."
  (let ((new (clecto:get-change cs :email))
        (old (getf data :email)))
    (if (and new (string= new old))
        (clecto:add-error cs :email "did not change")
        cs)))

(defun bump-session-version (cs data)
  "DEPRECATED. Was used to invalidate other devices' cookies. Now the
authoritative invalidation is 'delete the user's token rows' — see
UPDATE-PASSWORD! / UPDATE-EMAIL! / REVOKE-TOKENS-ON-CREDENTIAL-CHANGE.

This still fires the :credentials-changed audit event, so callers
that haven't migrated keep emitting the same telemetry. The schema
no longer carries :session-version, so the put-change is a no-op
unless the user explicitly added the column."
  (emit-auth-event :credentials-changed
                   (list :user-id (getf data :id)))
  cs)

(defun validate-current-password (cs data)
  "Verify :current-password in CS matches DATA's stored :password-hash.
Pushes an error onto :current-password if mismatched. Constant-time."
  (let ((supplied (clecto:get-change cs :current-password))
        (stored   (getf data :password-hash)))
    (cond
      ((null supplied)
       (clecto:add-error cs :current-password "can't be blank"))
      ((or (null stored)
           (not (verify-password supplied stored)))
       (clecto:add-error cs :current-password "is incorrect"))
      (t cs))))

(defun put-password-hash (cs)
  "If the changeset carries a valid :password change, hash it into
:password-hash. No-op when the cs is already invalid or no password
was supplied."
  (let ((pw (clecto:get-change cs :password)))
    (if (and (clecto:cs-valid-p cs) pw)
        (clecto:put-change cs :password-hash (hash-password pw))
        cs)))

