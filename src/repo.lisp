(in-package #:clauth)

;;; Authentication: email + password lookup. Designed so the time spent
;;; verifying is *almost* independent of whether the email exists,
;;; preventing user-enumeration via timing.

(defvar *dummy-hash* nil
  "Hash to verify against when the lookup branch needs to burn time but
has no real hash. Populated by ENSURE-DUMMY-HASH! at load time so the
first concurrent authenticate doesn't race to compute it.")

(defvar *dummy-hash-lock*
  (bordeaux-threads:make-lock "clauth-dummy-hash"))

(defun ensure-dummy-hash! ()
  "Compute the dummy hash if it isn't there yet. Called at load time;
also safe to re-call (locked, idempotent)."
  (bordeaux-threads:with-lock-held (*dummy-hash-lock*)
    (unless *dummy-hash*
      (setf *dummy-hash* (hash-password "x"))))
  *dummy-hash*)

;; Eagerly compute so the first request — possibly concurrent — finds
;; *dummy-hash* already set.
(eval-when (:load-toplevel :execute)
  (ensure-dummy-hash!))

(defun normalize-email (email)
  (and (stringp email) (string-downcase (string-trim " " email))))

(defun authenticate (repo schema-name email password)
  "Look up by EMAIL and verify PASSWORD. Returns the user plist on
success, NIL otherwise. Email is lowercased + trimmed to match the
normalization applied at registration. Performs a dummy Argon2 verify
when the email is missing OR when the stored row has no password hash
so neither timing nor crash behavior leaks user existence."
  (let* ((user (and (normalize-email email)
                    (clecto:repo-get-by repo schema-name
                                        (list :email (normalize-email email)))))
         (stored (and user (getf user :password-hash))))
    (cond
      ((and user stored)
       (if (verify-password password stored) user nil))
      (t
       (verify-password password (ensure-dummy-hash!))
       nil))))

;;; --- account lockout / rate limit ---

(defvar *lockout-max-attempts* 5
  "Failed-login threshold past which AUTHENTICATE-WITH-LOCKOUT locks
the account.")

(defvar *lockout-duration-seconds* 900   ; 15 min
  "How long an account stays locked once the threshold is crossed.")

(defun account-locked-p (user)
  "T if USER's :locked-until is in the future. Times are stored in UTC
so DST transitions and timezone migrations don't accidentally unlock
accounts an hour early or trap them an hour longer than configured."
  (let ((until (getf user :locked-until)))
    (and until
         ;; The lexicographic order of 'YYYY-MM-DD HH:MM:SSZ' strings
         ;; matches chronological order, so STRING< is sufficient.
         (string< (clecto:now-utc-datetime) until))))

(defun authenticate-with-lockout (repo schema-name email password
                                  &key (max-attempts *lockout-max-attempts*)
                                       (lockout-seconds *lockout-duration-seconds*))
  "Like AUTHENTICATE but tracks failed attempts and locks accounts.
Returns:
  (values user nil)            — success; counters reset
  (values nil :locked)         — currently locked (even if password was right)
  (values nil :wrong-password) — wrong credentials or missing user

Verify-password runs in every branch (against a dummy on missing/locked
input) so timing doesn't leak which case fired.

TIMING NOTE: Argon2id dominates total response time by 1–2 orders of
magnitude over the ancillary DB UPDATE used by success / wrong-password
branches, so the residual gap between 'missing user' (verify only) and
'matched + DB write' is in the low-percent range. If your threat model
includes a sophisticated network-timing attacker, place this behind
constant-rate request handling at the controller layer."
  (let* ((user (and (normalize-email email)
                    (clecto:repo-get-by repo schema-name
                                        (list :email (normalize-email email)))))
         (stored (and user (getf user :password-hash))))
    (cond
      ((null user)
       (verify-password password (ensure-dummy-hash!))
       (values nil :wrong-password))
      ((account-locked-p user)
       ;; Burn a verify so a locked account is indistinguishable from a
       ;; non-locked one in timing — caller still gets :locked.
       (verify-password password (or stored (ensure-dummy-hash!)))
       (values nil :locked))
      ((null stored)
       (verify-password password (ensure-dummy-hash!))
       (values nil :wrong-password))
      ((verify-password password stored)
       (reset-failed-attempts! repo schema-name user)
       (values user nil))
      (t
       (record-failed-attempt! repo schema-name user
                               max-attempts lockout-seconds)
       (values nil :wrong-password)))))

(defun reset-failed-attempts! (repo schema-name user)
  "On a successful login, zero the counter and lift any lock."
  (let ((schema (clecto::find-schema schema-name)))
    (clecto:repo-update-all
     repo
     (clecto:where (clecto:from (clecto::intern-table schema))
                   (list '= :id (getf user :id)))
     '(:failed-login-count 0 :locked-until nil))))

(defun record-failed-attempt! (repo schema-name user max-attempts lockout-seconds)
  "Bump the counter; lock the account when MAX-ATTEMPTS is reached."
  (let* ((count (1+ (or (getf user :failed-login-count) 0)))
         (lock-until (when (>= count max-attempts)
                       (universal-time-to-naive
                        (+ (get-universal-time) lockout-seconds)))))
    (clecto:repo-update-all
     repo
     (clecto:where (clecto:from (clecto::intern-table
                                 (clecto::find-schema schema-name)))
                   (list '= :id (getf user :id)))
     (list :failed-login-count count
           :locked-until lock-until))))

(defun universal-time-to-naive (univ)
  "Format UNIV (universal-time integer) as 'YYYY-MM-DD HH:MM:SSZ' in UTC.
Used for lockout deadlines and token expiries — both compared with
STRING< against (clecto:now-utc-datetime)."
  (multiple-value-bind (s m h d mo y) (decode-universal-time univ 0)
    (format nil "~4,'0d-~2,'0d-~2,'0d ~2,'0d:~2,'0d:~2,'0dZ"
            y mo d h m s)))
