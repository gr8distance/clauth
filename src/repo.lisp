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

(defun authenticate (repo schema-name email password)
  "Look up by EMAIL and verify PASSWORD. Returns the user plist on
success, NIL otherwise. Performs a dummy Argon2 verify when the email
is missing OR when the stored row has no password hash (OAuth-only
accounts, half-initialised rows) so neither timing nor crash behavior
leaks user existence."
  (let* ((user (clecto:repo-get-by repo schema-name (list :email email)))
         (stored (and user (getf user :password-hash))))
    (cond
      ((and user stored)
       (if (verify-password password stored) user nil))
      (t
       ;; Missing user OR missing/null hash — verify against the dummy
       ;; to keep the response time in the same ballpark as the real
       ;; verify above.
       (verify-password password (ensure-dummy-hash!))
       nil))))
