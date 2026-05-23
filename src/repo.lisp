(in-package #:clauth)

;;; Authentication: email + password lookup. Designed so the time spent
;;; verifying is *almost* independent of whether the email exists,
;;; preventing user-enumeration via timing.

(defvar *dummy-hash*
  ;; Computed lazily on first use so VERIFY-PASSWORD against a missing
  ;; user still pays roughly the cost of a real Argon2id verification.
  nil)

(defun %ensure-dummy-hash ()
  (or *dummy-hash*
      (setf *dummy-hash* (hash-password "x"))))

(defun authenticate (repo schema-name email password)
  "Look up by EMAIL and verify PASSWORD. Returns the user plist on
success, NIL otherwise. Performs a dummy Argon2 verify when the email
isn't found so request timing stays similar across both branches."
  (let ((user (clecto:repo-get-by repo schema-name (list :email email))))
    (cond
      (user
       (if (verify-password password (getf user :password-hash))
           user
           nil))
      (t
       ;; Burn ~the same time as a real verify so timing doesn't leak.
       (verify-password password (%ensure-dummy-hash))
       nil))))
