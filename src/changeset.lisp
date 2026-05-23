(in-package #:clauth)

(defmacro -> (init &body forms)
  "Thread-first — local copy so we don't depend on the caller's."
  (reduce (lambda (acc f)
            (if (consp f) (list* (car f) acc (cdr f)) (list f acc)))
          forms :initial-value init))

;;; Changeset helpers that wrap clecto's primitives with the standard
;;; registration / password-change patterns. Each returns a clecto
;;; changeset that's ready for repo-insert / repo-update.

(defun register-changeset (schema attrs &key (min-length 8) (max-length 72))
  "Build a changeset for a fresh signup. Validates email + password +
:password-confirmation match, then puts the argon2id hash on
:password-hash. The raw :password stays in the changeset as a virtual
field and never reaches SQL."
  (let ((cs (clecto:cast schema attrs
                         '(:email :password :password-confirmation))))
    (-> cs
        (clecto:validate-required '(:email :password))
        (clecto:validate-format :email "@")
        (clecto:validate-length :password :min min-length :max max-length)
        (clecto:validate-confirmation :password)
        (clecto:unique-constraint :email)
        (put-password-hash))))

(defun password-changeset (data attrs &key (min-length 8) (max-length 72))
  "Build a changeset for changing an existing user's password. DATA is
the loaded user record (must include the primary key). ATTRS supplies
:password and :password-confirmation."
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

(defun put-password-hash (cs)
  "If the changeset carries a valid :password change, hash it into
:password-hash. No-op when the cs is already invalid or no password
was supplied."
  (let ((pw (clecto:get-change cs :password)))
    (if (and (clecto:cs-valid-p cs) pw)
        (clecto:put-change cs :password-hash (hash-password pw))
        cs)))

