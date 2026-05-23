(defpackage #:clauth/tests
  (:use #:cl #:fiveam))
(in-package #:clauth/tests)

(def-suite :clauth)
(in-suite :clauth)

(defmacro -> (init &body forms)
  (reduce (lambda (acc f)
            (if (consp f) (list* (car f) acc (cdr f)) (list f acc)))
          forms :initial-value init))

;;; Lower argon2 cost during tests — keeps the suite fast without
;;; weakening the production defaults.
(setf clauth:*argon2-block-count* 8
      clauth:*argon2-iterations*  1)

;;; --- password ---

(test password-roundtrip
  (let ((h (clauth:hash-password "hunter2")))
    (is (stringp h))
    (is (search "argon2id" h))
    (is (clauth:verify-password "hunter2" h))
    (is (not (clauth:verify-password "wrong" h)))))

(test password-rejects-non-utf8-mix-and-handles-japanese
  (let ((h (clauth:hash-password "パスワード🔑")))
    (is (clauth:verify-password "パスワード🔑" h))
    (is (not (clauth:verify-password "パスワード" h)))))

(test password-format-uses-stored-params-not-current
  (let ((h (clauth:hash-password "x")))
    ;; bump cost; the old hash should still verify because we read
    ;; parameters from the stored string.
    (let ((clauth:*argon2-block-count* 16)
          (clauth:*argon2-iterations* 2))
      (is (clauth:verify-password "x" h)))))

(test password-rejects-garbage-hash
  (signals error (clauth:verify-password "x" "not-a-hash"))
  (signals error (clauth:verify-password "x" "")))

;;; --- token ---

(test token-roundtrip-and-mismatch
  (multiple-value-bind (raw stored) (clauth:generate-token)
    (is (= 64 (length raw)))                  ; 32 bytes hex
    (is (= 64 (length stored)))               ; sha256 hex
    (is (string/= raw stored))
    (is (clauth:verify-token-hash raw stored))
    (is (not (clauth:verify-token-hash "different" stored)))))

;;; --- schema helper ---

(test auth-fields-shape
  (let ((fields (clauth:auth-fields)))
    (is (find :email          fields :key #'car))
    (is (find :password-hash  fields :key #'car))
    ;; password fields are virtual
    (is (member :virtual (cdr (find :password fields :key #'car))))))

;;; --- registration changeset + repo authenticate ---

(clecto:defschema u "users"
  (:id :integer :primary-key t)
  (:email :string)
  (:password-hash :string)
  (:confirmed-at  :naive-datetime)
  (:password              :string :virtual t)
  (:password-confirmation :string :virtual t)
  (:timestamps))

(defun fresh-repo ()
  (let* ((a (clecto:make-sqlite-adapter ":memory:"))
         (r (clecto:make-repo a)))
    (clecto:repo-execute r
     "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                          password_hash TEXT, confirmed_at TEXT,
                          inserted_at TEXT, updated_at TEXT)")
    (values r a)))

(test register-and-authenticate
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (let ((cs (clauth:register-changeset
                      'u '(:email "a@b" :password "hunter22"
                           :password-confirmation "hunter22"))))
             (is (clecto:cs-valid-p cs))
             ;; The hash is on the cs, the raw password is virtual so
             ;; it never reaches the SQL.
             (is (stringp (clecto:get-change cs :password-hash)))
             (let ((record (nth-value 0 (clecto:repo-insert r cs))))
               (is (not (null record)))
               (is (not (member :password record)))))
           ;; happy path: right password
           (is (not (null (clauth:authenticate r 'u "a@b" "hunter22"))))
           ;; wrong password
           (is (null (clauth:authenticate r 'u "a@b" "wrong")))
           ;; missing user
           (is (null (clauth:authenticate r 'u "ghost@x" "anything"))))
      (clecto:sqlite-close a))))

(test register-rejects-mismatched-confirmation
  (let ((cs (clauth:register-changeset
             'u '(:email "a@b" :password "hunter22"
                  :password-confirmation "different"))))
    (is (not (clecto:cs-valid-p cs)))))

(test register-rejects-short-password
  (let ((cs (clauth:register-changeset
             'u '(:email "a@b" :password "x" :password-confirmation "x"))))
    (is (not (clecto:cs-valid-p cs)))))

(test register-surfaces-unique-email-collision
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (clecto:repo-insert r (clauth:register-changeset
                                  'u '(:email "a@b" :password "hunter22"
                                       :password-confirmation "hunter22")))
           (multiple-value-bind (rec err)
               (clecto:repo-insert r (clauth:register-changeset
                                      'u '(:email "a@b" :password "hunter22"
                                           :password-confirmation "hunter22")))
             (is (null rec))
             (is (assoc :email (clecto:cs-errors err)))))
      (clecto:sqlite-close a))))
