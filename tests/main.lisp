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
  (:session-version :integer)
  (:failed-login-count :integer)
  (:locked-until :naive-datetime)
  (:password              :string :virtual t)
  (:password-confirmation :string :virtual t)
  (:current-password      :string :virtual t)
  (:timestamps))

(defun fresh-repo ()
  (let* ((a (clecto:make-sqlite-adapter ":memory:"))
         (r (clecto:make-repo a)))
    (clecto:repo-execute r
     "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE,
                          password_hash TEXT, confirmed_at TEXT,
                          session_version INTEGER DEFAULT 0,
                          failed_login_count INTEGER DEFAULT 0,
                          locked_until TEXT,
                          inserted_at TEXT, updated_at TEXT)")
    (values r a)))

(test register-and-authenticate
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (let ((cs (clauth:register-changeset
                      'u '(:email "a@b" :password "hunter22-extra"
                           :password-confirmation "hunter22-extra"))))
             (is (clecto:cs-valid-p cs))
             ;; The hash is on the cs, the raw password is virtual so
             ;; it never reaches the SQL.
             (is (stringp (clecto:get-change cs :password-hash)))
             (let ((record (nth-value 0 (clecto:repo-insert r cs))))
               (is (not (null record)))
               (is (not (member :password record)))))
           ;; happy path: right password
           (is (not (null (clauth:authenticate r 'u "a@b" "hunter22-extra"))))
           ;; wrong password
           (is (null (clauth:authenticate r 'u "a@b" "wrong")))
           ;; missing user
           (is (null (clauth:authenticate r 'u "ghost@x" "anything"))))
      (clecto:sqlite-close a))))

(test register-rejects-mismatched-confirmation
  (let ((cs (clauth:register-changeset
             'u '(:email "a@b" :password "hunter22-extra"
                  :password-confirmation "different"))))
    (is (not (clecto:cs-valid-p cs)))))

(test register-rejects-short-password
  (let ((cs (clauth:register-changeset
             'u '(:email "a@b" :password "x" :password-confirmation "x"))))
    (is (not (clecto:cs-valid-p cs)))))

;;; --- security guards added after audit ---

(test parse-rejects-tampered-block-count
  ;; m=999999 would otherwise drive ironclad to allocate ~1 GB.
  (signals error
    (clauth:verify-password "x"
      (format nil "clauth$argon2id$m=999999,t=3$~a$~a"
              "0011223344556677" "deadbeef00000000deadbeef00000000"))))

(test parse-rejects-zero-length-hash
  ;; Empty hash component must NOT be accepted as a match.
  (signals error
    (clauth:verify-password "x"
      "clauth$argon2id$m=8,t=1$0011223344556677$")))

(test parse-rejects-negative-and-duplicate-params
  (signals error
    (clauth:verify-password "x"
      "clauth$argon2id$m=-1,t=1$0011223344556677$dead"))
  (signals error
    (clauth:verify-password "x"
      "clauth$argon2id$m=8,m=8,t=1$0011223344556677$dead")))

(test parse-rejects-non-string
  (signals error (clauth:verify-password "x" nil))
  (signals error (clauth:verify-password "x" 42)))

(test authenticate-nil-hash-falls-back-to-dummy
  ;; A row with a null password_hash (OAuth-only account, half-built
  ;; record) used to crash and leak existence via timing. Now: no
  ;; crash, returns nil quietly.
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (clecto:repo-execute r "INSERT INTO users (email) VALUES ('p@q')")
           (is (null (clauth:authenticate r 'u "p@q" "anything"))))
      (clecto:sqlite-close a))))

(test login-refuses-string-uid
  ;; A controller mistakenly forwarding a request param would otherwise
  ;; let anyone log in as any uid.
  (signals error
    (clauth:login (clug:make-conn) "1 OR 1=1")))

;;; --- plug integration tests against an in-memory clug app ---

(defun build-app (repo)
  "Compose load-current-user + require-auth over a fake handler that
echos the current user id (or 'anon')."
  (let ((load-user (clauth:load-current-user repo 'u)))
    (clug:to-clack-app
     (clug:pipeline
      load-user
      (lambda (conn)
        (let ((u (clauth:current-user conn)))
          (clug:put-resp conn 200
                         (if u (format nil "user=~a" (getf u :id)) "anon")
                         (list "content-type" "text/plain"))))))))

(defun env-with-cookie (cookie)
  (list :request-method :get :path-info "/" :query-string nil
        :headers (let ((h (make-hash-table :test 'equal)))
                   (when cookie (setf (gethash "cookie" h) cookie))
                   h)))

(test login-rotates-sid-and-makes-current-user-available
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "x@y" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (uid  (getf user :id))
                (store (clug:make-memory-store))
                (planted-sid "fixated-sid-deadbeef")
                ;; Attacker plants a known sid on the user.
                (_ (clug:store-save
                    store planted-sid (make-hash-table :test 'equal)))
                ;; Login app: authenticate and call clauth:login.
                (login-app
                  (clug:with-session
                    (lambda (env)
                      (let* ((c (clug:make-conn :req env))
                             (logged-in (clauth:login c (list :id uid))))
                        (list 200 nil '(""))))
                    :store store))
                (response (funcall login-app
                                   (env-with-cookie (format nil "clug.session=~a" planted-sid)))))
           (declare (ignore _))
           ;; Old sid no longer in the store — fixation defused.
           (is (null (clug:store-load store planted-sid)))
           ;; A fresh Set-Cookie went out.
           (let ((sc (loop for (k v) on (second response) by #'cddr
                           when (and (stringp k) (string= k "set-cookie")) return v)))
             (is (not (null sc)))
             (is (not (search planted-sid sc)))))
      (clecto:sqlite-close a))))

(test logout-clears-store-and-expires-cookie
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((store (clug:make-memory-store))
                (sid "logout-sid-1234")
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-id h) 42) h))
                (_ (clug:store-save store sid data))
                (app (clug:with-session
                       (lambda (env)
                         (let ((c (clug:make-conn :req env)))
                           (clauth:logout c)
                           (list 200 nil '(""))))
                       :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           (is (null (clug:store-load store sid)))
           (let ((sc (loop for (k v) on (second response) by #'cddr
                           when (and (stringp k) (string= k "set-cookie")) return v)))
             (is (not (null sc)))
             (is (search "Max-Age=0" sc))))
      (clecto:sqlite-close a))))

(test require-auth-401s-when-no-session
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((store (clug:make-memory-store))
                (app (clug:with-session
                       (clug:to-clack-app
                        (clug:pipeline
                         (clauth:load-current-user r 'u)
                         'clauth:require-auth
                         (lambda (c) (clug:put-resp c 200 "secret"))))
                       :store store))
                (response (funcall app (env-with-cookie nil))))
           (is (= 401 (first response))))
      (clecto:sqlite-close a))))

(test load-current-user-surfaces-record-by-session
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "s@s" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (uid (getf user :id))
                (store (clug:make-memory-store))
                (sid "good-sid-1234")
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-id h) uid) h))
                (_ (clug:store-save store sid data))
                (app (clug:with-session (build-app r) :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           (is (= 200 (first response)))
           (is (search (format nil "user=~a" uid)
                       (first (third response)))))
      (clecto:sqlite-close a))))

(test virtual-password-never-reaches-sql
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (clecto:repo-insert r (clauth:register-changeset
                                  'u '(:email "v@v" :password "hunter22-extra"
                                       :password-confirmation "hunter22-extra")))
           ;; Read raw SQL to confirm there's no :password column emitted
           ;; AND the value "hunter22-extra" isn't sitting in any cell.
           (let* ((rows (clecto:repo-execute r "SELECT * FROM users")))
             (dolist (row rows)
               (loop for (k v) on row by #'cddr do
                 (is (not (search "hunter22-extra"
                                  (cond ((stringp v) v) (t (princ-to-string v))))))))))
      (clecto:sqlite-close a))))

;;; --- A1: change-password ---

(test change-password-happy-path
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "cp@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-password-changeset
                     existing
                     '(:current-password "hunter22-extra"
                       :password "newpassword99"
                       :password-confirmation "newpassword99"))))
           (is (clecto:cs-valid-p cs))
           (clecto:repo-update r cs)
           ;; old password no longer authenticates; new one does
           (is (null (clauth:authenticate r 'u "cp@x" "hunter22-extra")))
           (is (not (null (clauth:authenticate r 'u "cp@x" "newpassword99")))))
      (clecto:sqlite-close a))))

(test change-password-rejects-wrong-current
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "cp2@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-password-changeset
                     existing
                     '(:current-password "wrong"
                       :password "newpassword99"
                       :password-confirmation "newpassword99"))))
           (is (not (clecto:cs-valid-p cs)))
           (is (assoc :current-password (clecto:cs-errors cs))))
      (clecto:sqlite-close a))))

(test change-password-rejects-blank-current
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "cp3@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-password-changeset
                     existing
                     '(:password "newpassword99"
                       :password-confirmation "newpassword99"))))
           (is (not (clecto:cs-valid-p cs)))
           (is (assoc :current-password (clecto:cs-errors cs))))
      (clecto:sqlite-close a))))

(test change-password-rejects-mismatched-confirmation
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "cp4@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-password-changeset
                     existing
                     '(:current-password "hunter22-extra"
                       :password "newpassword99"
                       :password-confirmation "different"))))
           (is (not (clecto:cs-valid-p cs))))
      (clecto:sqlite-close a))))

;;; --- A2: change-email ---

(test change-email-happy-path
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "old@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-email-changeset
                     existing
                     '(:email "new@x" :current-password "hunter22-extra"))))
           (is (clecto:cs-valid-p cs))
           (clecto:repo-update r cs)
           (is (not (null (clauth:authenticate r 'u "new@x" "hunter22-extra"))))
           (is (null (clauth:authenticate r 'u "old@x" "hunter22-extra"))))
      (clecto:sqlite-close a))))

(test change-email-requires-current-password
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "ce@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-email-changeset
                     existing
                     '(:email "new@x" :current-password "wrong"))))
           (is (not (clecto:cs-valid-p cs)))
           (is (assoc :current-password (clecto:cs-errors cs))))
      (clecto:sqlite-close a))))

(test change-email-rejects-no-op
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "noop@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (existing (list* :__schema__ 'u user))
                (cs (clauth:change-email-changeset
                     existing
                     '(:email "noop@x" :current-password "hunter22-extra"))))
           (is (not (clecto:cs-valid-p cs)))
           (is (assoc :email (clecto:cs-errors cs))))
      (clecto:sqlite-close a))))

;;; --- A3: session-timeout ---

(test session-timeout-logs-out-stale-session
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "st@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (uid (getf user :id))
                (store (clug:make-memory-store))
                (sid "stale-sid")
                (long-ago (- (get-universal-time) 9999))
                ;; pre-populate session: logged in, but last activity is old
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-id h) uid)
                        (setf (gethash :last-activity-at h) long-ago)
                        h))
                (_ (clug:store-save store sid data))
                (timeout-plug (clauth:session-timeout :max-idle-seconds 1800))
                (app (clug:with-session
                       (clug:to-clack-app
                        (clug:pipeline
                         timeout-plug
                         (clauth:load-current-user r 'u)
                         (lambda (c)
                           (clug:put-resp c 200
                                          (if (clauth:current-user c)
                                              "alive" "expired")))))
                       :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           (is (equal "expired" (first (third response))))
           (is (null (clug:store-load store sid))))
      (clecto:sqlite-close a))))

(test session-timeout-refreshes-activity-on-each-request
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "st2@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (uid (getf user :id))
                (store (clug:make-memory-store))
                (sid "fresh-sid")
                (just-now (- (get-universal-time) 10))
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-id h) uid)
                        (setf (gethash :last-activity-at h) just-now)
                        h))
                (_ (clug:store-save store sid data))
                (app (clug:with-session
                       (clug:to-clack-app
                        (clug:pipeline
                         (clauth:session-timeout :max-idle-seconds 1800)
                         (clauth:load-current-user r 'u)
                         (lambda (c)
                           (clug:put-resp c 200
                                          (if (clauth:current-user c)
                                              "alive" "expired")))))
                       :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           (is (equal "alive" (first (third response))))
           ;; timestamp was bumped
           (let ((reloaded (clug:store-load store sid)))
             (is (> (gethash :last-activity-at reloaded) just-now))))
      (clecto:sqlite-close a))))

;;; --- A audit follow-ups (M2 / M3 / L1 / L3 / L4) ---

(test virtual-current-password-never-reaches-sql-on-update
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (let* ((user (nth-value 0 (clecto:repo-insert
                                      r (clauth:register-changeset
                                         'u '(:email "v2@x" :password "hunter22-extra"
                                              :password-confirmation "hunter22-extra"))))))
             (clecto:repo-update r (clauth:change-password-changeset
                                    (list* :__schema__ 'u user)
                                    '(:current-password "hunter22-extra"
                                      :password "fresh-secret-99"
                                      :password-confirmation "fresh-secret-99"))))
           (let ((rows (clecto:repo-execute r "SELECT * FROM users")))
             (dolist (row rows)
               (loop for (k v) on row by #'cddr do
                 (let ((s (cond ((stringp v) v) (t (princ-to-string v)))))
                   (is (not (search "hunter22-extra"        s)))
                   (is (not (search "fresh-secret-99" s))))))))
      (clecto:sqlite-close a))))

(test update-password!-deletes-all-tokens
  ;; phx.gen.auth model: a password change purges every auth_tokens row
  ;; for that user, forcing every device to re-auth on its next request.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "upd@x" "hunter22-extra"))
                (raw1 (nth-value 0 (clauth:create-token r 'auth-token user)))
                (raw2 (nth-value 0 (clauth:create-token r 'auth-token user))))
           (declare (ignore raw1 raw2))
           (multiple-value-bind (rec err)
               (clauth:update-password! r 'u 'auth-token user
                 '(:current-password "hunter22-extra"
                   :password "newpw1234fresh"
                   :password-confirmation "newpw1234fresh"))
             (is (null err))
             (is (not (null rec))))
           ;; both tokens gone
           (let ((rows (clecto:repo-all r (clecto:from :auth-tokens))))
             (is (zerop (length rows)))))
      (clecto:sqlite-close a))))

(test password-change-forces-other-devices-to-logout
  ;; phx.gen.auth contract: after a password change, every other device's
  ;; session token has been deleted and load-current-user finds nothing.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "ml@x" "hunter22-extra"))
                ;; device A has a session token
                (device-a-raw (nth-value 0 (clauth:create-token r 'auth-token user))))
           ;; meanwhile device B changes the password
           (clauth:update-password! r 'u 'auth-token user
             '(:current-password "hunter22-extra"
               :password "newpw1234"
               :password-confirmation "newpw1234"))
           ;; device A's token is now gone
           (let* ((store (clug:make-memory-store))
                  (sid "device-A-sid")
                  (data (let ((h (make-hash-table :test 'equal)))
                          (setf (gethash :user-token h) device-a-raw) h))
                  (_ (clug:store-save store sid data))
                  (app (clug:with-session
                         (clug:to-clack-app
                          (clug:pipeline
                           (clauth:load-current-user r 'u
                                                     :token-schema 'auth-token)
                           (lambda (c)
                             (clug:put-resp c 200
                                            (if (clauth:current-user c)
                                                "alive" "stale")))))
                         :store store))
                  (response (funcall app
                                     (env-with-cookie (format nil "clug.session=~a" sid)))))
             (declare (ignore _))
             (is (equal "stale" (first (third response))))))
      (clecto:sqlite-close a))))

(test email-normalized-on-register-and-authenticate
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           ;; uppercase + leading/trailing whitespace
           (clecto:repo-insert r (clauth:register-changeset
                                  'u '(:email " Mixed@CASE.com "
                                       :password "hunter22-extra"
                                       :password-confirmation "hunter22-extra")))
           ;; authenticate with different casing succeeds
           (is (not (null (clauth:authenticate r 'u "mixed@case.com" "hunter22-extra"))))
           (is (not (null (clauth:authenticate r 'u "MIXED@CASE.COM" "hunter22-extra"))))
           ;; second register with same-but-recased should collide
           (multiple-value-bind (rec err)
               (clecto:repo-insert r (clauth:register-changeset
                                      'u '(:email "MIXED@case.com"
                                           :password "hunter22-extra"
                                           :password-confirmation "hunter22-extra")))
             (is (null rec))
             (is (assoc :email (clecto:cs-errors err)))))
      (clecto:sqlite-close a))))

(test session-timeout-clamps-negative-skew
  ;; Future-timestamp (clock skew) should NOT keep the user alive
  ;; forever — we clamp delta to zero so timeout still fires when
  ;; it should, and a skewed-future timestamp simply gets overwritten.
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (nth-value 0 (clecto:repo-insert
                                    r (clauth:register-changeset
                                       'u '(:email "sk@x" :password "hunter22-extra"
                                            :password-confirmation "hunter22-extra")))))
                (uid (getf user :id))
                (store (clug:make-memory-store))
                (sid "skew-sid")
                (future (+ (get-universal-time) 9999))
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-id h) uid)
                        (setf (gethash :session-version h) 0)
                        (setf (gethash :last-activity-at h) future)
                        h))
                (_ (clug:store-save store sid data))
                (app (clug:with-session
                       (clug:to-clack-app
                        (clug:pipeline
                         (clauth:session-timeout :max-idle-seconds 1800)
                         (clauth:load-current-user r 'u)
                         (lambda (c)
                           (clug:put-resp c 200
                                          (if (clauth:current-user c)
                                              "alive" "expired")))))
                       :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           ;; alive (skew didn't expire) AND the future timestamp got
           ;; overwritten with now
           (is (equal "alive" (first (third response))))
           (let ((reloaded (clug:store-load store sid)))
             (is (<= (gethash :last-activity-at reloaded)
                     (get-universal-time)))))
      (clecto:sqlite-close a))))

(test current-user-id-graceful-without-session-middleware
  ;; A bare conn (no clug:with-session wrapping) should not error;
  ;; current-user-id returns NIL.
  (is (null (clauth:current-user-id (clug:make-conn)))))

;;; --- B1: account lockout ---

(defun seed-user (r email pw)
  (nth-value 0 (clecto:repo-insert
                r (clauth:register-changeset
                   'u (list :email email :password pw
                            :password-confirmation pw)))))

(test lockout-locks-after-threshold
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (seed-user r "lk@x" "hunter22-extra")
           ;; 5 wrong attempts (default threshold)
           (dotimes (n 5)
             (multiple-value-bind (user reason)
                 (clauth:authenticate-with-lockout r 'u "lk@x" "wrong")
               (is (null user))
               (is (eq :wrong-password reason))))
           ;; 6th — still wrong, but now :locked
           (multiple-value-bind (user reason)
               (clauth:authenticate-with-lockout r 'u "lk@x" "wrong")
             (is (null user))
             (is (eq :locked reason)))
           ;; even the RIGHT password returns :locked while the lock holds
           (multiple-value-bind (user reason)
               (clauth:authenticate-with-lockout r 'u "lk@x" "hunter22-extra")
             (is (null user))
             (is (eq :locked reason))))
      (clecto:sqlite-close a))))

(test lockout-resets-on-successful-auth
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (seed-user r "lk2@x" "hunter22-extra")
           ;; rack up 3 fails (below threshold of 5)
           (dotimes (n 3)
             (clauth:authenticate-with-lockout r 'u "lk2@x" "wrong"))
           (let ((u (clecto:repo-get-by r 'u '(:email "lk2@x"))))
             (is (= 3 (getf u :failed-login-count))))
           ;; success resets the counter
           (multiple-value-bind (user reason)
               (clauth:authenticate-with-lockout r 'u "lk2@x" "hunter22-extra")
             (is (not (null user)))
             (is (null reason)))
           (let ((u (clecto:repo-get-by r 'u '(:email "lk2@x"))))
             (is (zerop (getf u :failed-login-count)))
             (is (null (getf u :locked-until)))))
      (clecto:sqlite-close a))))

(test lockout-missing-user-returns-wrong-password
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (multiple-value-bind (user reason)
             (clauth:authenticate-with-lockout r 'u "ghost@x" "anything")
           (is (null user))
           (is (eq :wrong-password reason)))
      (clecto:sqlite-close a))))

(test failed-attempt-counter-is-atomic
  ;; Pre-fix: read-modify-write — concurrent failures with the same
  ;; loaded count both wrote count+1, so two parallel wrong-password
  ;; attempts only bumped the counter once.
  ;;
  ;; Post-fix: the SET clause uses "failed_login_count + 1" so even
  ;; two failures issued from the SAME loaded user record advance
  ;; the counter twice.
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (let* ((user (seed-user r "race@x" "hunter22-extra")))
           (clauth::record-failed-attempt! r 'u user 100 60)
           (clauth::record-failed-attempt! r 'u user 100 60)
           (let ((reloaded (clecto:repo-get-by r 'u '(:email "race@x"))))
             (is (= 2 (getf reloaded :failed-login-count)))))
      (clecto:sqlite-close a))))

(test lockout-respects-custom-thresholds
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (seed-user r "lk3@x" "hunter22-extra")
           ;; threshold of 2, very short window
           (clauth:authenticate-with-lockout r 'u "lk3@x" "wrong"
                                             :max-attempts 2)
           (clauth:authenticate-with-lockout r 'u "lk3@x" "wrong"
                                             :max-attempts 2)
           (multiple-value-bind (user reason)
               (clauth:authenticate-with-lockout r 'u "lk3@x" "wrong"
                                                 :max-attempts 2)
             (is (null user))
             (is (eq :locked reason))))
      (clecto:sqlite-close a))))

;;; --- B2: API tokens ---

(clecto:defschema auth-token "auth_tokens"
  (:id         :integer :primary-key t)
  (:user-id    :integer)
  (:token-hash :string)
  (:context    :string)
  (:authenticated-at :naive-datetime)
  (:session-version :integer)
  (:expires-at :naive-datetime)
  (:timestamps))

(defun fresh-repo-with-tokens ()
  (multiple-value-bind (r a) (fresh-repo)
    (clecto:repo-execute r
     "CREATE TABLE auth_tokens (id INTEGER PRIMARY KEY,
                                user_id INTEGER,
                                token_hash TEXT UNIQUE,
                                context TEXT,
                                authenticated_at TEXT,
                                session_version INTEGER DEFAULT 0,
                                expires_at TEXT,
                                inserted_at TEXT, updated_at TEXT)")
    (values r a)))

(test api-token-mint-and-validate
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "t@x" "hunter22-extra"))
                (uid (getf user :id)))
           (multiple-value-bind (raw record)
               (clauth:create-token r 'auth-token user)
             (is (stringp raw))
             (is (= 64 (length raw)))
             (is (not (search raw (or (getf record :token-hash) ""))))
             ;; finding by the raw token returns the row
             (let ((found (clauth:find-and-validate-token r 'auth-token raw)))
               (is (not (null found)))
               (is (= uid (getf found :user-id))))
             ;; a different token doesn't match
             (is (null (clauth:find-and-validate-token r 'auth-token
                                                       "deadbeefxxxx")))))
      (clecto:sqlite-close a))))

(test api-token-respects-context
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "t2@x" "hunter22-extra"))
                (uid (getf user :id))
                (raw (nth-value 0 (clauth:create-token r 'auth-token user
                                                       :context "api"))))
           ;; same token, wrong context
           (is (null (clauth:find-and-validate-token
                      r 'auth-token raw :context "remember-me")))
           ;; right context
           (is (not (null (clauth:find-and-validate-token
                           r 'auth-token raw :context "api")))))
      (clecto:sqlite-close a))))

(test api-token-expiry
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "t3@x" "hunter22-extra"))
                (uid (getf user :id))
                ;; already-expired token
                (raw (nth-value 0 (clauth:create-token r 'auth-token user
                                                       :expires-in -10))))
           (is (null (clauth:find-and-validate-token r 'auth-token raw))))
      (clecto:sqlite-close a))))

(test api-token-revoke
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "t4@x" "hunter22-extra"))
                (uid (getf user :id))
                (raw nil)
                (rec nil))
           (multiple-value-bind (r1 rec1)
               (clauth:create-token r 'auth-token user)
             (setf raw r1 rec rec1))
           (clauth:revoke-token r 'auth-token (getf rec :id))
           (is (null (clauth:find-and-validate-token r 'auth-token raw))))
      (clecto:sqlite-close a))))

(test api-token-revoke-all-by-context
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "t5@x" "hunter22-extra"))
                (uid (getf user :id))
                (api-raw (nth-value 0 (clauth:create-token r 'auth-token user
                                                           :context "api")))
                (rm-raw  (nth-value 0 (clauth:create-token r 'auth-token user
                                                           :context "remember-me"))))
           (clauth:revoke-all-tokens-for-user r 'auth-token uid :context "api")
           (is (null (clauth:find-and-validate-token r 'auth-token api-raw)))
           ;; remember-me survived
           (is (not (null (clauth:find-and-validate-token r 'auth-token rm-raw
                                                          :context "remember-me")))))
      (clecto:sqlite-close a))))

(test bearer-plug-loads-user
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "b@x" "hunter22-extra"))
                (uid (getf user :id))
                (raw (nth-value 0 (clauth:create-token r 'auth-token user))))
           (let* ((plug (clauth:load-current-user-from-bearer
                         r :user-schema 'u :token-schema 'auth-token))
                  (conn (clug:make-conn
                         :req (list :headers
                                    (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "authorization" h)
                                            (format nil "Bearer ~a" raw))
                                      h))))
                  (out (funcall plug conn)))
             (is (not (null (clauth:current-user out))))
             (is (= uid (getf (clauth:current-user out) :id))))
           ;; missing / malformed bearer is a no-op (no current-user set)
           (let ((out (funcall (clauth:load-current-user-from-bearer
                                r :user-schema 'u :token-schema 'auth-token)
                               (clug:make-conn :req (list :headers
                                                          (make-hash-table :test 'equal))))))
             (is (null (clauth:current-user out)))))
      (clecto:sqlite-close a))))

;;; --- C1: require-role ---

(defun conn-with-current-user (user)
  (clug:assign (clug:make-conn) :current-user user))

(test require-role-passes-matching-role
  (let* ((conn (conn-with-current-user '(:id 1 :role "admin")))
         (out (funcall (clauth:require-role "admin") conn)))
    (is (not (clug:conn-halted-p out)))))

(test require-role-forbids-wrong-role
  (let* ((conn (conn-with-current-user '(:id 1 :role "user")))
         (out (funcall (clauth:require-role "admin") conn)))
    (is (clug:conn-halted-p out))
    (is (= 403 (clug:conn-status out)))))

(test require-role-accepts-any-of-many
  (let* ((conn (conn-with-current-user '(:id 1 :role "mod")))
         (out (funcall (clauth:require-role '("admin" "mod")) conn)))
    (is (not (clug:conn-halted-p out)))))

(test require-role-401s-with-no-user
  (let* ((conn (clug:make-conn))
         (out (funcall (clauth:require-role "admin") conn)))
    (is (clug:conn-halted-p out))
    (is (= 401 (clug:conn-status out)))))

(test require-role-honors-custom-reader
  (let* ((conn (conn-with-current-user
                '(:id 1 :roles ("admin" "mod"))))
         (reader (lambda (u) (first (getf u :roles))))
         (out (funcall (clauth:require-role "admin" :reader reader) conn)))
    (is (not (clug:conn-halted-p out)))))

(test require-role-rejects-empty-allowed
  (signals error (clauth:require-role nil))
  (signals error (clauth:require-role '())))

(test require-role-supports-multi-role-reader
  ;; Reader returns a LIST of roles; the plug accepts when any element
  ;; intersects ALLOWED.
  (let* ((conn (conn-with-current-user '(:id 1 :roles ("editor" "admin"))))
         (reader (lambda (u) (getf u :roles)))
         (out (funcall (clauth:require-role "admin" :reader reader) conn)))
    (is (not (clug:conn-halted-p out))))
  (let* ((conn (conn-with-current-user '(:id 1 :roles ("editor" "viewer"))))
         (reader (lambda (u) (getf u :roles)))
         (out (funcall (clauth:require-role "admin" :reader reader) conn)))
    (is (clug:conn-halted-p out))
    (is (= 403 (clug:conn-status out)))))

(test require-role-reader-errors-fail-closed
  ;; A misconfigured reader signals — the plug catches and 403s instead
  ;; of 500-ing.
  (let* ((conn (conn-with-current-user '(:id 1 :role "admin")))
         (reader (lambda (u) (declare (ignore u)) (error "boom")))
         (out (funcall (clauth:require-role "admin" :reader reader) conn)))
    (is (clug:conn-halted-p out))
    (is (= 403 (clug:conn-status out)))))

;;; --- D1: auth telemetry ---

(test auth-telemetry-fires-on-login-logout-and-auth
  (let* ((events nil)
         (clauth:*auth-telemetry* (lambda (e p) (push (cons e p) events))))
    (multiple-value-bind (r a) (fresh-repo)
      (unwind-protect
           (let* ((user (seed-user r "tel@x" "hunter22-extra"))
                  (store (clug:make-memory-store))
                  (app (clug:with-session
                         (lambda (env)
                           (let ((c (clug:make-conn :req env)))
                             (clauth:login c user)
                             (clauth:logout c)
                             (list 200 nil '(""))))
                         :store store)))
             (funcall app (env-with-cookie nil))
             ;; success login + success authenticate-with-lockout
             (clauth:authenticate-with-lockout r 'u "tel@x" "hunter22-extra")
             (clauth:authenticate-with-lockout r 'u "tel@x" "wrong")
             (clauth:authenticate-with-lockout r 'u "ghost@x" "x")
             (let ((kinds (mapcar #'car events)))
               (is (member :login         kinds))
               (is (member :logout        kinds))
               (is (member :auth-success  kinds))
               (is (member :auth-failure  kinds))))
        (clecto:sqlite-close a)))))

(test auth-telemetry-handler-error-doesnt-break-login
  ;; A misconfigured sink must not abort authentication.
  (setf clauth::*auth-telemetry-handler-failed* nil)
  (let* ((clauth:*auth-telemetry* (lambda (e p) (declare (ignore e p))
                                    (error "boom"))))
    (multiple-value-bind (r a) (fresh-repo)
      (unwind-protect
           (let* ((user (seed-user r "te@x" "hunter22-extra")))
             (is (eq user user))   ; insert succeeded despite broken sink
             (multiple-value-bind (got reason)
                 (clauth:authenticate-with-lockout r 'u "te@x" "hunter22-extra")
               (declare (ignore reason))
               (is (not (null got)))))
        (clecto:sqlite-close a)))))

;;; --- D2: logout-all-sessions ---

(test logout-all-sessions-purges-tokens
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "all@x" "hunter22-extra"))
                (uid  (getf user :id))
                (raw  (nth-value 0 (clauth:create-token r 'auth-token user))))
           (clauth:logout-all-sessions r 'u 'auth-token uid)
           (is (null (clauth:find-and-validate-token r 'auth-token raw))))
      (clecto:sqlite-close a))))

;;; --- D3: remember-me ---

(test remember-me-survives-session-expiry
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "rm@x" "hunter22-extra"))
                (store (clug:make-memory-store))
                ;; first request: log in with remember-me set
                (login-app
                  (clug:with-session
                    (clug:to-clack-app
                     (lambda (c)
                       (clauth:login-with-remember-me c user r 'auth-token
                                                      :secure nil)))
                    :store store))
                (login-resp (funcall login-app (env-with-cookie nil)))
                (rm-cookie
                  (loop for (k v) on (second login-resp) by #'cddr
                        when (and (stringp k) (string= k "set-cookie")
                                  (search clauth:*remember-me-cookie-key* v))
                        return v))
                ;; now the session is gone (different store) but the
                ;; remember-me cookie should re-load the user
                (fresh-store (clug:make-memory-store))
                (load-app
                  (clug:with-session
                    (clug:to-clack-app
                     (clug:pipeline
                      (clauth:load-current-user-or-remember-me
                       r :user-schema 'u :token-schema 'auth-token)
                      (lambda (c)
                        (clug:put-resp c 200
                                       (if (clauth:current-user c)
                                           "alive" "anon")))))
                    :store fresh-store))
                (rm-value (let* ((eq (position #\= rm-cookie))
                                 (semi (position #\; rm-cookie)))
                            (subseq rm-cookie (1+ eq) semi)))
                (response (funcall load-app
                                   (env-with-cookie
                                    (format nil "~a=~a"
                                            clauth:*remember-me-cookie-key*
                                            rm-value)))))
           (is (equal "alive" (first (third response)))))
      (clecto:sqlite-close a))))

(test logout-with-repo-revokes-remember-me
  ;; Audit H1: bare logout used to leave the remember-me row + cookie
  ;; intact, silently re-logging the user in on the next request.
  ;; logout now accepts :repo / :token-schema and revokes both.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "lwo@x" "hunter22-extra"))
                (raw  (nth-value 0 (clauth:create-token r 'auth-token user
                                                        :context clauth:*remember-me-context*))))
           ;; simulate a request carrying the remember-me cookie
           (let* ((conn (clug:make-conn
                         :req (list :headers
                                    (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "cookie" h)
                                            (format nil "~a=~a"
                                                    clauth:*remember-me-cookie-key*
                                                    raw))
                                      h)
                                    :clug.session-state (list :sid nil
                                                              :dirty nil
                                                              :destroy nil
                                                              :rotate nil
                                                              :original-sid nil)
                                    :clug.session (make-hash-table :test 'equal)))))
             (clauth:logout conn :repo r :token-schema 'auth-token)
             ;; row purged
             (is (null (clauth:find-and-validate-token
                        r 'auth-token raw
                        :context clauth:*remember-me-context*)))))
      (clecto:sqlite-close a))))

(test credentials-changed-event-fires
  ;; Audit H2: telemetry catalog listed :credentials-changed but no
  ;; clauth code path ever fired it. bump-session-version now emits.
  (let* ((events nil)
         (clauth:*auth-telemetry* (lambda (e p) (push (list e p) events))))
    (multiple-value-bind (r a) (fresh-repo)
      (unwind-protect
           (let* ((user (seed-user r "cc@x" "hunter22-extra")))
             (clecto:repo-update r (clauth:change-password-changeset
                                    (list* :__schema__ 'u user)
                                    '(:current-password "hunter22-extra"
                                      :password "fresh-pw-99"
                                      :password-confirmation "fresh-pw-99")))
             (is (some (lambda (e) (eq :credentials-changed (first e)))
                       events)))
        (clecto:sqlite-close a)))))

(test remember-me-rejected-after-password-change
  ;; update-password! deletes the token row; remember-me cookies now
  ;; pointing at deleted rows fail to authenticate.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "rm2@x" "hunter22-extra"))
                (raw  (nth-value 0 (clauth:create-token r 'auth-token user))))
           (clauth:update-password! r 'u 'auth-token user
             '(:current-password "hunter22-extra"
               :password "fresh-pw-123"
               :password-confirmation "fresh-pw-123"))
           (let* ((app (clug:with-session
                         (clug:to-clack-app
                          (clug:pipeline
                           (clauth:load-current-user-or-remember-me
                            r :user-schema 'u :token-schema 'auth-token)
                           (lambda (c)
                             (clug:put-resp c 200
                                            (if (clauth:current-user c)
                                                "alive" "anon")))))
                         :store (clug:make-memory-store)))
                  (response (funcall app
                                     (env-with-cookie
                                      (format nil "~a=~a"
                                              clauth:*remember-me-cookie-key*
                                              raw)))))
             (is (equal "anon" (first (third response))))))
      (clecto:sqlite-close a))))

;;; --- phx.gen.auth mirror: return-to + redirect plugs ---

(test require-auth-redirect-mode-captures-return-to-on-get
  (let* ((store (clug:make-memory-store))
         (app (clug:with-session
                (clug:to-clack-app
                 (lambda (c)
                   (clauth:require-auth c :redirect-to "/login")))
                :store store))
         (env (list :request-method :get :path-info "/dashboard"
                    :query-string nil
                    :headers (make-hash-table :test 'equal)))
         (response (funcall app env)))
    (is (= 302 (first response)))
    (is (equal "/login"
               (loop for (k v) on (second response) by #'cddr
                     when (and (stringp k) (string= k "location"))
                     return v)))))

(test require-auth-redirect-mode-skips-return-to-on-post
  (let* ((store (clug:make-memory-store))
         (captured nil)
         (app (clug:with-session
                (clug:to-clack-app
                 (lambda (c)
                   (let ((out (clauth:require-auth c :redirect-to "/login")))
                     (setf captured (clug:get-session-value
                                     out clauth:*session-return-to-key*))
                     out)))
                :store store))
         (env (list :request-method :post :path-info "/orders/new"
                    :query-string nil
                    :headers (make-hash-table :test 'equal))))
    (funcall app env)
    ;; POST path NOT captured — Phoenix's contract.
    (is (null captured))))

(test redirect-if-authenticated-bounces-logged-in-user
  (let* ((conn (conn-with-current-user '(:id 1)))
         (out (funcall (clauth:redirect-if-authenticated :redirect-to "/home")
                       conn)))
    (is (clug:conn-halted-p out))
    (is (= 302 (clug:conn-status out)))))

(test redirect-if-authenticated-passes-anonymous
  (let* ((conn (clug:make-conn))
         (out (funcall (clauth:redirect-if-authenticated :redirect-to "/home")
                       conn)))
    (is (not (clug:conn-halted-p out)))))

(test valid-email-shape-p-matches-phoenix-regex
  ;; Phoenix: ~r/^[^@,;\s]+@[^@,;\s]+$/
  (is (clauth:valid-email-shape-p "a@b"))
  (is (clauth:valid-email-shape-p "user.name+tag@example.com"))
  (is (not (clauth:valid-email-shape-p "no-at-sign")))
  (is (not (clauth:valid-email-shape-p "two@@signs")))
  (is (not (clauth:valid-email-shape-p "has space@x")))
  (is (not (clauth:valid-email-shape-p "a,b@x")))
  (is (not (clauth:valid-email-shape-p "@x")))
  (is (not (clauth:valid-email-shape-p "x@"))))

;;; --- audit follow-ups ---

(test log-in-and-redirect-rejects-open-redirect-target
  ;; A planted return-to of "//evil.com" must NOT become Location.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "or@x" "hunter22-extra"))
                (store (clug:make-memory-store))
                (app (clug:with-session
                       (clug:to-clack-app
                        (lambda (c)
                          ;; pretend the session has a malicious return-to
                          (setf c (clug:put-session-value
                                   c clauth:*session-return-to-key*
                                   "//evil.com/steal"))
                          (clauth:log-in-and-redirect
                           c user :repo r :token-schema 'auth-token
                           :default-path "/safe")))
                       :store store))
                (response (funcall app
                                   (list :request-method :get
                                         :path-info "/" :query-string nil
                                         :headers (make-hash-table :test 'equal))))
                (location (loop for (k v) on (second response) by #'cddr
                                when (and (stringp k) (string= k "location"))
                                return v)))
           (is (= 302 (first response)))
           (is (equal "/safe" location)))
      (clecto:sqlite-close a))))

(test return-to-includes-query-string
  (let* ((store (clug:make-memory-store))
         (captured nil)
         (app (clug:with-session
                (clug:to-clack-app
                 (lambda (c)
                   (let ((out (clauth:require-auth c :redirect-to "/login")))
                     (setf captured (clug:get-session-value
                                     out clauth:*session-return-to-key*))
                     out)))
                :store store))
         (env (list :request-method :get
                    :path-info "/dashboard"
                    :query-string "tab=billing&sort=desc"
                    :headers (make-hash-table :test 'equal))))
    (funcall app env)
    (is (equal "/dashboard?tab=billing&sort=desc" captured))))

(test session-timeout-fires-for-token-based-sessions
  ;; H3 regression: under token-mode, current-user-id is nil so the
  ;; OLD session-timeout short-circuited. Now it also checks the
  ;; session-token cell.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "tt@x" "hunter22-extra"))
                (raw (nth-value 0 (clauth:build-session-token r 'auth-token user)))
                (store (clug:make-memory-store))
                (sid "tok-sid")
                (data (let ((h (make-hash-table :test 'equal)))
                        (setf (gethash :user-token h) raw)
                        (setf (gethash :last-activity-at h)
                              (- (get-universal-time) 9999))
                        h))
                (_ (clug:store-save store sid data))
                (app (clug:with-session
                       (clug:to-clack-app
                        (clug:pipeline
                         (clauth:session-timeout :max-idle-seconds 1800)
                         (clauth:load-current-user r 'u :token-schema 'auth-token)
                         (lambda (c)
                           (clug:put-resp c 200
                                          (if (clauth:current-user c)
                                              "alive" "expired")))))
                       :store store))
                (response (funcall app
                                   (env-with-cookie (format nil "clug.session=~a" sid)))))
           (declare (ignore _))
           ;; session-timeout saw the token, decided "stale", called logout.
           ;; Token row should be gone too.
           (is (equal "expired" (first (third response))))
           (is (null (clauth:find-and-validate-token r 'auth-token raw))))
      (clecto:sqlite-close a))))

(test require-role-uses-equal-no-coercion
  ;; Documenting design: role comparison is EQUAL, so "admin" (string)
  ;; does NOT match :admin (keyword). Apps choose one shape and stick
  ;; with it across schema, reader, and allowed-list.
  (let* ((conn (conn-with-current-user '(:id 1 :role "admin")))
         (out (funcall (clauth:require-role :admin) conn)))
    (is (clug:conn-halted-p out))
    (is (= 403 (clug:conn-status out)))))

(test bearer-plug-rejected-after-password-change
  ;; Phoenix-style: changing the password deletes every existing token,
  ;; so the bearer plug can't find the row anymore.
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "stale@x" "hunter22-extra"))
                (raw  (nth-value 0 (clauth:create-token r 'auth-token user))))
           (let* ((plug (clauth:load-current-user-from-bearer
                         r :user-schema 'u :token-schema 'auth-token))
                  (conn (clug:make-conn
                         :req (list :headers
                                    (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "authorization" h)
                                            (format nil "Bearer ~a" raw))
                                      h)))))
             (is (not (null (clauth:current-user (funcall plug conn))))))
           (clauth:update-password! r 'u 'auth-token user
             '(:current-password "hunter22-extra"
               :password "fresh-secret-99"
               :password-confirmation "fresh-secret-99"))
           ;; same token, same plug, but now rejected
           (let* ((plug (clauth:load-current-user-from-bearer
                         r :user-schema 'u :token-schema 'auth-token))
                  (conn (clug:make-conn
                         :req (list :headers
                                    (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "authorization" h)
                                            (format nil "Bearer ~a" raw))
                                      h)))))
             (is (null (clauth:current-user (funcall plug conn))))))
      (clecto:sqlite-close a))))

(test revoke-tokens-on-credential-change-clears-store
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "rev@x" "hunter22-extra"))
                (uid (getf user :id))
                (raw (nth-value 0 (clauth:create-token r 'auth-token user))))
           (clauth:revoke-tokens-on-credential-change r 'auth-token uid)
           (is (null (clauth:find-and-validate-token r 'auth-token raw))))
      (clecto:sqlite-close a))))

(test bearer-plug-rejects-wrong-context
  (multiple-value-bind (r a) (fresh-repo-with-tokens)
    (unwind-protect
         (let* ((user (seed-user r "b2@x" "hunter22-extra"))
                (uid (getf user :id))
                ;; mint a remember-me token; bearer plug looking for :api
                ;; must not accept it.
                (raw (nth-value 0 (clauth:create-token r 'auth-token user
                                                       :context "remember-me"))))
           (let* ((plug (clauth:load-current-user-from-bearer
                         r :user-schema 'u :token-schema 'auth-token
                         :context "api"))
                  (conn (clug:make-conn
                         :req (list :headers
                                    (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "authorization" h)
                                            (format nil "Bearer ~a" raw))
                                      h))))
                  (out (funcall plug conn)))
             (is (null (clauth:current-user out)))))
      (clecto:sqlite-close a))))

(test register-surfaces-unique-email-collision
  (multiple-value-bind (r a) (fresh-repo)
    (unwind-protect
         (progn
           (clecto:repo-insert r (clauth:register-changeset
                                  'u '(:email "a@b" :password "hunter22-extra"
                                       :password-confirmation "hunter22-extra")))
           (multiple-value-bind (rec err)
               (clecto:repo-insert r (clauth:register-changeset
                                      'u '(:email "a@b" :password "hunter22-extra"
                                           :password-confirmation "hunter22-extra")))
             (is (null rec))
             (is (assoc :email (clecto:cs-errors err)))))
      (clecto:sqlite-close a))))
