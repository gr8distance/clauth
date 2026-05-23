(in-package #:clauth)

;;; Schema helper for the canonical user table. Splice the return value
;;; into a clecto defschema body:
;;;
;;;   (defschema user "users"
;;;     (:id :integer :primary-key t)
;;;     #.@(clauth:auth-fields)
;;;     (:timestamps))
;;;
;;; ...or just copy these fields into your own schema. Nothing in clauth
;;; requires the schema to be exactly this shape — only that the fields
;;; clauth touches (:email, :password-hash, :password,
;;; :password-confirmation, :confirmed-at) exist with these types.

(defun auth-fields ()
  "Return field specs for a minimal authenticated user. Splice into a
clecto schema's body.

:session-version is bumped whenever the user's credentials change
(password, email). LOAD-CURRENT-USER refuses to attach the record if
the cookie's recorded version is below the stored value — so changing
your password from one device invalidates every other device's
session on its next request."
  '((:email                 :string)
    (:password-hash         :string)
    (:confirmed-at          :naive-datetime)
    (:session-version       :integer)
    ;; Lockout / rate-limit bookkeeping. Both nil-ok for users who
    ;; have never failed a login.
    (:failed-login-count    :integer)
    (:locked-until          :naive-datetime)
    ;; Virtual: present on the changeset but never written to SQL.
    (:password              :string :virtual t)
    (:password-confirmation :string :virtual t)
    (:current-password      :string :virtual t)))
