(defpackage #:clauth
  (:use #:cl)

  ;; --- password ---
  (:export
   #:hash-password #:verify-password
   #:*argon2-block-count* #:*argon2-iterations* #:*argon2-key-length*)

  ;; --- token ---
  (:export
   #:generate-token #:token-hash #:verify-token-hash)

  ;; --- schema helpers ---
  (:export
   #:auth-fields)

  ;; --- changeset ---
  (:export
   #:register-changeset #:password-changeset)

  ;; --- repo ---
  (:export
   #:authenticate)

  ;; --- conn / session integration ---
  (:export
   #:login #:logout #:current-user-id
   #:load-current-user #:current-user #:require-auth))
