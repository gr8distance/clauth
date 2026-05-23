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
   #:register-changeset #:password-changeset
   #:change-password-changeset #:change-email-changeset)

  ;; --- repo ---
  (:export
   #:authenticate
   #:authenticate-with-lockout
   #:account-locked-p
   #:*lockout-max-attempts* #:*lockout-duration-seconds*)

  ;; --- conn / session integration ---
  (:export
   #:login #:logout #:current-user-id
   #:load-current-user #:current-user #:require-auth #:require-role
   #:session-timeout)

  ;; --- telemetry ---
  (:export
   #:*auth-telemetry* #:emit-auth-event #:auth-event-fields)

  ;; --- API tokens ---
  (:export
   #:auth-token-fields
   #:create-token #:find-and-validate-token
   #:revoke-token #:revoke-all-tokens-for-user
   #:revoke-tokens-on-credential-change
   #:logout-all-sessions
   #:load-current-user-from-bearer
   #:*default-api-token-ttl-seconds*)

  ;; --- remember-me ---
  (:export
   #:login-with-remember-me
   #:clear-remember-me-cookie #:revoke-remember-me
   #:load-current-user-or-remember-me
   #:*remember-me-cookie-key* #:*remember-me-ttl-seconds*
   #:*remember-me-context*))
