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
   #:change-password-changeset #:change-email-changeset
   #:validate-email-shape #:valid-email-shape-p)

  ;; --- repo ---
  (:export
   #:authenticate
   #:authenticate-with-lockout
   #:account-locked-p
   #:*lockout-max-attempts* #:*lockout-duration-seconds*)

  ;; --- conn / session integration ---
  (:export
   #:login #:logout #:current-user-id #:current-session-token
   #:load-current-user #:current-user
   #:require-auth #:require-role #:redirect-if-authenticated
   #:log-in-and-redirect
   #:maybe-store-return-to #:*session-return-to-key*
   #:session-timeout
   #:*session-token-key*)

  ;; --- telemetry ---
  (:export
   #:*auth-telemetry* #:emit-auth-event #:auth-event-fields)

  ;; --- API tokens ---
  (:export
   #:auth-token-fields
   #:create-token #:find-and-validate-token
   #:revoke-token #:revoke-all-tokens-for-user
   #:revoke-tokens-on-credential-change
   #:update-password! #:update-email!
   #:logout-all-sessions
   #:load-current-user-from-bearer
   #:*default-api-token-ttl-seconds*
   #:*session-context* #:*session-token-validity-seconds*
   #:*session-token-reissue-after-seconds*
   #:build-session-token #:load-user-by-session-token
   #:delete-session-token)

  ;; --- remember-me ---
  (:export
   #:login-with-remember-me
   #:clear-remember-me-cookie #:revoke-remember-me
   #:load-current-user-or-remember-me
   #:*remember-me-cookie-key* #:*remember-me-ttl-seconds*
   #:*remember-me-context*))
