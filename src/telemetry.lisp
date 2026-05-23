(in-package #:clauth)

;;; Auth-event telemetry. Mirrors clecto's *telemetry* in shape but
;;; fires for auth lifecycle events: login, logout, successful and
;;; failed authentications, lockouts, credential changes.
;;;
;;; Wire up a sink at app boot:
;;;
;;;   (setf clauth:*auth-telemetry*
;;;         (lambda (event payload)
;;;           (log:info "auth ~a ~a" event payload)))
;;;
;;; Or persist to a DB:
;;;
;;;   (setf clauth:*auth-telemetry*
;;;         (lambda (event payload)
;;;           (clecto:repo-insert *repo* (cast 'auth-event
;;;             (list :event (string event)
;;;                   :user-id (getf payload :user-id)
;;;                   ...))))).
;;;
;;; Errors raised inside the callback are swallowed (logged once to
;;; *error-output*) so a misconfigured sink can't break authentication.

(defvar *auth-telemetry* nil
  "Function (event payload) called from clauth lifecycle hooks.
EVENT is a keyword (see EMIT-AUTH-EVENT for the catalog). PAYLOAD is a
plist; the keys depend on the event. NIL disables.

The callback runs INLINE on the request thread. A slow sink (DB
write, HTTP call, file IO) adds its latency to every login / auth /
token operation; for production, queue the payload onto a worker
thread (bordeaux-threads or a job library) and return immediately.

PII NOTE: failure events carry the :email the user typed at the
login form, which may belong to a third party they mistyped. Treat
the audit log as containing user-submitted PII and apply retention
limits accordingly.")

(defvar *auth-telemetry-handler-failed* nil
  "Latches to T the first time the auth-telemetry callback signals,
emits a one-time warning to *error-output*, and then silently swallows
subsequent failures so a busted sink can't take down auth.")

(defun emit-auth-event (event payload)
  "Fire EVENT through *AUTH-TELEMETRY*. EVENTS:

  :login                — user logged in (:user-id)
  :logout               — user (or session) logged out (:user-id may be NIL)
  :auth-success         — password verified ok (:user-id)
  :auth-failure         — wrong creds / missing user (:email, :reason)
  :auth-locked          — account is currently locked, attempt blocked
                          (:user-id, :email)
  :account-locked       — this attempt is what tripped the lock
                          (:user-id, :locked-until)
  :credentials-changed  — password or email changed via clauth helpers
                          (:user-id, :change)
  :token-created        — bearer / remember-me token minted
                          (:user-id, :context)
  :token-revoked        — token explicitly revoked
                          (:user-id, :context-or-:all)

Sensitive values (passwords, raw tokens) are NEVER included. Email
appears only in failure events because the audit trail needs it to
correlate brute-force attempts."
  (when *auth-telemetry*
    (handler-case (funcall *auth-telemetry* event payload)
      (error (e)
        (unless *auth-telemetry-handler-failed*
          (setf *auth-telemetry-handler-failed* t)
          (format *error-output*
                  "~&clauth: *auth-telemetry* signaled ~a; ~
                   silencing further telemetry errors~%" e))
        nil))))

(defun auth-event-fields ()
  "Splice into a clecto schema body if you want a DB-backed audit log:

  (clecto:defschema auth-event \"auth_events\"
    (:id :integer :primary-key t)
    #.@(clauth:auth-event-fields)
    (:timestamps))

The clauth helpers don't write to this table themselves; sinks the
caller wires into *AUTH-TELEMETRY* do."
  '((:event       :string)
    (:user-id     :integer)
    (:email       :string)
    (:reason      :string)
    (:ip          :string)
    (:user-agent  :string)
    (:metadata    :string)))   ; freeform JSON
