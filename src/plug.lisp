(in-package #:clauth)

;;; Conn / session integration. Sits on top of clug/session so the user
;;; ID rides in the cookie-backed session store, not in a stateless JWT.

(defvar *current-user-key* :current-user
  "conn-assign key under which LOAD-CURRENT-USER stashes the user record.")

(defvar *session-token-key* :user-token
  "Session key under which LOGIN writes the raw session token (looked
up against auth_tokens with context = *session-context* on subsequent
requests). Mirrors phx.gen.auth's :user_token session key.")

;; Legacy: kept so existing code that referenced this still compiles,
;; but the user-id is no longer the auth fact — the session token is.
(defvar *session-user-key* :user-id
  "Deprecated. Session no longer stores the user id directly; the
session token (under *session-token-key*) is the authoritative key.
Kept so callers reading it through clug:get-session-value don't break.")

(defvar *session-version-key* :session-version
  "Session key recording the user's session-version at the time of
LOGIN. LOAD-CURRENT-USER compares it against the stored value on the
user row; if the stored value advanced (because change-password or
change-email bumped it from another device), this session is forced
to log out.")

(defun login (conn user &key repo token-schema)
  "Mark CONN as authenticated as USER. USER MUST be a loaded record —
we mint a session token bound to it and stash the raw value in the
session cookie. STRINGS are not accepted; bare integers are rejected
because we need :id and :session-version off the record.

REPO and TOKEN-SCHEMA select the auth_tokens table. When omitted, the
legacy cookie-only path is used (no DB row, no per-device revocation
— here only for migrations from the old API).

Rotates the session id to defend against fixation: an attacker who
planted a session cookie pre-login no longer rides the new privilege
level. Fires :login telemetry."
  (let* ((id (etypecase user
               (cons (or (getf user :id)
                         (error "login: user record has no :id")))
               (integer
                (error "login: pass the loaded record, not the bare id"))))
         (token (when (and repo token-schema)
                  (nth-value 0 (build-session-token repo token-schema user)))))
    (let ((c (if token
                 (clug:put-session-value conn *session-token-key* token)
                 ;; Legacy fallback: store user-id directly.
                 (clug:put-session-value conn *session-user-key* id))))
      (let ((out (clug:rotate-session-id c)))
        (emit-auth-event :login (list :user-id id))
        out))))

(defun logout (conn &key repo token-schema)
  "Clear the session. When REPO and TOKEN-SCHEMA are supplied:
  - delete the session token row from auth_tokens (so the next request
    from this device sees an invalid token and re-authenticates),
  - revoke the remember-me cookie + its DB row.
Pass them whenever auth_tokens is in use. Mirrors Phoenix's
log_out_user contract."
  (let* ((token (clug:get-session-value conn *session-token-key*))
         (id (current-user-id conn)))
    (when (and repo token-schema token)
      (delete-session-token repo token-schema token))
    (emit-auth-event :logout (list :user-id id))
    (let ((c (clug:clear-session conn)))
      (if (and repo token-schema)
          (funcall (symbol-function 'revoke-remember-me) c repo token-schema)
          c))))

(defun current-user-id (conn)
  "Legacy: returns the user-id directly from the session.

This used to be the auth fact; in the DB-backed session token world,
the truth is the token + repo lookup, and this function is only
useful for code that hasn't been migrated yet. New code should call
CURRENT-USER and read its :ID."
  (let ((state (getf (clug:conn-req conn) :clug.session-state)))
    (unless (getf state :destroy)
      (clug:get-session-value conn *session-user-key*))))

(defun current-session-token (conn)
  "Read the raw session token from the cookie session, or NIL.
LOAD-CURRENT-USER hashes it and queries auth_tokens on each request."
  (let ((state (getf (clug:conn-req conn) :clug.session-state)))
    (unless (getf state :destroy)
      (clug:get-session-value conn *session-token-key*))))

(defun load-current-user (repo user-schema &key token-schema)
  "Return a plug that authenticates the user for this request.

Phoenix-style DB-backed mode (when TOKEN-SCHEMA is supplied):
  1. Read the raw session token from the cookie session.
  2. Hash it and look up the auth_tokens row.
  3. Load the user, assign as :current-user.
  4. If the token is past *session-token-reissue-after-seconds* of its
     life, mint a fresh one (and delete the old).

Legacy mode (TOKEN-SCHEMA omitted): the session carries a :user-id
directly and we just repo-get. No per-device revocation, no reissue.
Kept so call sites that haven't migrated still work; new code should
always pass :token-schema."
  (if token-schema
      (token-based-load-current-user repo user-schema token-schema)
      (legacy-load-current-user repo user-schema)))

(defun legacy-load-current-user (repo user-schema)
  (lambda (conn)
    (let ((id (current-user-id conn)))
      (cond
        ((null id) conn)
        (t
         (let ((user (clecto:repo-get repo user-schema id)))
           (cond
             ((null user) (logout conn))
             ((session-version-stale-p conn user) (logout conn))
             (t (clug:assign conn *current-user-key* user)))))))))

(defun token-based-load-current-user (repo user-schema token-schema)
  (lambda (conn)
    (let ((token (current-session-token conn)))
      (cond
        ((null token) conn)
        (t
         (multiple-value-bind (user record)
             (load-user-by-session-token repo user-schema token-schema token)
           (cond
             ((null user)
              ;; Stale / expired / deleted — drop the session.
              (logout conn :repo repo :token-schema token-schema))
             (t
              (let ((c (clug:assign conn *current-user-key* user)))
                (maybe-reissue-session-token c repo token-schema user record))))))))))

(defun maybe-reissue-session-token (conn repo token-schema user record)
  "If RECORD is past the reissue half-life, mint a new session token
and delete the old. Mirrors Phoenix's maybe_reissue_user_session_token.

Compares :authenticated-at (set by CREATE-TOKEN in UTC via
NOW-UTC-DATETIME) against a UTC cutoff so the half-life is stable
across timezones. Uses :authenticated-at, not :inserted-at, because
clecto's automatic timestamps are local-time naïve datetimes and
mixing them with UTC strings drifts the cutoff by up to a TZ offset.

KNOWN GAP: delete-then-insert is not atomic. If the process dies
between the two, the user is logged out on next request. Phoenix has
the same shape. A proper fix needs an UPDATE on token-hash that
clecto doesn't expose yet."
  (let* ((created (getf record :authenticated-at))
         (cutoff  (universal-time-to-naive
                   (- (get-universal-time)
                      *session-token-reissue-after-seconds*))))
    (cond
      ((or (null created) (string< created cutoff))
       (revoke-token repo token-schema (getf record :id))
       (let ((raw (nth-value 0 (build-session-token repo token-schema user))))
         (clug:put-session-value conn *session-token-key* raw)))
      (t conn))))

(defun session-version-stale-p (conn user)
  "T when this session's recorded :session-version is below the stored
value on USER — meaning the user changed credentials elsewhere since
this cookie was minted. A missing version in either place is treated
as 0 so legacy data stays compatible."
  (let ((cookie-v (or (clug:get-session-value conn *session-version-key*) 0))
        (stored-v (or (getf user :session-version) 0)))
    (< cookie-v stored-v)))

(defun current-user (conn)
  "Retrieve the user record attached by LOAD-CURRENT-USER."
  (clug:get-assign conn *current-user-key*))

;;; Idle-session-timeout plug was removed. phx.gen.auth doesn't ship
;;; one; the recommended idiom is the session cookie's own max-age (set
;;; via the session middleware's :max-age option). Callers who really
;;; need an in-app idle timeout can read GET-UNIVERSAL-TIME stamps off
;;; the session themselves — it's a 10-line plug.

(defvar *session-return-to-key* :user-return-to
  "Session key under which REQUIRE-AUTH stashes the GET path the user
was trying to reach. LOG-IN-AND-REDIRECT reads it and clears it.")

(defun safe-internal-path-p (path)
  "T iff PATH is a same-origin relative path: starts with exactly one
'/' and the second char is not '/' or '\\'. Blocks protocol-relative
(\"//evil.com\") and backslash-bypass (\"/\\evil.com\") open redirects
that an attacker could plant via the return-to flow.

Phoenix relies on verified-routes for the same guarantee; clauth
checks explicitly because we don't have a route compiler."
  (and (stringp path)
       (plusp (length path))
       (char= (char path 0) #\/)
       (or (= (length path) 1)
           (and (char/= (char path 1) #\/)
                (char/= (char path 1) #\\)))))

(defun log-in-and-redirect (conn user &key repo token-schema (default-path "/"))
  "Establish a session for USER and redirect to the captured return-to
(or DEFAULT-PATH). Mirrors Phoenix log_in_user/2.

The redirect target is validated by SAFE-INTERNAL-PATH-P; an unsafe
return-to value (e.g. \"//evil.com\" planted via path-info smuggling)
falls back to DEFAULT-PATH instead of becoming an open redirect."
  (let* ((raw (clug:get-session-value conn *session-return-to-key*))
         (target (if (safe-internal-path-p raw) raw default-path))
         (c (login conn user :repo repo :token-schema token-schema))
         (c (clug:put-session-value c *session-return-to-key* nil)))
    (clug:halt
     (clug:put-resp c 302 ""
                    (list "location" target)))))

(defun maybe-store-return-to (conn)
  "Phoenix's contract: only the original GET path is captured. POST /
PUT / DELETE attempts are not stored because (a) they typically can't
be replayed safely after login, and (b) a captured POST URL is a
target for CSRF redirection. The query string is included so a deep
link like /dashboard?tab=billing survives the round trip."
  (cond
    ((not (eq (clug:conn-method conn) :get)) conn)
    (t
     (let* ((path (clug:conn-path conn))
            (qs   (getf (clug:conn-req conn) :query-string))
            (full (if (and qs (plusp (length qs)))
                      (format nil "~a?~a" path qs)
                      path)))
       (clug:put-session-value conn *session-return-to-key* full)))))

(defun require-auth (conn &key redirect-to flash)
  "Plug: gate downstream on the presence of a current-user.

In JSON mode (REDIRECT-TO unset, default), halts with 401 +
application/json. In redirect mode, halts with 302 to REDIRECT-TO
(typical: \"/login\"). The original GET path is captured under
*SESSION-RETURN-TO-KEY* so the post-login flow can send the user back
to where they were trying to go.

FLASH is an optional string written under :flash in the session for
the next request's UI to display."
  (cond
    ((current-user conn) conn)
    (redirect-to
     (let ((c (maybe-store-return-to conn)))
       (when flash (setf c (clug:put-session-value c :flash flash)))
       (clug:halt
        (clug:put-resp c 302 ""
                       (list "location" redirect-to)))))
    (t
     (clug:halt
      (clug:put-resp conn 401 "{\"error\":\"unauthorized\"}"
                     (list "content-type" "application/json"))))))

(defun redirect-if-authenticated (&key (redirect-to "/"))
  "Return a plug that redirects already-logged-in users away from
login / register pages. Mirrors Phoenix
redirect_if_user_is_authenticated/2."
  (lambda (conn)
    (if (current-user conn)
        (clug:halt
         (clug:put-resp conn 302 "" (list "location" redirect-to)))
        conn)))

(defun default-role-reader (user)
  (getf user :role))

(defun require-role (allowed &key (reader #'default-role-reader))
  "Return a plug that halts with 403 unless the current user's role is
in ALLOWED. ALLOWED is a single role value or a list of allowed values
(compared with EQUAL). READER pulls the role off the user record;
default is (getf user :role).

If READER returns a list (multi-role user), the check passes when ANY
element of that list is in ALLOWED. NIL roles never match.

The plug ALSO halts with 401 when no current-user is attached, and
with 403 when the READER signals an error — so misconfigured readers
fail closed rather than 500-ing.

clauth has no opinion on how roles are stored: a single :role string
column, a separate :user_roles join table read via a custom :reader,
or anything else. The plug only enforces the comparison.

NIL or '() passed as ALLOWED is rejected at plug-construction time —
a deny-all 'role' is almost always a typo (e.g. an unbound config
variable). Use a separate (lambda (conn) (clug:halt ...)) if you
genuinely want one."
  (let ((allowed-list (if (listp allowed) allowed (list allowed))))
    (when (null allowed-list)
      (error "require-role: ALLOWED is empty. Pass at least one role."))
    (lambda (conn)
      (let* ((user (current-user conn))
             (role (and user
                        (handler-case (funcall reader user)
                          (error () nil))))
             (roles (cond ((null role) nil)
                          ((listp role) role)
                          (t (list role)))))
        (cond
          ((null user)
           (clug:halt
            (clug:put-resp conn 401 "{\"error\":\"unauthorized\"}"
                           (list "content-type" "application/json"))))
          ((some (lambda (r) (member r allowed-list :test #'equal)) roles)
           conn)
          (t
           (clug:halt
            (clug:put-resp conn 403 "{\"error\":\"forbidden\"}"
                           (list "content-type" "application/json")))))))))
