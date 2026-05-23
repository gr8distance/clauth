(in-package #:clauth)

;;; Conn / session integration. Sits on top of clug/session so the user
;;; ID rides in the cookie-backed session store, not in a stateless JWT.

(defvar *current-user-key* :current-user
  "conn-assign key under which LOAD-CURRENT-USER stashes the user record.")

(defvar *session-user-key* :user-id
  "Session key under which LOGIN writes the user's primary key.")

(defvar *session-last-activity-key* :last-activity-at
  "Session key under which SESSION-TIMEOUT records the last-seen
universal-time. Stored as an integer.")

(defvar *session-version-key* :session-version
  "Session key recording the user's session-version at the time of
LOGIN. LOAD-CURRENT-USER compares it against the stored value on the
user row; if the stored value advanced (because change-password or
change-email bumped it from another device), this session is forced
to log out.")

(defun login (conn user)
  "Mark CONN as authenticated as USER. USER may be a record plist (we
read its :id) or the bare integer id value. STRINGS are deliberately
NOT accepted — a controller mistakenly forwarding a request param as
the user id would otherwise let any caller log in as any uid.

Rotates the session id to defend against fixation: an attacker who
planted a session cookie pre-login no longer rides the new privilege
level."
  (let* ((id (etypecase user
               (cons (or (getf user :id)
                         (error "login: user record has no :id")))
               (integer user)))
         (version (when (consp user)
                    (or (getf user :session-version) 0))))
    (let ((conn (clug:put-session-value conn *session-user-key* id)))
      (when version
        (setf conn (clug:put-session-value conn *session-version-key* version)))
      (let ((out (clug:rotate-session-id conn)))
        (emit-auth-event :login (list :user-id id))
        out))))

(defun logout (conn &key repo token-schema)
  "Clear the session. When REPO and TOKEN-SCHEMA are supplied, ALSO
revoke the remember-me cookie + its DB row — pass them whenever the
app wires up remember-me, otherwise the user clicks 'sign out' and
gets silently re-logged-in on the next request from their stored
remember-me token. Bare (logout conn) is fine when remember-me is
not in use."
  (let ((id (current-user-id conn)))
    (emit-auth-event :logout (list :user-id id))
    (let ((c (clug:clear-session conn)))
      ;; revoke-remember-me lives in remember-me.lisp (loaded after this
      ;; file); funcall avoids a compile-time undefined-function warning
      ;; while still resolving at load time when the symbol is defined.
      (if (and repo token-schema)
          (funcall (symbol-function 'revoke-remember-me) c repo token-schema)
          c))))

(defun current-user-id (conn)
  "Read the logged-in user's id from the session, or NIL. Returns NIL if
the session has been marked for destruction in this request — so a
plug that called LOGOUT earlier in the pipeline doesn't leak the id to
plugs further down."
  (let ((state (getf (clug:conn-req conn) :clug.session-state)))
    (unless (getf state :destroy)
      (clug:get-session-value conn *session-user-key*))))

(defun load-current-user (repo schema-name)
  "Return a plug that looks up the session user and attaches the record
under conn-assigns *current-user-key*. Forces logout when:
- session points at a deleted user, OR
- the user's :session-version on disk is greater than the version
  recorded in the cookie at login time (a credential change on another
  device fired BUMP-SESSION-VERSION)."
  (lambda (conn)
    (let ((id (current-user-id conn)))
      (cond
        ((null id) conn)
        (t
         (let ((user (clecto:repo-get repo schema-name id)))
           (cond
             ((null user) (logout conn))
             ((session-version-stale-p conn user) (logout conn))
             (t (clug:assign conn *current-user-key* user)))))))))

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

(defun session-timeout (&key (max-idle-seconds 1800))
  "Return a plug that logs the user out if more than MAX-IDLE-SECONDS
have elapsed since the last seen activity timestamp on the session.
Place AFTER WITH-SESSION but BEFORE LOAD-CURRENT-USER.

Touches the session on every authenticated request (writes a fresh
timestamp), which counts as 'dirty' and triggers a session save —
keep MAX-IDLE-SECONDS coarse enough that the write rate is sane.

CLOCK-SKEW NOTE: timestamps are based on each node's wall clock
(GET-UNIVERSAL-TIME). A skew where one node's clock is BEHIND another
would otherwise compute a negative delta and never expire — we clamp
to (MAX 0 delta) so skewed time fails closed (forces re-auth) rather
than open (kept alive forever)."
  (lambda (conn)
    (let ((uid (current-user-id conn)))
      (cond
        ((null uid) conn)                            ; not logged in, no-op
        (t
         (let* ((last (clug:get-session-value
                       conn *session-last-activity-key*))
                (now  (get-universal-time))
                (delta (and last (max 0 (- now last)))))
           (cond
             ((and delta (> delta max-idle-seconds)) (logout conn))
             (t (clug:put-session-value
                 conn *session-last-activity-key* now)))))))))

(defun require-auth (conn)
  "Plug: halt with 401 if no current-user is attached. Place AFTER
LOAD-CURRENT-USER in the pipeline."
  (if (current-user conn)
      conn
      (clug:halt
       (clug:put-resp conn 401 "{\"error\":\"unauthorized\"}"
                      (list "content-type" "application/json")))))

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
