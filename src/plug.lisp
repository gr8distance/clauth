(in-package #:clauth)

;;; Conn / session integration. Sits on top of clug/session so the user
;;; ID rides in the cookie-backed session store, not in a stateless JWT.

(defvar *current-user-key* :current-user
  "conn-assign key under which LOAD-CURRENT-USER stashes the user record.")

(defvar *session-user-key* :user-id
  "Session key under which LOGIN writes the user's primary key.")

(defun login (conn user)
  "Mark CONN as authenticated as USER. USER may be a record plist (we
read its :id) or the bare integer id value. STRINGS are deliberately
NOT accepted — a controller mistakenly forwarding a request param as
the user id would otherwise let any caller log in as any uid.

Rotates the session id to defend against fixation: an attacker who
planted a session cookie pre-login no longer rides the new privilege
level."
  (let ((id (etypecase user
              (cons (or (getf user :id)
                        (error "login: user record has no :id")))
              (integer user))))
    (clug:rotate-session-id
     (clug:put-session-value conn *session-user-key* id))))

(defun logout (conn)
  "Clear the session (and its server-side store entry)."
  (clug:clear-session conn))

(defun current-user-id (conn)
  "Read the logged-in user's id from the session, or NIL."
  (clug:get-session-value conn *session-user-key*))

(defun load-current-user (repo schema-name)
  "Return a plug that looks up the session user and attaches the record
under conn-assigns *current-user-key*. No-op when not logged in."
  (lambda (conn)
    (let ((id (current-user-id conn)))
      (if id
          (let ((user (clecto:repo-get repo schema-name id)))
            (if user
                (clug:assign conn *current-user-key* user)
                ;; Stale session pointing at a deleted user — drop it.
                (logout conn)))
          conn))))

(defun current-user (conn)
  "Retrieve the user record attached by LOAD-CURRENT-USER."
  (clug:get-assign conn *current-user-key*))

(defun require-auth (conn)
  "Plug: halt with 401 if no current-user is attached. Place AFTER
LOAD-CURRENT-USER in the pipeline."
  (if (current-user conn)
      conn
      (clug:halt
       (clug:put-resp conn 401 "{\"error\":\"unauthorized\"}"
                      (list "content-type" "application/json")))))
