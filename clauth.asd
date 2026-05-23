(defsystem "clauth"
  :description "Phoenix-flavored authentication for clack-based apps (clug + clecto)."
  :version "0.1.0"
  :author "ug <gr8.distance@gmail.com>"
  :license "MIT"
  :depends-on ("ironclad" "babel" "alexandria"
               "clug" "clug/session" "clecto")
  :pathname "src/"
  :components ((:file "package")
               (:file "password"  :depends-on ("package"))
               (:file "token"     :depends-on ("package"))
               (:file "schema"    :depends-on ("package"))
               (:file "changeset" :depends-on ("password" "schema"))
               (:file "repo"      :depends-on ("password"))
               (:file "plug"      :depends-on ("repo")))
  :in-order-to ((test-op (test-op "clauth/tests"))))

(defsystem "clauth/tests"
  :depends-on ("clauth" "fiveam")
  :pathname "tests/"
  :components ((:file "main"))
  :perform (test-op (op c) (symbol-call :fiveam :run! :clauth)))
