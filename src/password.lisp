(in-package #:clauth)

;;; Password hashing: Argon2id via ironclad.
;;;
;;; Hashes are stored as a self-describing string so future parameter
;;; changes don't break old hashes:
;;;
;;;   clauth$argon2id$m=<block-count>,t=<iterations>$<hex-salt>$<hex-hash>
;;;
;;; m is ironclad's block-count (1 block = 1024 bytes). t is the
;;; iteration count passed to derive-key.

;; These are global tuning knobs read at HASH-PASSWORD time. They do NOT
;; affect VERIFY-PASSWORD on existing hashes — VERIFY-PASSWORD reads the
;; parameters embedded in the stored string. That means lowering them in
;; a running process weakens NEW hashes only.
;;
;; CAUTION: setting these in a REPL session affects subsequent hashes
;; for the whole process. Don't (SETF *argon2-iterations* 1) "just for
;; this test"; bind them per-call instead: (LET ((*argon2-iterations* 1))
;; (HASH-PASSWORD ...)).

(defvar *argon2-block-count* 4096
  "Memory cost. 4096 blocks = 4 MiB. OWASP 2024 minimum for argon2id is
~7 MiB so this is on the low side for high-security apps; raise to 8192
or 16384 if your machines can afford it.")

(defvar *argon2-iterations* 3
  "Time cost. OWASP 2024 recommends >=3 for argon2id.")

(defvar *argon2-key-length* 32
  "Output hash length in bytes. 32 = 256 bits.")

(defvar *salt-length* 16
  "Salt length in bytes.")

(defun %password-bytes (password)
  (etypecase password
    (string                            (babel:string-to-octets password :encoding :utf-8))
    ((simple-array (unsigned-byte 8))  password)))

(defun %argon2id-derive (password salt block-count iterations key-length)
  (let ((kdf (ironclad:make-kdf :argon2id :block-count block-count)))
    (ironclad:derive-key kdf
                         (%password-bytes password)
                         salt
                         iterations
                         key-length)))

(defun hash-password (password)
  "Hash PASSWORD with Argon2id. Returns a self-describing string.
Parameters come from *argon2-block-count*, *argon2-iterations*, and
*argon2-key-length* at call time so a process can ramp up cost without
breaking old hashes."
  (let* ((salt (ironclad:make-random-salt *salt-length*))
         (hash (%argon2id-derive password salt
                                 *argon2-block-count*
                                 *argon2-iterations*
                                 *argon2-key-length*)))
    (format nil "clauth$argon2id$m=~d,t=~d$~a$~a"
            *argon2-block-count*
            *argon2-iterations*
            (ironclad:byte-array-to-hex-string salt)
            (ironclad:byte-array-to-hex-string hash))))

;; Hard caps on the parameters we accept from a stored hash. An attacker
;; who can write to the password_hash column otherwise sets m=4194304 to
;; pin 4 GiB and stall the worker, or hash-length=0 so constant-time
;; equality of empty arrays returns T (trivial bypass).
(defparameter *max-block-count*     65536  "Refuse to verify hashes with m > 64 MiB.")
(defparameter *max-iterations*      10     "Refuse to verify hashes with t > 10.")
(defparameter *min-salt-length*     8)
(defparameter *max-salt-length*     64)
(defparameter *min-hash-length*     16)
(defparameter *max-hash-length*     64)
(defparameter *max-param-string*    24
  "Cap on the length of any numeric param like \"4096\" so parse-integer
can't bignum-DoS us before validation.")

(defun %parse-hash (encoded)
  "Return (values block-count iterations salt hash) or signal an error.
Aggressively bounds every parsed value so a tampered DB row can't drive
verify-password into a memory blow-up, a parse-integer bignum DoS, or
a zero-length hash trivial bypass."
  (unless (stringp encoded)
    (error "Bad password hash: not a string"))
  (let ((parts (split-sequence encoded #\$)))
    (unless (and (= 5 (length parts))
                 (string= "clauth"   (nth 0 parts))
                 (string= "argon2id" (nth 1 parts)))
      (error "Unrecognized password hash format"))
    (let* ((m       (parse-params-token (nth 2 parts) "m" *max-block-count*))
           (i       (parse-params-token (nth 2 parts) "t" *max-iterations*))
           (salt    (ironclad:hex-string-to-byte-array (nth 3 parts)))
           (hash    (ironclad:hex-string-to-byte-array (nth 4 parts))))
      (unless (<= *min-salt-length* (length salt) *max-salt-length*)
        (error "Bad password hash: salt length out of range"))
      (unless (<= *min-hash-length* (length hash) *max-hash-length*)
        (error "Bad password hash: hash length out of range"))
      (values m i salt hash))))

(defun split-sequence (string ch)
  "$-split (no extra dep, no regex)."
  (loop with start = 0
        with len = (length string)
        for i from 0 to len
        when (or (= i len) (char= (char string i) ch))
          collect (subseq string start i)
          and do (setf start (1+ i))))

(defun parse-params-token (params key max-allowed)
  "Tokenise PARAMS by ',', find the unique 'KEY=N' entry, return N as a
non-negative integer bounded by MAX-ALLOWED. Rejects duplicate keys,
signed numbers, whitespace, oversize tokens."
  (let ((tokens (split-sequence params #\,))
        hit)
    (dolist (tok tokens)
      (let ((eq (position #\= tok)))
        (when (and eq (string= key (subseq tok 0 eq)))
          (when hit (error "Bad password hash: duplicate param ~a" key))
          (let ((value (subseq tok (1+ eq))))
            (when (> (length value) *max-param-string*)
              (error "Bad password hash: oversize param"))
            (unless (and (plusp (length value))
                         (every #'digit-char-p value))
              (error "Bad password hash: non-digit param"))
            (setf hit (parse-integer value))))))
    (unless hit (error "Bad password hash: missing param ~a" key))
    (unless (<= 1 hit max-allowed)
      (error "Bad password hash: ~a out of range" key))
    hit))

(defun verify-password (password encoded-hash)
  "Constant-time check: T iff PASSWORD matches the ENCODED-HASH produced
by HASH-PASSWORD. The recomputed hash uses the parameters stored INSIDE
the encoded string, not the current *argon2-*  values, so old hashes
keep verifying after the cost factors are raised.

%PARSE-HASH bounds every parameter aggressively — a tampered DB row
can't drive this into a memory blow-up or zero-length-hash bypass."
  (multiple-value-bind (m i salt stored) (%parse-hash encoded-hash)
    (let ((candidate (%argon2id-derive password salt m i (length stored))))
      (ironclad:constant-time-equal candidate stored))))
