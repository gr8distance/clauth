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

(defun %parse-hash (encoded)
  "Return (values block-count iterations salt hash) or signal an error."
  (let ((parts (split-sequence encoded #\$)))
    (unless (and (= 5 (length parts))
                 (string= "clauth"   (nth 0 parts))
                 (string= "argon2id" (nth 1 parts)))
      (error "Unrecognized password hash format: ~a"
             (subseq encoded 0 (min 24 (length encoded)))))
    (let* ((params (nth 2 parts))
           (m (parse-kv params "m="))
           (i (parse-kv params "t="))
           (salt (ironclad:hex-string-to-byte-array (nth 3 parts)))
           (hash (ironclad:hex-string-to-byte-array (nth 4 parts))))
      (values m i salt hash))))

(defun split-sequence (string ch)
  "$-split (no extra dep, no regex)."
  (loop with start = 0
        with len = (length string)
        for i from 0 to len
        when (or (= i len) (char= (char string i) ch))
          collect (subseq string start i)
          and do (setf start (1+ i))))

(defun parse-kv (params key)
  (let ((pos (search key params)))
    (unless pos
      (error "Missing parameter ~a in hash" key))
    (let* ((value-start (+ pos (length key)))
           (value-end (or (position #\, params :start value-start)
                          (length params))))
      (parse-integer params :start value-start :end value-end))))

(defun verify-password (password encoded-hash)
  "Constant-time check: T iff PASSWORD matches the ENCODED-HASH produced
by HASH-PASSWORD. The recomputed hash uses the parameters stored INSIDE
the encoded string, not the current *argon2-*  values, so old hashes
keep verifying after the cost factors are raised."
  (multiple-value-bind (m i salt stored) (%parse-hash encoded-hash)
    (let ((candidate (%argon2id-derive password salt m i (length stored))))
      (ironclad:constant-time-equal candidate stored))))
