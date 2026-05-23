(in-package #:clauth)

;;; Single-use tokens for password reset, email confirmation, etc.
;;;
;;; Threat model: the raw token travels via email/URL once. The DB
;;; stores only the SHA-256 hash. An attacker dumping the DB can't
;;; redeem tokens. Verification is constant-time.

(defvar *token-byte-length* 32
  "Default raw-token entropy. 32 bytes = 256 bits, plenty against
brute force.")

(defun generate-token (&optional (byte-length *token-byte-length*))
  "Return (values raw-token stored-hash). Hand RAW-TOKEN to the user
(via email link) and store STORED-HASH in the DB."
  (let* ((bytes (ironclad:random-data byte-length))
         (raw   (ironclad:byte-array-to-hex-string bytes)))
    (values raw (token-hash raw))))

(defun token-hash (raw-token)
  "SHA-256 of a raw token, as a hex string. Suitable for DB storage."
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-sequence
    'ironclad:sha256
    (babel:string-to-octets raw-token :encoding :utf-8))))

(defun verify-token-hash (raw-token stored-hash)
  "Constant-time check that RAW-TOKEN's hash equals STORED-HASH."
  (let ((candidate (token-hash raw-token)))
    (and (= (length candidate) (length stored-hash))
         (ironclad:constant-time-equal
          (babel:string-to-octets candidate :encoding :utf-8)
          (babel:string-to-octets stored-hash :encoding :utf-8)))))
