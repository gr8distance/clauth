(in-package #:clauth)

(defmacro -> (init &body forms)
  "Thread-first. Local to clauth — callers can either USE clauth or
write their own; we don't export this."
  (reduce (lambda (acc f)
            (if (consp f) (list* (car f) acc (cdr f)) (list f acc)))
          forms :initial-value init))
