(use-modules (ice-9 rdelim))

(define  (read-test-file)
  (display (read-line
	    (open-input-file "/home/marrero/test.txt"))))
