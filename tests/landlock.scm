;; Copyright (C) 2025 Florian Marrero Liestmann
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;
;; Author: Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>
;; File: landlock.scm

(use-modules (ice-9 exceptions)
	     (ice-9 match)
	     (srfi srfi-1)
	     (srfi srfi-26)
	     (ice-9 rdelim)
	     (srfi srfi-64)
	     (landlock))

(define names->mask (@@ (landlock) names->mask))
(define unsupported (@@ (landlock) unsupported))
(define %fs-access (@@ (landlock) %fs-access))
(define %net-access (@@ (landlock) %net-access))
(define %restrict-flags (@@ (landlock) %restrict-flags))
(define quiet-table (@@ (landlock) quiet-table))

(define abi (landlock-abi-version))
(define test-dir (dirname (current-filename)))
(define test-file (string-append test-dir "/test.txt"))

(define (read-first-line file)
  (false-if-exception (call-with-input-file file read-line)))

(define (bind-udp port)
  (false-if-exception
   (let ((sock (socket AF_INET SOCK_DGRAM 0)))
     (bind sock AF_INET INADDR_LOOPBACK port)
     (close-port sock)
     #t)))

(define (call-with-temporary-file proc)
  (let* ((port (mkstemp! (string-copy "/tmp/guile-landlock-XXXXXX")))
	 (name (port-filename port)))
    (display "outside" port)
    (close-port port)
    (dynamic-wind (const #t)
		  (lambda () (proc name))
		  (lambda () (delete-file name)))))

;; Return the list of booleans THUNK returns in a child process, or #f if it
;; fails.
(define (in-child thunk)
  ;; Don't flush buffered output twice.
  (force-output)
  (let ((pid (primitive-fork)))
    (if (zero? pid)
	(primitive-exit
	 (match (false-if-exception (thunk))
	   (#f 255)
	   (results (fold (lambda (result bit status)
			    (if result (logior status (ash 1 bit)) status))
			  0 results (iota (length results))))))
	(match (status:exit-val (cdr (waitpid pid)))
	  (255 #f)
	  (status (map (cut logbit? <> status) (iota 8)))))))

(define (exit-status command)
  (force-output)
  (let ((pid (primitive-fork)))
    (if (zero? pid)
	(begin
	  (let ((null (open-fdes "/dev/null" O_WRONLY)))
	    (dup2 null 1)
	    (dup2 null 2))
	  (false-if-exception (apply landlock-exec command))
	  (primitive-exit 127))
	(status:exit-val (cdr (waitpid pid))))))

(define %store-rules
  (map (cut landlock-path <> %landlock-read-access #:optional? #t)
       '("/gnu/store" "/usr" "/lib" "/lib64" "/bin" "/etc/ld.so.cache")))

(test-begin "landlock")

(test-group "access rights"
  (test-equal "mask of supported rights"
    #b101 (names->mask %fs-access '(execute read-file) 1))
  (test-equal "unsupported rights are dropped from the mask"
    0 (names->mask %fs-access '(resolve-unix) 8))
  (test-equal "unsupported rights"
    '(resolve-unix) (unsupported %fs-access '(read-file resolve-unix) 8))
  (test-equal "UDP needs ABI 10"
    '(bind-udp) (unsupported %net-access '(bind-tcp bind-udp) 9))
  (test-equal "tsync needs ABI 8"
    '(tsync) (unsupported %restrict-flags '(log-same-exec-off tsync) 7))
  (test-equal "quiet needs ABI 10"
    '(read-file) (unsupported (quiet-table %fs-access) '(read-file) 9))
  (test-assert "read and write access cover all filesystem rights"
    (lset= eq? (map car %fs-access)
	   (append %landlock-read-access %landlock-write-access)))
  (test-assert "unknown right is an error"
    (guard (e ((landlock-error? e) #t))
      (names->mask %fs-access '(read-files) 10)
      #f)))

(test-group "missing features"
  (test-equal "missing on ABI 9"
    '(bind-udp read-file quiet)
    ((@@ (landlock) missing-features)
     9
     (list (landlock-path "/" '(read-file) #:quiet? #t)
	   (landlock-port 53 '(bind-udp)))
     '((read-file) (bind-tcp bind-udp) () (read-file) () ())
     '(tsync)))
  (test-equal "nothing missing on ABI 10"
    '()
    ((@@ (landlock) missing-features)
     10 '() '((read-file) (bind-udp) (signal) (read-file) (bind-udp) (signal)) '(tsync))))

(test-group "unhandled access"
  (test-equal "strict mode raises an error"
    '((read-dir bind-tcp))
    (guard (e ((landlock-error? e) (exception-irritants e)))
      (landlock-restrict! (list (landlock-path test-dir '(read-file read-dir))
				(landlock-port 80 '(bind-tcp)))
			  #:fs '(read-file) #:net '(connect-tcp)
			  #:best-effort? #f)))
  (test-equal "best-effort mode drops unhandled rights"
    '(#t)
    (match (in-child
	    (lambda ()
	      (list (memq (landlock-restrict!
			   (list (landlock-path test-dir %landlock-read-access))
			   #:fs '(read-file) #:net '())
			  '(fully-enforced not-enforced)))))
      ((ok? . _) (list ok?))
      (#f #f))))

;; Needs a kernel below ABI 10.
(unless (< 0 abi 10)
  (test-skip "strict mode"))

(test-group "strict mode"
  (test-equal "unsupported rights raise an error"
    '((bind-udp))
    (guard (e ((landlock-error? e) (exception-irritants e)))
      (landlock-restrict! '() #:fs '() #:net '(bind-udp) #:best-effort? #f))))

(unless (landlock-supported?)
  (format #t "Landlock isn't supported, skipping kernel tests.~%")
  (test-skip "kernel"))

(test-group "kernel"
  (test-assert "errata" (or (< abi 7) (integer? (landlock-errata))))
  (call-with-temporary-file
   (lambda (outside)
     (test-equal "restrict to paths"
       '(fully-enforced #t #t)
       (match (in-child
	       (lambda ()
		 (list (eq? 'fully-enforced
			    (landlock-restrict!
			     (list (landlock-path test-dir %landlock-read-access)
				   (landlock-path "/nonexistent" '(read-file)
						  #:optional? #t))))
		       (read-first-line test-file)
		       (not (read-first-line outside)))))
	 ((enforced? readable? denied? . _)
	  (list (if enforced? 'fully-enforced 'other) readable? denied?))
	 (#f #f)))))
  (test-assert "missing path raises a system error"
    (match (in-child
	    (lambda ()
	      (list (catch 'system-error
		      (lambda ()
			(landlock-restrict!
			 (list (landlock-path "/nonexistent" '(read-file))))
			#f)
		      (lambda args (= ENOENT (system-error-errno args)))))))
      ((raised? . _) raised?)
      (#f #f)))
  (call-with-temporary-file
   (lambda (outside)
     (let ((cat (search-path (parse-path (getenv "PATH")) "cat"))
	   (rules (cons (landlock-path test-dir '(read-file)) %store-rules)))
       (test-equal "exec program beneath allowed path"
	 0 (exit-status (list rules (list cat test-file) #:net '())))
       (test-equal "exec'd program can't read outside"
	 1 (exit-status (list rules (list cat outside) #:net '())))))))

(unless (>= abi 10)
  (format #t "Landlock ABI 10 isn't supported, skipping ABI 10 tests.~%")
  (test-skip "abi 10"))

(test-group "abi 10"
  (test-equal "UDP, quiet rules and restrict flags"
    '(#t #t #t)
    (match (in-child
	    (lambda ()
	      (list (eq? 'fully-enforced
			 (landlock-restrict!
			  (list (landlock-port 0 '(bind-udp))
				(landlock-path test-dir '(read-file) #:quiet? #t))
			  #:quiet-fs '(read-file)
			  #:flags '(log-same-exec-off tsync)
			  #:best-effort? #f))
		    (bind-udp 0)
		    (not (bind-udp 54321)))))
      ((a b c . _) (list a b c))
      (#f #f))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "landlock")
(exit (zero? failures))
