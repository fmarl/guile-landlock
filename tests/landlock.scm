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

(define (connect-unix file)
  (false-if-exception
   (let ((sock (socket AF_UNIX SOCK_STREAM 0)))
     (connect sock AF_UNIX file)
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

(define (call-with-unix-server proc)
  (let ((file (format #f "/tmp/guile-landlock-~a.sock" (getpid)))
	(sock (socket AF_UNIX SOCK_STREAM 0)))
    (bind sock AF_UNIX file)
    (listen sock 1)
    (dynamic-wind (const #t)
		  (lambda () (proc file))
		  (lambda ()
		    (close-port sock)
		    (delete-file file)))))

;; Return the value of THUNK in a child process, or #f if it raises.
(define (in-child thunk)
  (flush-all-ports)
  (match (pipe)
    ((in . out)
     (let ((pid (primitive-fork)))
       (if (zero? pid)
	   (begin
	     (close-port in)
	     (write (false-if-exception (thunk)) out)
	     (close-port out)
	     (primitive-exit 0))
	   (begin
	     (close-port out)
	     (let ((result (read in)))
	       (close-port in)
	       (waitpid pid)
	       (and (not (eof-object? result)) result))))))))

(define (landlock-error-irritants thunk)
  (guard (e ((landlock-error? e) (exception-irritants e)))
    (thunk)
    #f))

(define (exit-status command)
  (flush-all-ports)
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
    (landlock-error-irritants
     (lambda ()
       (landlock-restrict! (list (landlock-path test-dir '(read-file read-dir))
				 (landlock-port 80 '(bind-tcp)))
			   #:fs '(read-file) #:net '(connect-tcp)
			   #:best-effort? #f))))
  (test-assert "best-effort mode drops unhandled rights"
    (memq (in-child
	   (lambda ()
	     (landlock-restrict!
	      (list (landlock-path test-dir %landlock-read-access))
	      #:fs '(read-file) #:net '())))
	  '(fully-enforced not-enforced))))

(unless (< 0 abi 10)
  (test-skip "strict mode"))

(test-group "strict mode"
  (test-equal "unsupported rights raise an error"
    '((bind-udp))
    (landlock-error-irritants
     (lambda ()
       (landlock-restrict! '() #:fs '() #:net '(bind-udp) #:best-effort? #f)))))

(unless (landlock-supported?)
  (format #t "Landlock isn't supported, skipping kernel tests.~%")
  (test-skip "kernel"))

(test-group "kernel"
  (test-assert "errata" (or (< abi 7) (integer? (landlock-errata))))
  (call-with-temporary-file
   (lambda (outside)
     (test-equal "restrict to paths"
       '(fully-enforced "abc abc abc" #f)
       (in-child
	(lambda ()
	  (list (landlock-restrict!
		 (list (landlock-path test-dir %landlock-read-access)
		       (landlock-path "/nonexistent" '(read-file)
				      #:optional? #t)))
		(read-first-line test-file)
		(read-first-line outside)))))))
  (test-equal "missing path raises a system error"
    ENOENT
    (in-child
     (lambda ()
       (catch 'system-error
	 (lambda ()
	   (landlock-restrict!
	    (list (landlock-path "/nonexistent" '(read-file)))))
	 (lambda args (system-error-errno args))))))
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
    '(fully-enforced #t #f)
    (in-child
     (lambda ()
       (list (landlock-restrict!
	      (list (landlock-port 0 '(bind-udp))
		    (landlock-path test-dir '(read-file) #:quiet? #t))
	      #:quiet-fs '(read-file)
	      #:flags '(log-same-exec-off tsync)
	      #:best-effort? #f)
	     (bind-udp 0)
	     (bind-udp 54321)))))
  (test-equal "quiet rule without access"
    'fully-enforced
    (in-child
     (lambda ()
       (landlock-restrict! (list (landlock-path test-dir '() #:quiet? #t))
			   #:quiet-fs '(read-file)
			   #:best-effort? #f))))
  (test-equal "quiet rule without access isn't skipped"
    ENOENT
    (in-child
     (lambda ()
       (catch 'system-error
	 (lambda ()
	   (landlock-restrict! (list (landlock-path "/nonexistent" '()
						    #:quiet? #t))
			       #:quiet-fs '(read-file)))
	 (lambda args (system-error-errno args))))))
  (test-equal "quiet rule without handled rights"
    'fully-enforced
    (in-child
     (lambda ()
       (landlock-restrict! (list (landlock-path test-dir '(read-file)
						#:quiet? #t))
			   #:fs '(write-file)))))
  (call-with-unix-server
   (lambda (file)
     (test-equal "resolve-unix on a socket file"
       '(fully-enforced #t)
       (in-child
	(lambda ()
	  (list (landlock-restrict! (list (landlock-path file '(resolve-unix)))
				    #:best-effort? #f)
		(connect-unix file))))))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "landlock")
(exit (zero? failures))
