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
             (ice-9 ftw)
             (ice-9 match)
             (ice-9 rdelim)
             (ice-9 threads)
             (srfi srfi-1)
             (srfi srfi-26)
             (srfi srfi-64)
             (landlock))

(define names->mask (@@ (landlock) names->mask))
(define unsupported (@@ (landlock) unsupported))
(define quiet-table (@@ (landlock) quiet-table))
(define %fs-access (@@ (landlock) %fs-access))
(define %net-access (@@ (landlock) %net-access))
(define %scopes (@@ (landlock) %scopes))
(define %restrict-flags (@@ (landlock) %restrict-flags))
(define syscall-offset (@@ (landlock) syscall-offset))

(define abi (landlock-abi-version))
(define test-dir (dirname (current-filename)))
(define test-file (string-append test-dir "/test.txt"))
(define tmp-dir (or (getenv "TMPDIR") "/tmp"))

;; The default tsync flag needs ABI 8.
(define default-enforcement
  (if (>= abi 8) 'fully-enforced 'partially-enforced))

(define (in dir name)
  (string-append dir "/" name))

(define-syntax-rule (errno-of body ...)
  (catch 'system-error
    (lambda () body ... 'ok)
    (lambda args (system-error-errno args))))

(define (value-or-exception thunk)
  (catch #t
    thunk
    (lambda (key . args)
      (match (cons key args)
        (('%exception (? landlock-error? e))
         `(landlock-error ,@(exception-irritants e)))
        (('system-error . _)
         `(system-error ,(system-error-errno (cons key args))))
        (_ `(exception ,key))))))

(define (exception-of thunk)
  (value-or-exception (lambda () (thunk) #f)))

(define (in-child thunk)
  (flush-all-ports)
  (match (pipe)
    ((in . out)
     (match (primitive-fork)
       (0
        (close-port in)
        (false-if-exception (write (value-or-exception thunk) out))
        (close-port out)
        (primitive-exit 0))
       (pid
        (close-port out)
        (let* ((result (read in))
               (status (cdr (waitpid pid))))
          (close-port in)
          (if (and (zero? status) (not (eof-object? result)))
              result
              `(exit ,status))))))))

(define-syntax-rule (restricted body ...)
  (in-child (lambda () body ...)))

(define (errnos-after restrict operations)
  (restricted
   (restrict)
   (map (lambda (operation) (errno-of (operation))) operations)))

(define (exit-status rules command . options)
  (flush-all-ports)
  (match (primitive-fork)
    (0
     (let ((null (open-fdes "/dev/null" O_WRONLY)))
       (dup2 null 1)
       (dup2 null 2))
     (false-if-exception (apply landlock-exec rules command options))
     (primitive-exit 127))
    (pid (status:exit-val (cdr (waitpid pid))))))

(define (delete-tree file)
  (if (eq? 'directory (stat:type (lstat file)))
      (begin
        (chmod file #o700)
        (for-each (compose delete-tree (cut in file <>))
                  (scandir file (negate (cut member <> '("." "..")))))
        (rmdir file))
      (delete-file file)))

(define (call-with-temporary-directory proc)
  (let ((dir (mkdtemp (in tmp-dir "guile-landlock-XXXXXX"))))
    (dynamic-wind (const #t)
                  (cut proc dir)
                  (cut delete-tree dir))))

(define (write-text file text)
  (call-with-output-file file (cut display text <>)))

(define (read-text file)
  (call-with-input-file file read-line))

(define (call-with-socket family type proc)
  (let ((sock (socket family type 0)))
    (dynamic-wind (const #t)
                  (cut proc sock)
                  (cut close-port sock))))

(define (bind-port type port)
  (call-with-socket AF_INET type
    (cut bind <> AF_INET INADDR_LOOPBACK port)))

(define (connect-port type port)
  (call-with-socket AF_INET type
    (cut connect <> AF_INET INADDR_LOOPBACK port)))

(define (connect-unix address)
  (call-with-socket AF_UNIX SOCK_STREAM
    (cut connect <> AF_UNIX address)))

(define (call-with-listener family address proc)
  (call-with-socket family SOCK_STREAM
    (lambda (sock)
      (apply bind sock family address)
      (listen sock 1)
      (proc sock))))

(define (call-with-tcp-listener proc)
  (call-with-listener AF_INET (list INADDR_LOOPBACK 0)
    (compose proc sockaddr:port getsockname)))

(define (require-abi version group)
  (unless (>= abi version)
    (format #t "Landlock ABI ~a isn't supported, skipping ~s.~%" version group)
    (test-skip group)))

(define %store-rules
  (map (cut landlock-path <> %landlock-read-access #:optional? #t)
       '("/gnu/store" "/usr" "/lib" "/lib64" "/bin" "/etc/ld.so.cache")))

(define (make-fixture dir)
  (for-each (lambda (name) (write-text (in dir name) "abc"))
            '("file" "long" "doomed"))
  (for-each (lambda (name) (mkdir (in dir name)))
            '("dir" "empty-dir")))

(define %fs-operations
  `((read-file . ,(lambda (dir) (read-text (in dir "file"))))
    (write-file . ,(lambda (dir)
                     (close-fdes (open-fdes (in dir "file") O_WRONLY))))
    (read-dir . ,(lambda (dir) (closedir (opendir (in dir "dir")))))
    (remove-dir . ,(lambda (dir) (rmdir (in dir "empty-dir"))))
    (remove-file . ,(lambda (dir) (delete-file (in dir "doomed"))))
    (make-reg . ,(lambda (dir) (mknod (in dir "new-file") 'regular #o600 0)))
    (make-dir . ,(lambda (dir) (mkdir (in dir "new-dir"))))
    (make-sym . ,(lambda (dir) (symlink "file" (in dir "new-symlink"))))
    (make-fifo . ,(lambda (dir) (mknod (in dir "new-fifo") 'fifo #o600 0)))
    (make-sock . ,(lambda (dir) (mknod (in dir "new-socket") 'socket #o600 0)))
    (truncate . ,(lambda (dir) (truncate-file (in dir "long") 1)))))

(define (fs-operation-results rights)
  (call-with-temporary-directory
   (lambda (dir)
     (make-fixture dir)
     (map cons
          (map first %fs-operations)
          (errnos-after (cut landlock-restrict!
                             (list (landlock-path dir rights)) #:net '())
                        (map (match-lambda
                               ((_ . operation) (cut operation dir)))
                             %fs-operations))))))

(define (expected-fs-operation-results rights)
  (map (match-lambda
         ((right . _)
          (cons right
                (if (or (memq right rights)
                        ;; Unhandled before ABI 3.
                        (and (eq? right 'truncate) (< abi 3)))
                    'ok
                    EACCES))))
       %fs-operations))

(test-begin "landlock")

(test-group "uapi"
  ;; <linux/landlock.h>
  (define (check name table uapi)
    (test-equal (string-append name " values")
      (map (match-lambda ((name value _) (list name value 0)))
           uapi)
      (map (match-lambda
             ((name _ since)
              (list name
                    (names->mask table (list name) since)
                    (names->mask table (list name) (- since 1)))))
           uapi))
    (test-assert (string-append name " names")
      (lset= eq? (map first table) (map first uapi))))

  (check "filesystem" %fs-access
         '((execute #x1 1)
           (write-file #x2 1)
           (read-file #x4 1)
           (read-dir #x8 1)
           (remove-dir #x10 1)
           (remove-file #x20 1)
           (make-char #x40 1)
           (make-dir #x80 1)
           (make-reg #x100 1)
           (make-sock #x200 1)
           (make-fifo #x400 1)
           (make-block #x800 1)
           (make-sym #x1000 1)
           (refer #x2000 2)
           (truncate #x4000 3)
           (ioctl-dev #x8000 5)
           (resolve-unix #x10000 9)))
  (check "network" %net-access
         '((bind-tcp #x1 4)
           (connect-tcp #x2 4)
           (bind-udp #x4 10)
           (connect-send-udp #x8 10)))
  (check "scope" %scopes
         '((abstract-unix-socket #x1 6)
           (signal #x2 6)))
  (check "flag" %restrict-flags
         '((log-same-exec-off #x1 7)
           (log-new-exec-on #x2 7)
           (log-subdomains-off #x4 7)
           (tsync #x8 8)))
  (test-equal "system call numbers"
    `(444 554 4444 5444 6444 ,(+ #x40000000 444) 444 444)
    (map (match-lambda
           ((type pointer-size) (+ 444 (syscall-offset type pointer-size))))
         '(("x86_64-pc-linux-gnu" 8)
           ("alphaev67-unknown-linux-gnu" 8)
           ("mipsel-unknown-linux-gnu" 4)
           ("mips64el-unknown-linux-gnuabi64" 8)
           ("mips64el-unknown-linux-gnu" 4)
           ("x86_64-pc-linux-gnux32" 4)
           ("aarch64-unknown-linux-gnu" 8)
           ("i686-pc-linux-gnu" 4))))
  (test-equal "quieting needs ABI 10"
    '((read-file) ())
    (list (unsupported (quiet-table %fs-access) '(read-file) 9)
          (unsupported (quiet-table %fs-access) '(read-file) 10))))

(test-group "rules"
  (test-equal "path accessors"
    '("/" (read-file) #t #f)
    (let ((rule (landlock-path "/" '(read-file) #:optional? #t)))
      (list (landlock-path-path rule)
            (landlock-path-access rule)
            (landlock-path-optional? rule)
            (landlock-path-quiet? rule))))
  (test-equal "port accessors"
    '(443 (connect-tcp) #t)
    (let ((rule (landlock-port 443 '(connect-tcp) #:quiet? #t)))
      (list (landlock-port-port rule)
            (landlock-port-access rule)
            (landlock-port-quiet? rule))))
  (test-assert "all filesystem rights"
    (lset= eq?
           (append %landlock-read-access %landlock-write-access)
           (landlock-path-access (landlock-path "/" 'all))))
  (test-equal "all network rights"
    '(bind-tcp connect-tcp bind-udp connect-send-udp)
    (landlock-port-access (landlock-port 0 'all)))
  (test-equal "port range"
    '(0 65535)
    (map (compose landlock-port-port (cut landlock-port <> '()))
         '(0 65535)))
  (test-equal "invalid rules"
    '((landlock-error (read-files))
      (landlock-error (connect-tcp))
      (landlock-error (read-file))
      (landlock-error read-file)
      (landlock-error root)
      (landlock-error -1)
      (landlock-error 65536)
      (landlock-error 80.0))
    (map exception-of
         (list (cut landlock-path "/" '(read-files))
               (cut landlock-path "/" '(connect-tcp))
               (cut landlock-port 80 '(read-file))
               (cut landlock-path "/" 'read-file)
               (cut landlock-path 'root '(read-file))
               (cut landlock-port -1 '())
               (cut landlock-port 65536 '())
               (cut landlock-port 80.0 '())))))

(test-group "validation"
  (test-equal "invalid options"
    '((landlock-error (read-files))
      (landlock-error (read-file))
      (landlock-error (tsnyc))
      (landlock-error (signal))
      (landlock-error ("/"))
      (landlock-error #f)
      (landlock-error mostly-enforced)
      (landlock-error -1)
      (landlock-error "10"))
    (restricted
     (map exception-of
          (list (cut landlock-restrict! '() #:fs '(read-files))
                (cut landlock-restrict! '() #:scope '(read-file))
                (cut landlock-restrict! '() #:flags '(tsnyc))
                (cut landlock-restrict! '() #:quiet-net '(signal))
                (cut landlock-restrict! '("/"))
                (cut landlock-restrict! #f)
                (cut landlock-restrict! '() #:require 'mostly-enforced)
                (cut landlock-restrict! '() #:abi -1)
                (cut landlock-restrict! '() #:abi "10")))))
  (test-equal "invalid commands"
    '((landlock-error ()) (landlock-error ("true" 1)))
    (restricted
     (map exception-of
          (list (cut landlock-exec '() '())
                (cut landlock-exec '() '("true" 1)))))))

(test-group "paths"
  (test-equal "missing paths raise a system error"
    '((system-error 2) (system-error 2) (system-error 2) (system-error 2))
    (restricted
     (map exception-of
          (list (cut landlock-restrict!
                     (list (landlock-path "/nonexistent" '(read-file))))
                (cut landlock-restrict!
                     (list (landlock-path "/nonexistent" '(read-file)))
                     #:abi 0 #:require 'not-enforced)
                (cut landlock-restrict!
                     (list (landlock-path "/nonexistent" '(read-file)))
                     #:fs '(write-file))
                (cut landlock-restrict!
                     (list (landlock-path "/nonexistent" '() #:quiet? #t))
                     #:quiet-fs '(read-file))))))
  (call-with-temporary-directory
   (lambda (dir)
     (mkdir (in dir "locked") 0)
     (test-equal "optional paths that can't be opened are skipped"
       '(#f #f #f)
       (restricted
        (map (lambda (path)
               (exception-of
                (cut landlock-restrict!
                     (list (landlock-path path '(read-file) #:optional? #t))
                     #:fs '(read-file) #:net '() #:require 'not-enforced)))
             (list "/nonexistent"
                   (in test-file "file")
                   (if (zero? (getuid))
                       "/nonexistent"
                       (in dir "locked/file")))))))))

(test-group "requirements"
  (test-equal "nothing handled"
    '(landlock-error)
    (restricted
     (landlock-restrict! '() #:fs '() #:net '() #:flags '())))
  (test-equal "not enforced without Landlock"
    'landlock-error
    (car (restricted (landlock-restrict! '() #:abi 0))))
  (test-equal "accepting no enforcement"
    'not-enforced
    (restricted (landlock-restrict! '() #:abi 0 #:require 'not-enforced)))
  (test-equal "unhandled rule rights"
    '(landlock-error (path-rules read-dir) (port-rules bind-tcp))
    (restricted
     (landlock-restrict! (list (landlock-path test-dir '(read-file read-dir))
                               (landlock-port 80 '(bind-tcp)))
                         #:fs '(read-file) #:net '(connect-tcp)
                         #:require 'fully-enforced)))
  (test-equal "unhandled quiet rights"
    '(landlock-error (quiet-fs read-file) (quiet-scope signal))
    (restricted
     (landlock-restrict! '() #:fs '(write-file)
                         #:quiet-fs '(read-file) #:quiet-scope '(signal)
                         #:require 'fully-enforced))))

(test-group "exec"
  (test-equal "landlock-exec refuses to run unrestricted"
    '((landlock-error) (landlock-error ("true")))
    (map (lambda (require)
           (restricted
            (landlock-exec '() '("true") #:fs '() #:net '()
                           #:require require)))
         '(partially-enforced not-enforced))))

(test-equal "errata"
  (>= abi 7)
  (integer? (landlock-errata)))

(require-abi 7 "unsupported features")

(test-group "unsupported features"
  (test-equal "fully-enforced requirement"
    '(landlock-error (net bind-udp) (quiet-fs read-file) (flags tsync))
    (restricted
     (landlock-restrict! '() #:fs '(read-file) #:net '(bind-tcp bind-udp)
                         #:quiet-fs '(read-file) #:flags '(tsync)
                         #:abi 7 #:require 'fully-enforced))))

(require-abi 1 "filesystem")

(test-group "filesystem"
  (call-with-temporary-directory
   (lambda (dir)
     (write-text (in dir "outside") "outside")
     (test-equal "restrict to paths"
       `(,default-enforcement "abc abc abc" ,EACCES)
       (restricted
        (list (landlock-restrict! (list (landlock-path test-dir '(read-file)))
                                  #:fs '(read-file) #:net '())
              (read-text test-file)
              (errno-of (read-text (in dir "outside"))))))
     (test-equal "unhandled rights are dropped"
       `(,default-enforcement ok ,EACCES)
       (restricted
        (list (landlock-restrict!
               (list (landlock-path test-dir %landlock-read-access))
               #:fs '(read-file) #:net '())
              (errno-of (closedir (opendir dir)))
              (errno-of (read-text (in dir "outside"))))))
     (test-equal "restrictions stack"
       `(,EACCES ,EACCES "abc abc abc")
       (restricted
        (landlock-restrict! (list (landlock-path test-dir '(read-file))
                                  (landlock-path dir '(read-file)))
                            #:fs '(read-file) #:net '())
        (landlock-restrict! (list (landlock-path test-dir '(read-file)))
                            #:fs '(read-file) #:net '())
        (let ((after-narrowing (errno-of (read-text (in dir "outside")))))
          (landlock-restrict! (list (landlock-path test-dir '(read-file))
                                    (landlock-path dir '(read-file)))
                              #:fs '(read-file) #:net '())
          (list after-narrowing
                (errno-of (read-text (in dir "outside")))
                (read-text test-file)))))))
  (test-equal "more rules than file descriptors"
    default-enforcement
    (restricted
     (setrlimit 'nofile 32 32)
     (landlock-restrict! (make-list 100 (landlock-path test-dir '(read-file)))
                         #:fs '(read-file) #:net '())))
  (test-equal "directory rights on files are dropped"
    `(,default-enforcement "abc abc abc")
    (restricted
     (list (landlock-restrict! (list (landlock-path test-file
                                                    '(read-file read-dir)))
                               #:fs '(read-file read-dir) #:net '())
           (read-text test-file))))
  (test-equal "fully-enforced requirement rejects directory rights on files"
    `(landlock-error ,test-file (read-dir))
    (restricted
     (landlock-restrict! (list (landlock-path test-file '(read-file read-dir)))
                         #:fs '(read-file read-dir) #:net '()
                         #:require 'fully-enforced)))
  (for-each (match-lambda
              ((right . _)
               (test-equal (format #f "only ~a" right)
                 (expected-fs-operation-results (list right))
                 (fs-operation-results (list right)))))
            %fs-operations)
  (test-equal "read and write access allow everything"
    (expected-fs-operation-results (map first %fs-operations))
    (fs-operation-results (append %landlock-read-access
                                  %landlock-write-access)))
  (call-with-temporary-directory
   (lambda (dir)
     (write-text (in dir "outside") "outside")
     (let ((cat (search-path (parse-path (getenv "PATH")) "cat"))
           (rules (cons (landlock-path test-dir '(read-file)) %store-rules)))
       (test-equal "exec program beneath allowed path"
         0 (exit-status rules (list cat test-file) #:net '()))
       (test-equal "exec'd program can't read outside"
         1 (exit-status rules (list cat (in dir "outside")) #:net '()))
       (test-equal "exec needs execute"
         127 (exit-status (list (landlock-path "/" '(read-file)))
                          (list cat test-file)
                          #:net '()))
       (test-equal "exec doesn't need tsync"
         0 (exit-status rules (list cat test-file)
                        #:fs %landlock-read-access #:net '() #:abi 7
                        #:require 'fully-enforced))
       (test-equal "failing exec raises a system error"
         `(system-error ,ENOENT)
         (restricted
          (landlock-exec '() '("/nonexistent") #:fs '(read-file)
                         #:net '())))))))

(require-abi 2 "refer")

(test-group "refer"
  (call-with-temporary-directory
   (lambda (dir)
     (mkdir (in dir "other"))
     (write-text (in dir "file") "abc")
     (test-equal "hard links into other directories need refer"
       `((ok) (,EXDEV))
       (map (lambda (rights link-name)
              (errnos-after
               (cut landlock-restrict! (list (landlock-path dir rights))
                    #:net '())
               (list (cut link (in dir "file") (in dir link-name)))))
            '((make-reg refer) (make-reg))
            '("other/a" "other/b"))))))

(require-abi 4 "network")

(test-group "network"
  (call-with-tcp-listener
   (lambda (allowed)
     (call-with-tcp-listener
      (lambda (other)
        (define (results rules)
          (errnos-after (cut landlock-restrict! rules #:fs '())
                        (list (cut bind-port SOCK_STREAM 0)
                              (cut connect-port SOCK_STREAM allowed)
                              (cut connect-port SOCK_STREAM other))))

        (test-equal "only bind-tcp"
          `(ok ,EACCES ,EACCES)
          (results (list (landlock-port 0 '(bind-tcp)))))
        (test-equal "only connect-tcp"
          `(,EACCES ok ,EACCES)
          (results (list (landlock-port allowed '(connect-tcp)))))))))
  (test-equal "partially enforced on older ABIs"
    `(partially-enforced ok ,EACCES)
    (restricted
     (list (landlock-restrict! '() #:fs '(read-file) #:abi 3)
           (errno-of (bind-port SOCK_STREAM 0))
           (errno-of (read-text test-file)))))
  (test-equal "fully-enforced requirement on older ABIs"
    '(landlock-error (net bind-tcp connect-tcp))
    (restricted
     (landlock-restrict! '() #:fs '(read-file) #:net '(bind-tcp connect-tcp)
                         #:flags '() #:abi 3
                         #:require 'fully-enforced))))

(require-abi 6 "scopes")

(test-group "scopes"
  (let ((address (format #f "\x00guile-landlock-~a" (getpid))))
    (call-with-listener AF_UNIX (list address)
      (lambda (_)
        (define (results scope)
          (errnos-after (cut landlock-restrict! '() #:fs '() #:net '()
                             #:scope scope)
                        (list (cut kill (getppid) 0)
                              (cut connect-unix address))))

        (test-equal "only signal"
          `(,EPERM ok)
          (results '(signal)))
        (test-equal "only abstract-unix-socket"
          `(ok ,EPERM)
          (results '(abstract-unix-socket)))))))

(require-abi 8 "tsync")

(test-group "tsync"
  (define (read-in-other-thread restrict)
    (restricted
     (match (pipe)
       ((in . out)
        (let ((thread (call-with-new-thread
                       (lambda ()
                         (read-char in)
                         (errno-of (read-text test-file))))))
          (restrict)
          (write-char #\x out)
          (force-output out)
          (join-thread thread))))))

  (test-equal "without tsync, other threads are unrestricted"
    'ok
    (read-in-other-thread (cut landlock-restrict! '() #:net '() #:flags '())))
  (test-equal "tsync restricts all threads by default"
    EACCES
    (read-in-other-thread (cut landlock-restrict! '() #:net '())))
  (test-equal "failing exec leaves no thread unrestricted"
    EACCES
    (read-in-other-thread
     (lambda ()
       (false-if-exception
        (landlock-exec '() '("/nonexistent") #:fs '(read-file)
                       #:net '()))))))

(require-abi 9 "resolve-unix")

(test-group "resolve-unix"
  (call-with-temporary-directory
   (lambda (dir)
     (let ((socket-file (in dir "socket")))
       (call-with-listener AF_UNIX (list socket-file)
         (lambda (_)
           (test-equal "connect to socket files"
             `((ok) (,EACCES))
             (map (lambda (path)
                    (errnos-after
                     (cut landlock-restrict!
                          (list (landlock-path path '(resolve-unix)))
                          #:fs '(resolve-unix)
                          #:require 'fully-enforced)
                     (list (cut connect-unix socket-file))))
                  (list socket-file test-dir)))))))))

(require-abi 10 "abi 10")

(test-group "abi 10"
  (define (udp-results rules)
    (errnos-after (cut landlock-restrict! rules #:fs '())
                  (list (cut bind-port SOCK_DGRAM 0)
                        (cut connect-port SOCK_DGRAM 9)
                        (cut connect-port SOCK_DGRAM 10))))

  (test-equal "only bind-udp"
    `(ok ,EACCES ,EACCES)
    (udp-results (list (landlock-port 0 '(bind-udp)))))
  ;; Connecting an unbound socket binds it to port 0.
  (test-equal "connect-send-udp and binding port 0"
    `(ok ok ,EACCES)
    (udp-results (list (landlock-port 9 '(connect-send-udp))
                       (landlock-port 0 '(bind-udp)))))
  (test-equal "quiet rules and restrict flags"
    'fully-enforced
    (restricted
     (landlock-restrict! (list (landlock-port 0 '(bind-udp) #:quiet? #t)
                               (landlock-path test-dir '(read-file)
                                              #:quiet? #t))
                         #:quiet-fs '(read-file) #:quiet-net '(bind-udp)
                         #:scope '(signal) #:quiet-scope '(signal)
                         #:flags '(log-same-exec-off tsync)
                         #:require 'fully-enforced)))
  (test-equal "quiet rule without access"
    'fully-enforced
    (restricted
     (landlock-restrict! (list (landlock-path test-dir '() #:quiet? #t))
                         #:quiet-fs '(read-file)
                         #:require 'fully-enforced)))
  (test-equal "quiet rule without handled rights"
    'fully-enforced
    (restricted
     (landlock-restrict! (list (landlock-path test-dir '(read-file)
                                              #:quiet? #t))
                         #:fs '(write-file))))
  (test-equal "unhandled quiet rights are dropped"
    'fully-enforced
    (restricted
     (landlock-restrict! '() #:fs '(write-file)
                         #:quiet-fs '(read-file) #:quiet-scope '(signal)))))

(define failures (test-runner-fail-count (test-runner-current)))
(test-end "landlock")
(exit (zero? failures))
