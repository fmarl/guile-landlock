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

(define-module (landlock)
  #:use-module (ice-9 exceptions)
  #:use-module (ice-9 match)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (system foreign)
  #:use-module (system foreign-library)
  #:export (landlock-abi-version
            landlock-supported?
            landlock-errata

            %landlock-read-access
            %landlock-write-access

            landlock-path
            landlock-path?
            landlock-path-path
            landlock-path-access
            landlock-path-optional?
            landlock-path-quiet?
            landlock-port
            landlock-port?
            landlock-port-port
            landlock-port-access
            landlock-port-quiet?

            landlock-restrict!
            landlock-exec

            landlock-error?))

(define %fs-access
  '((execute 0 1)
    (write-file 1 1)
    (read-file 2 1)
    (read-dir 3 1)
    (remove-dir 4 1)
    (remove-file 5 1)
    (make-char 6 1)
    (make-dir 7 1)
    (make-reg 8 1)
    (make-sock 9 1)
    (make-fifo 10 1)
    (make-block 11 1)
    (make-sym 12 1)
    (refer 13 2)
    (truncate 14 3)
    (ioctl-dev 15 5)
    (resolve-unix 16 9)))

(define %net-access
  '((bind-tcp 0 4)
    (connect-tcp 1 4)
    (bind-udp 2 10)
    (connect-send-udp 3 10)))

(define %scopes
  '((abstract-unix-socket 0 6)
    (signal 1 6)))

(define %restrict-flags
  '((log-same-exec-off 0 7)
    (log-new-exec-on 1 7)
    (log-subdomains-off 2 7)
    (tsync 3 8)))

(define %kinds
  `((fs ,%fs-access "filesystem access rights")
    (net ,%net-access "network access rights")
    (scope ,%scopes "scopes")
    (flags ,%restrict-flags "flags")))

;; struct landlock_ruleset_attr
(define %ruleset-fields
  '((fs . fs)
    (net . net)
    (scope . scope)
    (quiet-fs . fs)
    (quiet-net . net)
    (quiet-scope . scope)))

(define %quiet-abi 10)

(define (quiet-table table)
  (map (match-lambda
         ((name bit abi) (list name bit (max abi %quiet-abi))))
       table))

(define (field-table field)
  (let ((kind (assq-ref %ruleset-fields field)))
    (if (eq? field kind)
        (second (assq kind %kinds))
        (quiet-table (field-table kind)))))

(define %landlock-read-access
  '(execute read-file read-dir))

(define %landlock-write-access
  (lset-difference eq? (map first %fs-access) %landlock-read-access))

(define %enforcement-levels
  '(not-enforced partially-enforced fully-enforced))

(define-exception-type &landlock-error &error
  make-landlock-error
  landlock-error?)

(define (raise-landlock-error message . irritants)
  (raise-exception
   (make-exception (make-landlock-error)
                   (make-exception-with-origin 'landlock)
                   (make-exception-with-message message)
                   (make-exception-with-irritants irritants))))

(define (check-names kind names)
  (match (assq kind %kinds)
    ((_ table what)
     (match names
       ('all (map first table))
       (((? symbol?) ...)
        (match (remove (cut assq <> table) names)
          (() names)
          (unknown (raise-landlock-error (string-append "unknown " what)
                                         unknown))))
       (_ (raise-landlock-error (string-append "invalid " what) names))))))

(define (names->mask table names abi)
  "Return the bitmask of NAMES from TABLE that ABI supports."
  (fold (lambda (name mask)
          (match (assq-ref table name)
            ((bit since) (if (>= abi since) (logior mask (ash 1 bit)) mask))))
        0
        names))

(define (unsupported table names abi)
  "Return the NAMES from TABLE that ABI doesn't support."
  (filter (lambda (name)
            (match (assq-ref table name)
              ((_ since) (< abi since))))
          names))

(define (group key names)
  (if (null? names) '() `((,key ,@names))))

(define-record-type <landlock-path>
  (make-landlock-path path access optional? quiet?)
  landlock-path?
  (path landlock-path-path)
  (access landlock-path-access)
  (optional? landlock-path-optional?)
  (quiet? landlock-path-quiet?))

(define* (landlock-path path access #:key optional? quiet?)
  "Allow ACCESS, a list of filesystem access rights or 'all, beneath PATH.  An
OPTIONAL? path is skipped if it doesn't exist or isn't accessible.  Denials of
QUIET? paths aren't logged for the access rights given as #:quiet-fs to
landlock-restrict!."
  (unless (string? path)
    (raise-landlock-error "invalid path" path))
  (make-landlock-path path (check-names 'fs access) optional? quiet?))

(define-record-type <landlock-port>
  (make-landlock-port port access quiet?)
  landlock-port?
  (port landlock-port-port)
  (access landlock-port-access)
  (quiet? landlock-port-quiet?))

(define* (landlock-port port access #:key quiet?)
  "Allow ACCESS, a list of network access rights or 'all, on PORT."
  (unless (and (exact-integer? port) (<= 0 port 65535))
    (raise-landlock-error "invalid port" port))
  (make-landlock-port port (check-names 'net access) quiet?))

(define (check-rules rules)
  (unless (and (list? rules)
               (every (lambda (rule)
                        (or (landlock-path? rule) (landlock-port? rule)))
                      rules))
    (raise-landlock-error "invalid rules" rules)))

(define (syscall-offset host-type pointer-size)
  (let ((arch (car (string-split host-type #\-))))
    (cond ((string-prefix? "alpha" arch) 110)
          ((string-prefix? "mips" arch)
           (cond ((= pointer-size 8) 5000)                ; n64
                 ((string-prefix? "mips64" arch) 6000)    ; n32
                 (else 4000)))                            ; o32
          ((and (string=? arch "x86_64") (= pointer-size 4))
           #x40000000)                                    ; x32
          (else 0))))

(define %landlock-create-ruleset
  (+ 444 (syscall-offset %host-type (sizeof '*))))
(define %landlock-add-rule (+ %landlock-create-ruleset 1))
(define %landlock-restrict-self (+ %landlock-create-ruleset 2))

(define %create-ruleset-version 1)
(define %create-ruleset-errata 2)
(define %add-rule-quiet 1)
(define %rule-path-beneath 1)
(define %rule-net-port 2)
(define %pr-set-no-new-privs 38)

(define (checked name proc . leading)
  (lambda args
    (call-with-values (cut apply proc (append leading args))
      (lambda (result errno)
        (if (< result 0)
            (throw 'system-error name "~A"
                   (list (strerror errno)) (list errno))
            result)))))

(define (c-function name return-type arg-types)
  (foreign-library-function #f name
                            #:return-type return-type
                            #:arg-types arg-types
                            #:return-errno? #t))

(define (syscall name number . arg-types)
  (checked name (c-function "syscall" long (cons long arg-types)) number))

(define create-ruleset
  (syscall "landlock_create_ruleset" %landlock-create-ruleset
           '* unsigned-long unsigned-long))

(define add-rule
  (syscall "landlock_add_rule" %landlock-add-rule
           long long '* unsigned-long))

(define restrict-self
  (syscall "landlock_restrict_self" %landlock-restrict-self
           long unsigned-long))

(define set-no-new-privs!
  (checked "prctl"
           (c-function "prctl" int (cons int (make-list 4 unsigned-long)))
           %pr-set-no-new-privs 1 0 0 0))

(define (u64-struct . fields)
  (uint-list->bytevector fields (native-endianness) 8))

(define (path-beneath-attr access fd)
  ;; Packed struct: __u64 followed by __s32.
  (let ((bv (make-bytevector 12)))
    (bytevector-u64-native-set! bv 0 access)
    (bytevector-s32-native-set! bv 8 fd)
    bv))

(define (landlock-abi-version)
  "Return the Landlock ABI version of the running kernel, or 0 if Landlock is
unsupported or disabled."
  (catch 'system-error
    (cut create-ruleset %null-pointer 0 %create-ruleset-version)
    (const 0)))

(define (landlock-supported?)
  (> (landlock-abi-version) 0))

(define (landlock-errata)
  "Return the bitmask of fixed issues of the running kernel's Landlock ABI, or
#f if the kernel doesn't report errata."
  (and (>= (landlock-abi-version) 7)
       (create-ruleset %null-pointer 0 %create-ruleset-errata)))

(define (target-abi abi)
  (unless (or (not abi) (and (exact-integer? abi) (>= abi 0)))
    (raise-landlock-error "invalid ABI version" abi))
  (let ((kernel (landlock-abi-version)))
    (min kernel (or abi kernel))))

(define (call-with-fdes fd proc)
  (dynamic-wind (const #t)
                (cut proc fd)
                (cut close-fdes fd)))

(define (open-path path optional?)
  "Return an O_PATH file descriptor for PATH, or #f if PATH is OPTIONAL? and
doesn't exist or isn't accessible."
  (catch 'system-error
    (cut open-fdes path (logior O_PATH O_CLOEXEC))
    (lambda args
      (if (and optional?
               (memv (system-error-errno args) (list ENOENT ENOTDIR EACCES)))
          #f
          (apply throw args)))))

;; The kernel rejects directory rights on files.
(define %file-access
  '(execute write-file read-file truncate ioctl-dev resolve-unix))

(define (path-access rule fd)
  (if (eq? 'directory (stat:type (stat fd)))
      (landlock-path-access rule)
      (lset-intersection eq? (landlock-path-access rule) %file-access)))

(define (for-each-rule proc rules)
  (for-each (lambda (rule)
              (match rule
                ((? landlock-port?)
                 (proc rule #f (landlock-port-access rule)))
                ((? landlock-path?)
                 (match (open-path (landlock-path-path rule)
                                   (landlock-path-optional? rule))
                   (#f #f)
                   (fd (call-with-fdes fd
                         (lambda (fd)
                           (proc rule fd (path-access rule fd)))))))))
            rules))

(define (check-file-access rule fd access)
  (when (landlock-path? rule)
    (match (lset-difference eq? (landlock-path-access rule) access)
      (() #t)
      (rights (raise-landlock-error "directory access rights on a file"
                                    (landlock-path-path rule) rights)))))

(define (ruleset-names fs net scope quiet-fs quiet-net quiet-scope)
  (map (match-lambda*
         (((field . kind) names) (cons field (check-names kind names))))
       %ruleset-fields
       (list fs net scope quiet-fs quiet-net quiet-scope)))

(define (unhandled-access rules names)
  "Return the access rights in RULES and the quiet fields of NAMES that NAMES
doesn't handle."
  (define (unhandled rights field)
    (lset-difference eq? rights (assq-ref names field)))

  (define (rule-access rule? access)
    (delete-duplicates (append-map access (filter rule? rules))))

  (append (group 'path-rules
                 (unhandled (rule-access landlock-path? landlock-path-access)
                            'fs))
          (group 'port-rules
                 (unhandled (rule-access landlock-port? landlock-port-access)
                            'net))
          (append-map (match-lambda
                        ((field . kind)
                         (group field
                                (unhandled (assq-ref names field) kind))))
                      %ruleset-fields)))

(define (missing-features names flags abi)
  "Return the NAMES and FLAGS that ABI doesn't support."
  (append (append-map (lambda (field)
                        (group field (unsupported (field-table field)
                                                  (assq-ref names field)
                                                  abi)))
                      (map first %ruleset-fields))
          (group 'flags (unsupported %restrict-flags flags abi))))

(define (ruleset-masks names abi)
  (define (mask field)
    (names->mask (field-table field) (assq-ref names field) abi))

  ;; The kernel rejects quiet rights that aren't handled.
  (map (match-lambda
         ((field . kind) (cons field (logand (mask kind) (mask field)))))
       %ruleset-fields))

(define (add-rule! ruleset-fd rule fd access masks abi)
  "Add RULE to RULESET-FD, limited to the rights handled by MASKS."
  (define (add! type attr kind quiet-field quiet?)
    (let ((mask (logand (assq-ref masks kind)
                        (names->mask (field-table kind) access abi)))
          ;; The kernel rejects quiet rules if nothing is quiet.
          (flags (if (and quiet? (not (zero? (assq-ref masks quiet-field))))
                     %add-rule-quiet
                     0)))
      (unless (and (zero? mask) (zero? flags))
        (add-rule ruleset-fd type (bytevector->pointer (attr mask)) flags))))

  (match rule
    ((? landlock-path?)
     (add! %rule-path-beneath (cut path-beneath-attr <> fd)
           'fs 'quiet-fs (landlock-path-quiet? rule)))
    ((? landlock-port?)
     (add! %rule-net-port (cut u64-struct <> (landlock-port-port rule))
           'net 'quiet-net (landlock-port-quiet? rule)))))

(define (enforce! rules masks flags abi check)
  (call-with-fdes
      (create-ruleset (bytevector->pointer
                       (apply u64-struct
                              (map (compose (cut assq-ref masks <>) first)
                                   %ruleset-fields)))
                      (* 8 (length %ruleset-fields))
                      0)
    (lambda (ruleset-fd)
      (for-each-rule (lambda (rule fd access)
                       (check rule fd access)
                       (add-rule! ruleset-fd rule fd access masks abi))
                     rules)
      (set-no-new-privs!)
      (restrict-self ruleset-fd (names->mask %restrict-flags flags abi)))))

(define (enforcement masks missing)
  (cond
   ;; The kernel rejects rulesets that handle nothing.
   ((every (compose zero? (cut assq-ref masks <>)) '(fs net scope))
    'not-enforced)
   ((null? missing) 'fully-enforced)
   (else 'partially-enforced)))

(define (check-enforcement result required abi missing)
  (unless (memq result (member required %enforcement-levels))
    (if (null? missing)
        (raise-landlock-error "Landlock isn't enforced")
        (apply raise-landlock-error
               (format #f "not supported by Landlock ABI ~a" abi)
               missing))))

(define* (landlock-restrict! rules
                             #:key
                             (fs 'all) (net 'all) (scope '())
                             (quiet-fs '()) (quiet-net '()) (quiet-scope '())
                             (flags '(tsync))
                             abi
                             (require 'partially-enforced))
  "Restrict all threads, or only the calling one without tsync, and their
future children to RULES, using at most Landlock ABI version ABI.  Raise a
landlock-error unless the result is at least REQUIRE.  Return 'fully-enforced,
'partially-enforced or 'not-enforced."
  (check-rules rules)
  (unless (memq require %enforcement-levels)
    (raise-landlock-error "invalid requirement" require))
  (let* ((abi (target-abi abi))
         (names (ruleset-names fs net scope quiet-fs quiet-net quiet-scope))
         (flags (check-names 'flags flags))
         (masks (ruleset-masks names abi))
         (missing (missing-features names flags abi))
         (result (enforcement masks missing))
         (enforced? (not (eq? result 'not-enforced)))
         (strict? (eq? require 'fully-enforced))
         (check (if strict? check-file-access (const #t))))
    (when strict?
      (match (unhandled-access rules names)
        (() #t)
        (unhandled (apply raise-landlock-error
                          "access rights not handled by the ruleset"
                          unhandled))))
    (unless enforced?
      (for-each-rule check rules))
    (check-enforcement result require abi missing)
    (when enforced?
      (enforce! rules masks flags abi check))
    result))

(define* (landlock-exec rules command
                        #:key abi #:allow-other-keys #:rest options)
  "Restrict the process to RULES, see landlock-restrict! for OPTIONS, and
replace it with COMMAND, a list of the program's file name and its
arguments.  Raise a landlock-error instead of running COMMAND unrestricted."
  (match command
    (((? string? program) (? string?) ...)
     ;; Exec ends other threads, so tsync only matters if it fails.
     (let ((flags (if (>= (target-abi abi) 8) '(tsync) '())))
       (when (eq? 'not-enforced
                  (apply landlock-restrict! rules #:flags flags options))
         (raise-landlock-error "Landlock isn't enforced" command))
       (apply execl program command)))
    (_ (raise-landlock-error "invalid command" command))))
