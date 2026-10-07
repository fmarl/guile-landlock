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
	    landlock-port
	    landlock-port?

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

(define %quiet-abi 10)

(define (quiet-table table)
  (map (match-lambda
	 ((name bit abi) (list name bit (max abi %quiet-abi))))
       table))

(define %landlock-read-access
  '(execute read-file read-dir))

(define %landlock-write-access
  (lset-difference eq? (map first %fs-access) %landlock-read-access))

(define-exception-type &landlock-error &error
  make-landlock-error
  landlock-error?)

(define (raise-landlock-error message . irritants)
  (raise-exception
   (make-exception (make-landlock-error)
		   (make-exception-with-origin 'landlock)
		   (make-exception-with-message message)
		   (make-exception-with-irritants irritants))))

(define (lookup table name)
  (or (assq-ref table name)
      (raise-landlock-error "unknown access right or flag" name)))

(define (expand table names)
  (if (eq? names 'all)
      (map first table)
      names))

(define (names->mask table names abi)
  "Return the bitmask of NAMES from TABLE that ABI supports."
  (fold (lambda (name mask)
	  (match (lookup table name)
	    ((bit since) (if (>= abi since) (logior mask (ash 1 bit)) mask))))
	0
	names))

(define (unsupported table names abi)
  "Return the NAMES from TABLE that ABI doesn't support."
  (filter (lambda (name)
	    (match (lookup table name)
	      ((_ since) (< abi since))))
	  names))

(define-record-type <landlock-path>
  (make-landlock-path path access optional? quiet?)
  landlock-path?
  (path landlock-path-path)
  (access landlock-path-access)
  (optional? landlock-path-optional?)
  (quiet? landlock-path-quiet?))

(define* (landlock-path path access #:key optional? quiet?)
  "Allow ACCESS, a list of filesystem access rights, beneath PATH.  An
OPTIONAL? path is skipped if it doesn't exist.  Denials of QUIET? paths aren't
logged for the access rights given as #:quiet-fs to landlock-restrict!."
  (make-landlock-path path access optional? quiet?))

(define-record-type <landlock-port>
  (make-landlock-port port access quiet?)
  landlock-port?
  (port landlock-port-port)
  (access landlock-port-access)
  (quiet? landlock-port-quiet?))

(define* (landlock-port port access #:key quiet?)
  "Allow ACCESS, a list of network access rights, on PORT."
  (make-landlock-port port access quiet?))

(define (rule-unsupported rule abi)
  (match rule
    (($ <landlock-path> _ access _ quiet?)
     (append (unsupported %fs-access access abi)
	     (if (and quiet? (< abi %quiet-abi)) '(quiet) '())))
    (($ <landlock-port> _ access quiet?)
     (append (unsupported %net-access access abi)
	     (if (and quiet? (< abi %quiet-abi)) '(quiet) '())))))

(define %landlock-create-ruleset 444)
(define %landlock-add-rule 445)
(define %landlock-restrict-self 446)

(define %create-ruleset-version 1)
(define %create-ruleset-errata 2)
(define %add-rule-quiet 1)
(define %rule-path-beneath 1)
(define %rule-net-port 2)
(define %pr-set-no-new-privs 38)

(define (check-result name)
  (lambda (result errno)
    (if (< result 0)
	(throw 'system-error name "~A" (list (strerror errno)) (list errno))
	result)))

(define (syscall name number arg-types)
  (let ((proc (foreign-library-function #f "syscall"
					#:return-type long
					#:arg-types (cons long arg-types)
					#:return-errno? #t)))
    (lambda args
      (call-with-values (cut apply proc number args)
	(check-result name)))))

(define create-ruleset
  (syscall "landlock_create_ruleset" %landlock-create-ruleset
	   (list '* unsigned-long unsigned-long)))

(define add-rule
  (syscall "landlock_add_rule" %landlock-add-rule
	   (list long long '* unsigned-long)))

(define restrict-self
  (syscall "landlock_restrict_self" %landlock-restrict-self
	   (list long unsigned-long)))

(define set-no-new-privs!
  (let ((prctl (foreign-library-function #f "prctl"
					 #:return-type int
					 #:arg-types (list int unsigned-long unsigned-long
							   unsigned-long unsigned-long)
					 #:return-errno? #t)))
    (lambda ()
      (call-with-values (cut prctl %pr-set-no-new-privs 1 0 0 0)
	(check-result "prctl")))))

(define (u64-struct . fields)
  (let ((bv (make-bytevector (* 8 (length fields)))))
    (for-each (lambda (field index)
		(bytevector-u64-native-set! bv (* 8 index) field))
	      fields
	      (iota (length fields)))
    bv))

(define (path-beneath-attr access fd)
  ;; Packed struct: __u64 followed by __s32.
  (let ((bv (make-bytevector 12)))
    (bytevector-u64-native-set! bv 0 access)
    (bytevector-s32-native-set! bv 8 fd)
    bv))

(define (call-with-fdes fd proc)
  (dynamic-wind (const #t)
		(cut proc fd)
		(cut close-fdes fd)))

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

(define (open-path path optional?)
  "Return an O_PATH file descriptor for PATH, or #f if PATH is OPTIONAL? and
doesn't exist or isn't accessible."
  (catch 'system-error
    (cut open-fdes path (logior O_PATH O_CLOEXEC))
    (lambda args
      (if (and optional? (memv (system-error-errno args) (list ENOENT EACCES)))
	  #f
	  (apply throw args)))))

(define %file-access
  '(execute write-file read-file truncate ioctl-dev resolve-unix))

;; The kernel rejects directory rights on files.
(define (file-mask path access mask abi best-effort?)
  (let ((directory-access (lset-difference eq? access %file-access)))
    (when (and (not best-effort?) (pair? directory-access))
      (raise-landlock-error "directory access rights on a file"
			    path directory-access))
    (logand mask (names->mask %fs-access %file-access abi))))

(define (add-rule! ruleset-fd rule abi masks best-effort?)
  "Add RULE to RULESET-FD, limited to the rights handled by MASKS."
  ;; The kernel rejects quiet rules without access if nothing is quiet.
  (define (quiet-flag quiet? quiet-mask)
    (if (and quiet? (not (zero? quiet-mask))) %add-rule-quiet 0))

  (match-let (((fs net _ quiet-fs quiet-net _) masks))
    (match rule
      (($ <landlock-path> path access optional? quiet?)
       (let ((mask (logand fs (names->mask %fs-access access abi)))
	     (flags (quiet-flag quiet? quiet-fs)))
	 (unless (and (zero? mask) (zero? flags))
	   (let ((fd (open-path path optional?)))
	     (when fd
	       (call-with-fdes fd
		 (lambda (fd)
		   (let ((mask (if (eq? 'directory (stat:type (stat fd)))
				   mask
				   (file-mask path access mask abi
					      best-effort?))))
		     (unless (and (zero? mask) (zero? flags))
		       (add-rule ruleset-fd %rule-path-beneath
				 (bytevector->pointer
				  (path-beneath-attr mask fd))
				 flags))))))))))
      (($ <landlock-port> port access quiet?)
       (let ((mask (logand net (names->mask %net-access access abi)))
	     (flags (quiet-flag quiet? quiet-net)))
	 (unless (and (zero? mask) (zero? flags))
	   (add-rule ruleset-fd %rule-net-port
		     (bytevector->pointer (u64-struct mask port))
		     flags)))))))

(define %ruleset-attr-tables
  (list %fs-access %net-access %scopes
	(quiet-table %fs-access) (quiet-table %net-access) (quiet-table %scopes)))

(define (missing-features abi rules attr flags)
  "Return the access rights and flags in RULES, ATTR and FLAGS that ABI doesn't
support.  ATTR lists the names for each of %ruleset-attr-tables."
  (delete-duplicates
   (append (append-map (cut unsupported <> <> abi) %ruleset-attr-tables attr)
	   (unsupported %restrict-flags flags abi)
	   (append-map (cut rule-unsupported <> abi) rules))))

(define (unhandled-access rules attr)
  "Return the access rights in RULES and in the quiet lists of ATTR that ATTR
doesn't handle."
  (match attr
    ((fs net scope quiet-fs quiet-net quiet-scope)
     (delete-duplicates
      (append (append-map (match-lambda
			    (($ <landlock-path> _ access)
			     (lset-difference eq? access fs))
			    (($ <landlock-port> _ access)
			     (lset-difference eq? access net)))
			  rules)
	      (lset-difference eq? quiet-fs fs)
	      (lset-difference eq? quiet-net net)
	      (lset-difference eq? quiet-scope scope))))))

;; The kernel rejects quiet rights that aren't handled.
(define (attr-masks abi attr)
  (match (map (cut names->mask <> <> abi) %ruleset-attr-tables attr)
    ((fs net scope quiet-fs quiet-net quiet-scope)
     (list fs net scope
	   (logand fs quiet-fs) (logand net quiet-net)
	   (logand scope quiet-scope)))))

(define (enforce! abi rules attr flags best-effort?)
  (let ((masks (attr-masks abi attr)))
    (call-with-fdes
     (create-ruleset (bytevector->pointer (apply u64-struct masks))
		     (* 8 (length %ruleset-attr-tables))
		     0)
     (lambda (ruleset-fd)
       (for-each (cut add-rule! ruleset-fd <> abi masks best-effort?) rules)
       (set-no-new-privs!)
       (restrict-self ruleset-fd (names->mask %restrict-flags flags abi))))))

(define* (landlock-restrict! rules
			     #:key
			     (fs 'all) (net 'all) (scope '())
			     (quiet-fs '()) (quiet-net '()) (quiet-scope '())
			     (flags '())
			     (best-effort? #t))
  "Restrict the calling thread and its future children to RULES.  Without
BEST-EFFORT?, raise a landlock-error for anything that can't be enforced.
Return 'fully-enforced, 'partially-enforced or 'not-enforced."
  (let* ((abi (landlock-abi-version))
	 (attr (map expand %ruleset-attr-tables
		    (list fs net scope quiet-fs quiet-net quiet-scope)))
	 (unhandled (unhandled-access rules attr))
	 (missing (missing-features abi rules attr flags)))
    (cond
     ((and (not best-effort?) (pair? unhandled))
      (raise-landlock-error "access rights not handled by the ruleset"
			    unhandled))
     ((and (not best-effort?) (pair? missing))
      (raise-landlock-error
       (format #f "not supported by Landlock ABI ~a" abi) missing))
     ;; The kernel rejects empty rulesets.
     ((or (zero? abi) (every zero? (take (attr-masks abi attr) 3)))
      'not-enforced)
     (else
      (enforce! abi rules attr flags best-effort?)
      (if (null? missing) 'fully-enforced 'partially-enforced)))))

(define (landlock-exec rules command . options)
  "Restrict the process to RULES, see landlock-restrict! for OPTIONS, and
replace it with COMMAND, a list of the program and its arguments.  Raise a
landlock-error instead of running COMMAND unrestricted."
  (when (eq? 'not-enforced (apply landlock-restrict! rules options))
    (raise-landlock-error "Landlock isn't enforced" command))
  (apply execl (first command) command))
