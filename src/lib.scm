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
;; File: lib.scm

(define-module (ffi landlock)
  #:use-module (system foreign-library)
  #:use-module (system foreign)
  #:use-module (srfi srfi-9)
  #:export (landlock-abi-version
	    landlock-supported?))

(define-record-type <capabilities>
  (make-capabilities fs-mask net-mask scope-mask)
  capabilities?
  (fs-mask capabilities)
  (net-mask capabilities)
  (scope-mask capabilities))

(define shim "./shim.so")

(define ffi-landlock-abi-version
  (foreign-library-function shim "scm_ll_abi_version"
			    #:return-type int
			    #:arg-types '()))

(define ffi-landlock-create-ruleset
  (foreign-library-function shim "scm_ll_create_ruleset"
                            #:return-type int
                            #:arg-types (list long long long)))

(define ffi-landlock-add-net-port-rule
  (foreign-library-function shim "scm_ll_add_net_port_rule"
			    #:return-type int
			    #:arg-types (list int long int)))

(define ffi-landlock-restrict-self
  (foreign-library-function shim "scm_ll_restrict_self"
			    #:return-type int
			    #:arg-types (list int)))

(define (landlock-abi-version)
  (let ((version (ffi-landlock-abi-version)))
    (cond ((= version 1) 'V1)
          ((= version 2) 'V2)
          ((= version 3) 'V3)
          ((= version 4) 'V4)
          ((= version 5) 'V5)
          ((= version 6) 'V6)
          ((= version 7) 'V7)
          (else 'V0))))

(define (landlock-supported?)
  (not (eq? (landlock-abi-version) 'V0)))

(define (landlock-capabilities abi)
  (cond ((eq? abi 'V1) (make-capabilities (- (ash 1 13) 1) 0 0))
        ((eq? abi 'V2) (make-capabilities (- (ash 1 14) 1) 0 0))
        ((eq? abi 'V3) (make-capabilities (- (ash 1 15) 1) 0 0))
        ((eq? abi 'V4) (make-capabilities (- (ash 1 15) 1) (- (ash 1 2) 1) 0))
        ((eq? abi 'V5) (make-capabilities (- (ash 1 16) 1) (- (ash 1 2) 1) 0))
        ((eq? abi 'V6) (make-capabilities (- (ash 1 16) 1) (- (ash 1 2) 1) (- (ash 1 2) 1)))
        ((eq? abi 'V7) (make-capabilities (- (ash 1 16) 1) (- (ash 1 2) 1) (- (ash 1 2) 1)))
        (else (make-capabilities 0 0 0))))

(define (landlock-access-fs access)
  (cond ((eq? access 'EXECUTE) (ash 1 0))
        ((eq? access 'WRITE_FILE) (ash 1 1))
        ((eq? access 'READ_FILE) (ash 1 2))
        ((eq? access 'READ_DIR) (ash 1 3))
        ((eq? access 'REMOVE_DIR) (ash 1 4))
        ((eq? access 'REMOVE_FILE) (ash 1 5))
        ((eq? access 'MAKE_CHAR) (ash 1 6))
        ((eq? access 'MAKE_DIR) (ash 1 7))
        ((eq? access 'MAKE_REG) (ash 1 8))
        ((eq? access 'MAKE_SOCK) (ash 1 9))
        ((eq? access 'MAKE_FIFO) (ash 1 10))
        ((eq? access 'MAKE_BLOCK) (ash 1 11))
        ((eq? access 'MAKE_SYM) (ash 1 12))
        ((eq? access 'REFER) (ash 1 13))
        ((eq? access 'TRUNCATE) (ash 1 14))
        ((eq? access 'IOCTL_DEV) (ash 1 15))))

(define (landlock-access-net access)
  (cond ((eq? access 'BIND_TCP) (ash 1 0))
        ((eq? access 'CONNECT_TCP) (ash 1 1))))

(define (landlock-access-scope access)
  (cond ((eq? access 'ABSTRACT_UNIX_SOCKET) (ash 1 0))
        ((eq? access 'SIGNAL) (ash 1 1))))
