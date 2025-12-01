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
  #:export (ll-create-ruleset
	    ll-abi-version))

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

