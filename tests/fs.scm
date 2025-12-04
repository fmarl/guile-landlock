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
;; File: fs.scm

(add-to-load-path "../src/")

(use-modules (ice-9 rdelim)
	     (ffi landlock))
,9
(define (read-test-file)
  (display (read-line
	    (open-input-file (string-append (dirname (current-filename)) "/test.txt")))))

(define (without-landlock)
  read-test-file)

(define (with-landlock)
  (begin
    ()))
