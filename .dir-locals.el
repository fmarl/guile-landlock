;;; SPDX-License-Identifier: GPL-3.0-or-later
;;; Copyright © 2026 Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>

;; Per-directory local variables for GNU Emacs, following those of Guix.

((nil
  . ((fill-column . 78)
     (tab-width   .  8)
     (sentence-end-double-space . t)))
 (scheme-mode
  .
  ((indent-tabs-mode . nil)

   ;; Guile and Guix forms used here.
   (eval . (put 'catch 'scheme-indent-function 1))
   (eval . (put 'dynamic-wind 'scheme-indent-function nil))
   (eval . (put 'package 'scheme-indent-function 0))
   (eval . (put 'test-assert 'scheme-indent-function 1))
   (eval . (put 'test-equal 'scheme-indent-function 1))

   ;; Forms of this project.
   (eval . (put 'call-with-fdes 'scheme-indent-function 1)))))
