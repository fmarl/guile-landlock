(use-modules (guix gexp)
             (guix git-download)
             (guix packages)
             (guix build-system guile)
             ((guix licenses) #:prefix license:)
             (gnu packages base)
             (gnu packages guile))

(define %source-dir (dirname (current-filename)))

(package
  (name "guile-landlock")
  (version "0.1.0-git")
  (source (local-file %source-dir "guile-landlock-checkout"
                      #:recursive? #t
                      #:select? (or (git-predicate %source-dir) (const #t))))
  (build-system guile-build-system)
  (arguments
   (list #:source-directory "src"
         #:phases
         #~(modify-phases %standard-phases
             (add-after 'build 'check
               (lambda _
                 (invoke "guile" "--no-auto-compile" "-L" "src"
                         "tests/landlock.scm"))))))
  (native-inputs (list coreutils guile-3.0))
  (home-page "https://github.com/fmarl/guile-landlock")
  (synopsis "Guile bindings for the Landlock sandboxing API")
  (description
   "Guile-Landlock restricts filesystem, network and IPC access of Guile
programs and the programs they execute using Linux's Landlock.")
  (license license:gpl3+))
