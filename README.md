# guile-landlock

Guile bindings for [Landlock](https://docs.kernel.org/userspace-api/landlock.html).

```scheme
(use-modules (landlock))

(landlock-restrict!
 (list (landlock-path "/gnu/store" %landlock-read-access)
       (landlock-path "/tmp" (append %landlock-read-access %landlock-write-access))
       (landlock-path "/etc/ssl" '(read-file read-dir) #:optional? #t)
       (landlock-port 443 '(connect-tcp)))
 #:scope '(signal abstract-unix-socket))
```

## Wrapping Guix packages

```scheme
(use-modules (guix gexp) (gnu packages base))

(define guile-landlock (load "/path/to/guile-landlock/guix.scm"))

(program-file "cat-landlocked"
  (with-extensions (list guile-landlock)
    #~(begin
        (use-modules (landlock))
        (landlock-exec (list (landlock-path "/gnu/store" %landlock-read-access)
                             (landlock-path (getcwd) '(read-file)))
                       (cons #$(file-append coreutils "/bin/cat")
                             (cdr (command-line)))
                       #:net '()))))
```

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
