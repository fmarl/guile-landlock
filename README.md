# guile-landlock

Guile bindings for [Landlock](https://docs.kernel.org/userspace-api/landlock.html),
ABI 1 to 10.  Pure Guile, no C code.

```scheme
(use-modules (landlock))

(landlock-restrict!
 (list (landlock-path "/gnu/store" %landlock-read-access)
       (landlock-path "/tmp" (append %landlock-read-access %landlock-write-access))
       (landlock-path "/etc/ssl" '(read-file read-dir) #:optional? #t)
       (landlock-port 443 '(connect-tcp)))
 #:scope '(signal abstract-unix-socket))
```

## API

`(landlock-path path access #:optional? #:quiet?)` allows `access` beneath
`path`.  An `#:optional?` path that doesn't exist is skipped.

`(landlock-port port access #:quiet?)` allows `access` on `port`.

`(landlock-restrict! rules #:key ...)` restricts the calling thread and its
children.  Returns `fully-enforced`, `partially-enforced` or `not-enforced`.

| Keyword | Default | |
|---|---|---|
| `#:fs`, `#:net` | `'all` | Rights denied unless a rule allows them |
| `#:scope` | `'()` | `signal`, `abstract-unix-socket` |
| `#:quiet-fs`, `#:quiet-net`, `#:quiet-scope` | `'()` | Rights whose denials aren't logged; `#:quiet-fs` and `#:quiet-net` only apply to `#:quiet? #t` rules |
| `#:flags` | `'()` | `log-same-exec-off`, `log-new-exec-on`, `log-subdomains-off`, `tsync` (all threads) |
| `#:best-effort?` | `#t` | Drop what the kernel or ruleset can't handle; `#f` raises `landlock-error` instead |

`(landlock-exec rules command . options)` restricts the process and executes
`command`, a list of the program path and its arguments.  It raises
`landlock-error` instead of running `command` unrestricted.

`(landlock-abi-version)` returns 0 without Landlock.  Failing system calls
raise `system-error`.

Filesystem rights: `execute`, `write-file`, `read-file`, `read-dir`,
`remove-dir`, `remove-file`, `make-char`, `make-dir`, `make-reg`, `make-sock`,
`make-fifo`, `make-block`, `make-sym`, `refer`, `truncate`, `ioctl-dev`,
`resolve-unix`.  `%landlock-read-access` is `execute`, `read-file` and
`read-dir`; `%landlock-write-access` is the rest.

Network rights: `bind-tcp`, `connect-tcp`, `bind-udp`, `connect-send-udp`.

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

The program needs read access to `/gnu/store` for its libraries.  On Guix
System, many files in `/etc` link into the store.

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
