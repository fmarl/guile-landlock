# guile-landlock

Guile bindings for [Landlock](https://docs.kernel.org/userspace-api/landlock.html).
Pure Guile, supports Landlock ABI 1 to 10.

## Usage

```scheme
(use-modules (landlock))

(landlock-restrict!
 (list (landlock-path "/gnu/store" %landlock-read-access)
       (landlock-path "/tmp" (append %landlock-read-access %landlock-write-access))
       (landlock-path "/etc/ssl" '(read-file read-dir) #:optional? #t)
       (landlock-port 443 '(connect-tcp)))
 #:scope '(signal abstract-unix-socket))
;; => fully-enforced, partially-enforced or not-enforced
```

- `(landlock-path path access #:optional? #:quiet?)` allows `access` beneath
  `path`.  Missing `#:optional?` paths are skipped.
- `(landlock-port port access #:quiet?)` allows `access` on `port`.

Keyword arguments of `landlock-restrict!`:

| Keyword | Default | |
|---|---|---|
| `#:fs` | `'all` | Filesystem rights denied unless allowed by a rule |
| `#:net` | `'all` | Network rights denied unless allowed by a rule |
| `#:scope` | `'()` | `signal`, `abstract-unix-socket` |
| `#:quiet-fs`, `#:quiet-net`, `#:quiet-scope` | `'()` | Rights whose denials aren't logged for `#:quiet? #t` rules |
| `#:flags` | `'()` | `log-same-exec-off`, `log-new-exec-on`, `log-subdomains-off`, `tsync` |
| `#:best-effort?` | `#t` | Ignore unsupported rights and rule rights missing from `#:fs`/`#:net` instead of raising a `landlock-error` |

Only the calling thread is restricted unless `#:flags` contains `tsync`.

Filesystem rights: `execute`, `write-file`, `read-file`, `read-dir`,
`remove-dir`, `remove-file`, `make-char`, `make-dir`, `make-reg`, `make-sock`,
`make-fifo`, `make-block`, `make-sym`, `refer`, `truncate`, `ioctl-dev`,
`resolve-unix`.  `%landlock-read-access` contains `execute`, `read-file` and
`read-dir`, `%landlock-write-access` the rest.

Network rights: `bind-tcp`, `connect-tcp`, `bind-udp`, `connect-send-udp`.

`(landlock-abi-version)` returns 0 if Landlock is unavailable.  Failing system
calls raise `system-error`.

## Wrapping Guix packages

`landlock-exec` restricts the process and executes a command:

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

The wrapped program needs `/gnu/store` to load its libraries.  Many files in
`/etc` on Guix System are symlinks into the store.

## Development

```sh
guix shell -m manifest.scm -- make check
guix build -f guix.scm
```
