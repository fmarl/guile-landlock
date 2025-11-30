(define-module (ffi landlock)
  #:use-module (system foreign-library)
  #:use-module (system foreign)
  #:export (ll-create-ruleset))

(define ll-create-ruleset
  (foreign-library-function "./shim.so" "ll_create_ruleset"
                            #:return-type int
                            #:arg-types (list int int int)))

