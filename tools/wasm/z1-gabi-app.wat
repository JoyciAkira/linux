(module
  (import "env" "memory" (memory 1 32768 shared))
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (table (export "__indirect_function_table") 1 funcref)
  (elem (i32.const 0) $app)

  ;; Z1-GABI witness: /app — exec'd by /init with REAL multi-argv
  ;; ("/app", "--z1", "gamma=42"). Verdict via exit code (the Linux way):
  ;;   7  = PASS  (argc==3, argv[1] recognizable, TLS roundtrip exact)
  ;;   8  = argc wrong
  ;;   9  = TLS roundtrip mismatch
  ;;   10 = argv[1] not recognizable (must start with '-')
  (func $exitc (param $c i32)
    (drop (call $syscall (i32.const 94) (local.get $c)
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (loop $p
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $p)))

  (func $app (param $arg i32) (local $argc i32) (local $tls i32) (local $a1 i32)
    ;; z1_get_args into scratch @2048 (struct + strings fit in 2048 bytes)
    (local.set $argc
      (call $syscall (i32.const 245) (i32.const 2048) (i32.const 2048)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (if (i32.ne (local.get $argc) (i32.const 3))
      (then (call $exitc (i32.const 8))))

    ;; argv[1] string check: first byte must be '-'
    ;; compact layout: argc@0 envc@4 argv[0]@8 argv[1]@12
    (local.set $a1 (i32.load (i32.const 2060)))
    (if (i32.ne (i32.load8_u (local.get $a1)) (i32.const 45))
      (then (call $exitc (i32.const 10))))

    ;; TLS roundtrip: set a recognizable value, read it back
    (drop (call $syscall (i32.const 244) (i32.const 0x0a110cfd)
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (local.set $tls
      (call $syscall (i32.const 246) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (if (i32.ne (local.get $tls) (i32.const 0x0a110cfd))
      (then (call $exitc (i32.const 9))))

    ;; PASS
    (call $exitc (i32.const 7)))

  (export "_start" (func $app)))
