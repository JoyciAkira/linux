(module
  (import "env" "memory" (memory 1 32768 shared))
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (table (export "__indirect_function_table") 2 funcref)
  (elem (i32.const 0) $init $child_exec)

  ;; Z1-GABI witness: /init verifier.
  ;; Words: @0 magic "Z1G1"(0x5a314731) @4 init_argc @8 argv0_ok @12 tls_ok
  ;;        @16 app raw wait status @20 app verdict(7=pass) @24 getpid @28 done
  ;; Layout: strings/arrays at 4096+ (prepared BEFORE clone so the fork
  ;; child inherits them; execve replaces the child image with /app).
  ;; Child entry: execve("/app", {"/app","--z1","gamma=42"}, {}) with the
  ;; pointers prepared by the parent BEFORE the clone (inherited memory).
  (func $child_exec (param $arg i32)
    (drop (call $syscall (i32.const 221) (i32.const 4096) (i32.const 4200)
      (i32.const 4224) (i32.const 0) (i32.const 0) (i32.const 0)))
    ;; execve must not return; park defensively
    (loop $p
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $p)))

  (func $init (param $arg i32) (local $ret i32) (local $st i32)
    (i32.store (i32.const 0) (i32.const 0x5a314731))

    ;; Z1_GABI_ARGV_REAL (init): argc from kernel-exec'd /init >= 1
    (local.set $ret
      (call $syscall (i32.const 245) (i32.const 1024) (i32.const 2048)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.store (i32.const 4) (local.get $ret))
    (if (i32.ge_s (local.get $ret) (i32.const 1))
      (then
        ;; compact layout: argc@buf+0 envc@buf+4 argv[0]@buf+8
        (if (i32.ne (i32.load8_u (i32.load (i32.const 1032))) (i32.const 0))
          (then (i32.store (i32.const 8) (i32.const 1))))))

    ;; Z1_GABI_TLS_REAL (init): set then get roundtrip
    (drop (call $syscall (i32.const 244) (i32.const 0x12345000)
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (if (i32.eq (call $syscall (i32.const 246)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))
      (i32.const 0x12345000))
      (then (i32.store (i32.const 12) (i32.const 1))))

    ;; Prepare "/app", argv {"/app","--z1","gamma=42",0}, env {0}
    ;; strings @4096.., argv array @4200, env @4224, child scratch @4300
    (i32.store8 (i32.const 4096) (i32.const 47))  ;; '/'
    (i32.store8 (i32.const 4097) (i32.const 97))  ;; 'a'
    (i32.store8 (i32.const 4098) (i32.const 112)) ;; 'p'
    (i32.store8 (i32.const 4099) (i32.const 112)) ;; 'p'
    (i32.store8 (i32.const 4100) (i32.const 0))
    (i32.store8 (i32.const 4101) (i32.const 45))  ;; '-'
    (i32.store8 (i32.const 4102) (i32.const 122)) ;; 'z'
    (i32.store8 (i32.const 4103) (i32.const 49))  ;; '1'
    (i32.store8 (i32.const 4104) (i32.const 0))
    (i32.store8 (i32.const 4105) (i32.const 103)) ;; 'g'
    (i32.store8 (i32.const 4106) (i32.const 97))  ;; 'a'
    (i32.store8 (i32.const 4107) (i32.const 0))
    (i32.store (i32.const 4200) (i32.const 4096))
    (i32.store (i32.const 4204) (i32.const 4101))
    (i32.store (i32.const 4208) (i32.const 4105))
    (i32.store (i32.const 4212) (i32.const 0))
    (i32.store (i32.const 4224) (i32.const 0))

    ;; fork (clone-WITH-FN, SIGCHLD): child entry $child_exec does execve.
    ;; Fork-mode (fn=0) is NOT usable here: non-blink fork_user resume
    ;; re-runs _start (documented limitation) → fork bomb.
    (local.set $ret
      (call $syscall (i32.const 220) (i32.const 1) (i32.const 0) (i32.const 17)
        (i32.const 0) (i32.const 0) (i32.const 0)))
    (if (i32.gt_s (local.get $ret) (i32.const 0))
      (then
        (local.set $st
          (call $syscall (i32.const 260) (local.get $ret) (i32.const 4232)
            (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
        (if (i32.gt_s (local.get $st) (i32.const 0))
          (then
            (i32.store (i32.const 16) (i32.load (i32.const 4232)))
            (i32.store (i32.const 20)
              (i32.shr_s (i32.load (i32.const 4232)) (i32.const 8)))))))

    ;; authority alive
    (i32.store (i32.const 24)
      (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))

    (i32.atomic.store (i32.const 28) (i32.const 1))
    (drop (memory.atomic.notify (i32.const 28) (i32.const 1)))
    (loop $alive
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $alive)))

  (export "_start" (func $init)))
