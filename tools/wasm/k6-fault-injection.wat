(module
  (import "env" "memory" (memory 1 32768 shared))
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (table (export "__indirect_function_table") 3 funcref)
  (elem (i32.const 0) $parent $trap_child $storm_child)

  ;; K6R1 fault-injection guest. Word layout (i32):
  ;;   @0  magic "K6FI" (0x4b364649)
  ;;   @4  invalid-syscall(9999) result, expect -38 (-ENOSYS)
  ;;   @8  trap child pid (>0)
  ;;   @12 trap child wait4 raw status (kernel-written, expect 11 = SIGSEGV)
  ;;   @16 post-trap getpid (authority-alive proof)
  ;;   @20 storm children successfully waited (expect 10)
  ;;   @24 storm rounds completed (expect 10)
  ;;   @28 completion word (atomic store 1 + notify + wait)
  ;;   @64 storm wait4 status scratch (last round, expect 1792 = exit 7 << 8)
  ;;
  ;; Clone ABI (arch/wasm fork.c): syscall(220, fn, fn_arg, clone_flags, ...).
  ;; fn = guest table index of the child entry (clone-with-fn: the child task
  ;; binds the parent image and runs that function on its own user worker).
  ;; clone_flags = 17 → no CLONE_* flags, exit_signal = SIGCHLD: a waitable
  ;; fork. A Wasm guest cannot resume mid-function, so fork-mode (fn=0) is
  ;; not usable here — children MUST get their own entry function.

  ;; Child entry 1: immediate genuine Wasm trap. K6R1 contract: the child's
  ;; kernel continuation parked in user.call resumes with KWA_USER_CALL_TRAP
  ;; and runs do_exit(SIGSEGV) — a kernel-owned signal death, observable by
  ;; the parent as wait4 status 11 (WIFSIGNALED, WTERMSIG = SIGSEGV).
  (func $trap_child (param $arg i32)
    unreachable)

  ;; Child entry 2: normal work then clean exit(7). The parent must reap it
  ;; with wait4 status (7 << 8) = 1792 (WIFEXITED, WEXITSTATUS = 7).
  (func $storm_child (param $arg i32) (local $i i32)
    (local.set $i (i32.const 0))
    (loop $w
      (drop (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $w (i32.lt_u (local.get $i) (i32.const 3))))
    (drop
      (call $syscall (i32.const 94) (i32.const 7)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (loop $p
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $p)))

  (func $parent (param $arg i32) (local $ret i32) (local $i i32) (local $w i32)
    (i32.store (i32.const 0) (i32.const 0x4b364649))

    ;; Phase 1: invalid syscall must be rejected with -ENOSYS.
    (i32.store (i32.const 4)
      (call $syscall (i32.const 9999) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))

    ;; Phase 2: clone child running $trap_child (table index 1); it traps.
    (local.set $ret
      (call $syscall (i32.const 220)
        (i32.const 1)    ;; arg0 fn = table index of $trap_child
        (i32.const 0)    ;; arg1 fn_arg
        (i32.const 17)   ;; arg2 clone_flags = SIGCHLD (waitable fork)
        (i32.const 0) (i32.const 0) (i32.const 0)))
    (if (i32.gt_s (local.get $ret) (i32.const 0))
      (then
        (i32.store (i32.const 8) (local.get $ret))
        ;; Reap the trap child; the kernel writes the raw wait status @12.
        (drop
          (call $syscall (i32.const 260) (local.get $ret) (i32.const 12)
            (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))))

    ;; Phase 3: 10 storm rounds of clone($storm_child) + exit(7) + wait4 —
    ;; the authority must still clone/reap normally AFTER containing SIGSEGV.
    (local.set $i (i32.const 0))
    (loop $storm
      (local.set $ret
        (call $syscall (i32.const 220)
          (i32.const 2) (i32.const 0) (i32.const 17)
          (i32.const 0) (i32.const 0) (i32.const 0)))
      (if (i32.gt_s (local.get $ret) (i32.const 0))
        (then
          (local.set $w
            (call $syscall (i32.const 260) (local.get $ret) (i32.const 64)
              (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
          (if (i32.gt_s (local.get $w) (i32.const 0))
            (then
              (i32.store (i32.const 20)
                (i32.add (i32.load (i32.const 20)) (i32.const 1)))))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (i32.store (i32.const 24) (local.get $i))
      (br_if $storm (i32.lt_u (local.get $i) (i32.const 10))))

    ;; Phase 4: authority alive after faults — getpid round-trip.
    (i32.store (i32.const 16)
      (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const -559038737)))
    (i32.atomic.store (i32.const 28) (i32.const 1))
    (drop (memory.atomic.notify (i32.const 28) (i32.const 1)))
    (loop $alive
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $alive)))

  (export "_start" (func $parent)))
