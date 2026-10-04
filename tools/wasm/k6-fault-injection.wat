(module
  (import "env" "memory" (memory 1 32768 shared))
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (table (export "__indirect_function_table") 1 funcref)
  (elem (i32.const 0) $parent)

  ;; Single entry: clone returns 0 in child, >0 in parent.
  ;; Child: getpid storm + exit_group(42) + park.
  ;; Parent: invalid syscall + 10× clone/wait + final getpid + signal @28 + park.
  (func $parent (param $arg i32) (local $child i32) (local $rounds i32) (local $i i32)
    ;; Magic marker for witness identification
    (i32.store (i32.const 0) (i32.const 0x4b364649))  ;; "K6FI"

    ;; === Phase 1: Invalid syscall NR 9999 — should return -ENOSYS (-38) ===
    (i32.store (i32.const 4)
      (call $syscall (i32.const 9999) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))

    ;; === Phase 2: Clone+wait stress test (10 rounds) ===
    (local.set $rounds (i32.const 0))
    (loop $stress
      ;; clone(CLONE_VM|CLONE_FS|CLONE_FILES = 0x11, stack=0, ...)
      (local.set $child
        (call $syscall (i32.const 220) (i32.const 17) (i32.const 0)
          (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
      ;; Branch: child (pid==0) does work+exit then parks; parent waits
      (if (i32.eqz (local.get $child))
        (then
          ;; Child path: getpid round-trips
          (local.set $i (i32.const 0))
          (loop $child_work
            (drop (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
              (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $child_work (i32.lt_u (local.get $i) (i32.const 5))))
          ;; exit_group(42)
          (drop (call $syscall (i32.const 231) (i32.const 42) (i32.const 0)
            (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
          ;; Park child forever
          (loop $child_park
            (drop (memory.atomic.wait32 (i32.const 28) (i32.const 0) (i64.const -1)))
            (br $child_park)))
        (else
          ;; Parent path: wait4(child, &status@64, 0, NULL) if clone succeeded
          (if (i32.gt_s (local.get $child) (i32.const 0))
            (then
              (drop (call $syscall (i32.const 260) (local.get $child) (i32.const 64)
                (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))))))
      (local.set $rounds (i32.add (local.get $rounds) (i32.const 1)))
      (br_if $stress (i32.lt_u (local.get $rounds) (i32.const 10))))

    ;; Store completed storm rounds
    (i32.store (i32.const 8) (local.get $rounds))

    ;; === Phase 3: Final getpid to prove authority alive post-stress ===
    (i32.store (i32.const 12)
      (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const -559038737)))

    ;; Signal completion — EXACT K5 PROTOCOL: store 1 @28, notify @28, wait @28 expecting 1
    (i32.atomic.store (i32.const 28) (i32.const 1))
    (drop (memory.atomic.notify (i32.const 28) (i32.const 1)))
    (loop $alive
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $alive)))
  (export "_start" (func $parent)))