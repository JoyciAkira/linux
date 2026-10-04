(module
  (import "env" "memory" (memory 1 32768 shared))
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (table (export "__indirect_function_table") 2 funcref)
  (elem (i32.const 0) $parent $child_entry)
  (data (i32.const 256) "/k5-child\00")
  (data (i32.const 512) "\00\01\00\00\00\00\00\00")

  (func $child_entry (param $arg i32)
    (drop (call $syscall (i32.const 221) (i32.const 256) (i32.const 512)
      (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    ;; Successful execve never returns into this image.
    unreachable)

  (func $parent (param $arg i32) (local $child i32)
    (i32.store (i32.const 0) (i32.const 0x4b355031))
    (i32.store (i32.const 4)
      (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const -559038737)))
    (local.set $child
      (call $syscall (i32.const 220) (i32.const 1) (i32.const 0)
        (i32.const 17) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.store (i32.const 8) (local.get $child))
    (i32.store (i32.const 12)
      (call $syscall (i32.const 260) (local.get $child) (i32.const 64)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.store (i32.const 16) (i32.load (i32.const 64)))
    (i32.store (i32.const 20)
      (call $syscall (i32.const 260) (local.get $child) (i32.const 68)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.store (i32.const 24)
      (call $syscall (i32.const 172) (i32.const 0) (i32.const 0)
        (i32.const 0) (i32.const 0) (i32.const 0) (i32.const -559038737)))
    (i32.atomic.store (i32.const 28) (i32.const 1))
    (drop (memory.atomic.notify (i32.const 28) (i32.const 1)))
    ;; Preserve the living parent at the post-wait checkpoint. The witness
    ;; tears down the entire independent runtime after reading real results.
    (loop $alive
      (drop (memory.atomic.wait32 (i32.const 28) (i32.const 1) (i64.const -1)))
      (br $alive)))
  (export "_start" (func $parent)))
