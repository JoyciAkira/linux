(module
  ;; Import non-shared memory from host (matches production worker contract)
  ;; Bootstrap provides a compatible non-shared memory for minimal user modules
  (import "env" "memory" (memory 1))
  ;; Import linux.syscall(nr, a0, a1, a2, a3, a4, a5) -> result
  (import "linux" "syscall" (func $syscall (param i32 i32 i32 i32 i32 i32 i32) (result i32)))

  ;; Indirect function table for production worker entrypoint dispatch
  ;; Production worker.ts does: table.get(fn) then calls entry(arg)
  ;; We place _start at index 0 in the table
  (table (export "__indirect_function_table") 1 funcref)
  (elem (i32.const 0) func $_start_impl)

  ;; Internal implementation of _start that makes 3 sequential syscalls
  (func $_start_impl (param $arg i32)
    (local $r0 i32)
    (local $r1 i32)
    (local $r2 i32)

    ;; Call 1: getpid (nr=172) with sentinel a5=0xDEADBEEF
    i32.const 172         ;; nr = getpid
    i32.const 0           ;; a0
    i32.const 0           ;; a1
    i32.const 0           ;; a2
    i32.const 0           ;; a3
    i32.const 0           ;; a4
    i32.const -559038737  ;; a5 = 0xDEADBEEF as signed i32
    call $syscall
    local.set $r0

    ;; Store result[0] at offset 0
    i32.const 0
    local.get $r0
    i32.store

    ;; Call 2: same syscall
    i32.const 172
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const -559038737
    call $syscall
    local.set $r1

    ;; Store result[1] at offset 4
    i32.const 4
    local.get $r1
    i32.store

    ;; Call 3: same syscall
    i32.const 172
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const -559038737
    call $syscall
    local.set $r2

    ;; Store result[2] at offset 8
    i32.const 8
    local.get $r2
    i32.store

    ;; Store call_count=3 at offset 12
    i32.const 12
    i32.const 3
    i32.store
  )

  ;; Also export _start directly for non-table-based invocation
  (export "_start" (func $_start_impl))
 ;; Export pointer to result buffer so witness can read exact syscall return values
 ;; Layout: [result0:i32, result1:i32, result2:i32, call_count:i32] at offset 0
 (global $result_buffer_ptr (export "result_buffer") i32 (i32.const 0))
)