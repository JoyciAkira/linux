#!/usr/bin/env python3
"""Safety regression guard for the historical Z1 futex repair candidate.

This is a source-level invariant check, not a kernel compile, guest execution,
concurrency stress run, or T2 certification.
"""
from pathlib import Path

s = Path("arch/wasm/kernel/syscall.c").read_text()
p = s.index("/* Z1-F11-C5 T2 candidate")
s = s[p:]

requirements = {
    "single queue lock": "static DEFINE_SPINLOCK(z1_futex_lock)",
    "explicit mm ownership": "struct mm_struct *mm;",
    "explicit guest address": "u32 __user *uaddr;",
    "lock covers wait enrollment": "spin_lock_irqsave(&z1_futex_lock, flags);",
    "fault disabled during locked recheck": "pagefault_disable();",
    "validated user address": "access_ok(uaddr, sizeof(*uaddr))",
    "value mismatch Linux semantics": "return -EAGAIN;",
    "kernel scheduler park": "schedule();",
    "waiter removes its node": "if (*pp == &q)",
    "kernel wake queue ownership": "wake_q_add(&wake_q, q->task);",
    "grouped wake outside lock": "wake_up_q(&wake_q);",
    "full mm/address equality": "q->mm == mm && q->uaddr == uaddr",
    "six-argument Linux futex entry": "SYSCALL_DEFINE6(z1_futex",
    "unsupported timeout is rejected": "if (timeout || uaddr2 || val3)",
    "unsupported operation fail closed": "return -ENOSYS;",
}
for title, fragment in requirements.items():
    if fragment not in s:
        raise AssertionError(f"{title}: expected {fragment!r}")
if "kfree(q)" in s:
    raise AssertionError("waiter stack node must not be freed by waker")
if s.count("raw_copy_from_user(&cur, uaddr, sizeof(cur))") != 2:
    raise AssertionError("value must be read once before lock and again under lock")
if s.index("spin_unlock_irqrestore(&z1_futex_lock, flags);", s.index("wake_q_add(")) > s.index("wake_up_q(&wake_q)"):
    raise AssertionError("wakeup must happen after releasing bucket lock")
if s.index("if (q.queued)") < s.index("schedule();"):
    raise AssertionError("waiter-owned node must be cleaned after wake/interrupt")
# Explicit-mm wake and ctid exit have one Z1 queue authority.
fork = Path("kernel/fork.c").read_text()
header = Path("arch/wasm/include/asm/z1_futex.h").read_text()
if "unsigned int z1_futex_wake_mm(struct mm_struct *mm" not in s:
    raise AssertionError("missing shared Z1 wake implementation")
if "return z1_futex_wake_mm(mm, uaddr, val);" not in s:
    raise AssertionError("syscall FUTEX_WAKE bypasses shared Z1 wake authority")
if "q->mm == mm && q->uaddr == uaddr" not in s:
    raise AssertionError("explicit-mm identity not enforced")
if "#ifdef CONFIG_WASM\n#include <asm/z1_futex.h>\n#endif" not in fork:
    raise AssertionError("arch-gated mm_release bridge missing")
if "z1_futex_wake_mm(mm," not in fork:
    raise AssertionError("clear_child_tid does not wake Z1")
if fork.index("z1_futex_wake_mm(mm,") < fork.index("do_futex(tsk->clear_child_tid, FUTEX_WAKE"):
    raise AssertionError("native futex wake must be retained before Z1 bridge")
if "z1_futex_wake_mm(struct mm_struct *mm" not in header:
    raise AssertionError("Z1 API declaration missing")
print("Z1_FUTEX_SOURCE_LIFETIME_CONTRACT PASS (source only; T2 NOT CERTIFIED)")
