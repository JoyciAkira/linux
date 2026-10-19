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
print("Z1_FUTEX_SOURCE_LIFETIME_CONTRACT PASS (source only; T2 NOT CERTIFIED)")
