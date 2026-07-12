import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SYSCALL_TABLE,
  SYSCALL_MAP,
  buildSyscallMap,
  decodeSyscall,
  isKnownSyscall,
} from "../dist/d1-syscall-decoder.js";

test("all numeric syscall keys are unique", () => {
  const seen = new Set();
  for (const [nr] of SYSCALL_TABLE) {
    assert.equal(seen.has(nr), false, `duplicate syscall number 0x${nr.toString(16)}`);
    seen.add(nr);
  }
  assert.equal(SYSCALL_MAP.size, SYSCALL_TABLE.length);
});

test("buildSyscallMap throws on duplicate numeric keys", () => {
  assert.throws(
    () => buildSyscallMap([[0xe8, "epoll_wait"], [0xe8, "clock_nanosleep"]]),
    /duplicate syscall number 0xe8/,
  );
});

test("clock_nanosleep decodes correctly (0xe6 / 230)", () => {
  assert.equal(decodeSyscall(0xe6), "clock_nanosleep");
  assert.equal(decodeSyscall(230), "clock_nanosleep");
});

test("epoll_wait decodes correctly (0xe8 / 232)", () => {
  assert.equal(decodeSyscall(0xe8), "epoll_wait");
  assert.equal(decodeSyscall(232), "epoll_wait");
});

test("clock_nanosleep and epoll_wait are distinct numbers", () => {
  assert.notEqual(0xe6, 0xe8);
  assert.notEqual(decodeSyscall(0xe6), decodeSyscall(0xe8));
});

test("corrected entries match authoritative x86-64 numbering", () => {
  assert.equal(decodeSyscall(0x11c), "eventfd");
  assert.equal(decodeSyscall(0x122), "eventfd2");
  assert.equal(decodeSyscall(0x10), "ioctl");
});

test("unknown syscall numbers remain typed as unknown", () => {
  assert.equal(isKnownSyscall(0x7fffffff), false);
  assert.equal(decodeSyscall(0x7fffffff), "syscall_2147483647");
  assert.equal(isKnownSyscall(0xe8), true);
});
