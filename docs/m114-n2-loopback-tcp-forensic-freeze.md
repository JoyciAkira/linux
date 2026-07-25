# NODE_LOOPBACK_TCP_FORENSICALLY_FROZEN

**Verdict:** `NODE_LOOPBACK_TCP_FORENSICALLY_FROZEN`
**Date:** 2026-07-25
**Campaign phase:** C (forensic freeze of N2 loopback TCP)

---

## 1. Problema iniziale

Node.js v20.18.0 x86-64 nel guest Blink/Linux WASM non poteva completare
TCP loopback:

- `connect(127.0.0.1:porta_chiusa)` → `ENETUNREACH`
- roundtrip server/client su `127.0.0.1` → `TIMEOUT` / `RESULT_ABSENT`

## 2. Evidence ENETUNREACH (OBSERVED)

Strace runtime nel guest:

```
socket(AF_INET, SOCK_STREAM) -> 18            # OK
connect(18, 127.0.0.1:19999) -> -ENETUNREACH  # routing fallisce
```

`ENETUNREACH` (non `ECONNREFUSED`) = nessuna rotta per `127.0.0.0/8`.

Diagnostica aggiuntiva:

```
ifconfig lo 127.0.0.1 up
  → ioctl(fd, SIOCSIFADDR=0x8916)
  → blink/ioctl.c:406 "missing ioctl 0x8916" → EINVAL
  → lo resta DOWN (flags=0x8, solo IFF_LOOPBACK, no IFF_UP)
```

`/proc/net/route` vuoto. Nessuna interfaccia con IP assegnato.

## 3. Discrimination test

Ipotesi alternative escluse con evidenza:

| Ipotesi | Esclusa da |
|---------|-----------|
| Busybox senza applet ifconfig | busybox-x86 iniettato, ifconfig parte ma EINVAL su ioctl |
| Blink socket shim rifiuta AF_INET | `socket(AF_INET)` → fd 18 OK, il fallimento è in routing |
| libuv perde EINPROGRESS | connect ritorna ENETUNREACH immediato, no EINPROGRESS |
| /proc non montato | montato manualmente, route table comunque vuota |

Root cause provata con printk diagnostico (rimossi poi):

```
ZNLO: loopback_net_init done, dev=0405ec20, flags=0x8   # lo creato, DOWN
ZNLO: bringing lo UP, flags=0x8                          # initcall eseguito
ZNLO: dev_open rc=0, flags now=0x9                       # UP dopo fix
refused: ECONNREFUSED                                     # semantica corretta
```

## 4. Root cause (OBSERVED)

Due fatti convergenti:

1. **Blink manca gli ioctl handler `SIOCSIFADDR` (0x8916) e
   `SIOCSIFFLAGS` (0x8914)** in `blink/blink/ioctl.c`. Userspace non può
   configurare `lo` → `lo` resta `DOWN` dopo il boot.

2. **Il kernel WASM non esegue `late_initcall` (livello 7)** per la
   funzione di auto-up. Solo `device_initcall` (livello 6) viene eseguito.

Fix applicato (FIX B, kernel-side): un `device_initcall` porta `lo` UP;
`dev_open` attiva `NETDEV_UP` e `devinet.c` assegna automaticamente
`127.0.0.1/8` (chain built-in, non tocca Blink).

## 5. late_initcall vs device_initcall (OBSERVED)

| Initcall level | Eseguito? | Evidenza |
|---------------|-----------|----------|
| `late_initcall` (7) | **NO** | printk non appare, `lo` resta DOWN |
| `device_initcall` (6) | **SÌ** | printk appare, `dev_open rc=0`, `ECONNREFUSED` |

Il kernel WASM itera i livelli initcall 0–6 ma il livello 7 non raggiunge
la funzione registrata (causa esatta nel layout sezioni WASM non isolata;
sintomo provato runtime).

## 6. Diff finale

`drivers/net/loopback.c` (+17 righe):

```c
/* Auto-up lo: dev_open fires NETDEV_UP, which makes devinet.c
 * auto-assign 127.0.0.1/8. Needed because blink WASM lacks SIOCSIFADDR.
 */
static int __init loopback_auto_up(void)
{
	struct net_device *lo = init_net.loopback_dev;

	if (!lo)
		return 0;

	rtnl_lock();
	dev_open(lo, NULL);
	rtnl_unlock();
	return 0;
}
device_initcall(loopback_auto_up);
```

`arch/wasm/include/asm/process_events.h` (+4 righe, build fix —
dichiarazioni per funzioni `zn_*` già definite in
`arch/wasm/kernel/process_events.c`, necessarie per compilare
`kernel/sched/core.c` e `arch/wasm/kernel/binfmt_wasm.c` che le
chiamano. Nessun cambiamento di comportamento.):

```c
void zn_init_run_identity(void);
u64 zn_get_next_event_seq(void);
void zn_get_run_id(u64 *hi, u64 *lo);
```

Un solo `if (!lo)`, una sola `dev_open`, un solo `rtnl_lock`/`rtnl_unlock`,
nessun `printk` diagnostico, nessuna modifica non correlata.

## 7. Build environment

```
container:  ubuntu:24.04 linux/arm64
clang:      Ubuntu clang version 19.1.1 (1ubuntu1~24.04.2)
linker:     Ubuntu LLD 19.1.1
wabt:       wasm2wat per arch/wasm/sections.json
target:     ARCH=wasm LLVM_PREFIX=/usr/lib/llvm-19/bin/ CC=clang-19
```

## 8. Artifact SHA-256 (congelati)

```
vmlinux.wasm (ricertificato):  b8a6d1a14d72fae95c14a5f99dce43d18a8f6b9478fa8cf12f1cde50466f905f
rootfs-d1f4.ext2:              368f144f8fc5f6f7352e80290fe3dbaedb57898181628415dae8ee50f62d1337
/bin/blink (nella rootfs):     a10c46584a41eb44bde89eb40d22c8c8de6a8dc00fb5ebf5f4ef477d4239ad8c
net-ladder-n2-tcp.mjs:         cacf57735501e0bf7311c749de7aa615011c538935ec69c0f0781805e33b200a
node-gate-net-probe.html:      ee045ca6729556186f912ac5bdd183302323e5ff98deb3ec536ebe56e74cb13c
```

Nota: il kernel SHA precedentemente atteso `d6607ee2…` usava un
`devinet.o` stale (compilato Jul 6). Il rebuild ha ricompilato
`devinet.o` dal source current dopo l'add/remove di una patch
sperimentale (`eth0_auto_up`, non in critical path). Comportamento
funzionale per loopback identico; ricertificato con C3 (6/6).

## 9. Risultati 6/6 (C3, kernel b8a6d1a1)

```
── tcp-refused-1 ──  ✅ TCP_REFUSED:ECONNREFUSED  exit=0 crash=0 wall=121377ms
── tcp-refused-2 ──  ✅ TCP_REFUSED:ECONNREFUSED  exit=0 crash=0 wall=98826ms
── tcp-refused-3 ──  ✅ TCP_REFUSED:ECONNREFUSED  exit=0 crash=0 wall=92838ms
── tcp-roundtrip-1 ── ✅ TCP_PONG:PONG            exit=0 crash=0 wall=98936ms
── tcp-roundtrip-2 ── ✅ TCP_PONG:PONG            exit=0 crash=0 wall=105046ms
── tcp-roundtrip-3 ── ✅ TCP_PONG:PONG            exit=0 crash=0 wall=98921ms
 tcp-refused:   3/3
 tcp-roundtrip: 3/3
 TOTAL:         6/6
```

Guest exit code 0 in 6/6. Crash 0. Timeout 0. Cleanup osservato.

## 10. Rollback

```
vmlinux.wasm.bak-pre-loopback         (kernel pre-fix, ENETUNREACH)
vmlinux.wasm.bak-pre-process-lifecycle (kernel N2 pulito, processo-lifecycle base)
rootfs-d1f4.ext2.bak-pre-process-lifecycle
blink-fixed.wasm.bak-pre-process-lifecycle
```

Rollback verificato: `cp vmlinux.wasm.bak-pre-loopback vmlinux.wasm`
ripristina il kernel originale (reproduce `ENETUNREACH`).

## 11. Limitazioni

- Certifica **solo** TCP loopback (`127.0.0.1`) guest-interno.
- **Non** certifica: TCP remoto, virtio-net verso host, DNS, TLS, HTTP.
- `lo` viene portato UP dal kernel (device_initcall); eth0/virtio-net
  resta non configurato (richiede fixture esterna, vedi NBR-3 design).
- Blink ioctl `SIOCSIFADDR`/`SIOCSIFFLAGS` ancora mancanti (FIX A in
  quarantena — SIGSEGV al boot); il fix kernel bypassa la necessità
  userspace di ifconfig.
- `late_initcall` (livello 7) non eseguito in questo kernel WASM;
  causa esatta non isolata (sintomo provato).
- Boot ~80–120s per gate; non ottimizzato.

## 12. Claim consentiti

```
NODE_LOOPBACK_TCP_FORENSICALLY_FROZEN
Node TCP loopback verified inside the Blink/Linux WASM guest.
```

## 13. Claim VIETATI (non ancora)

```
ZERONODE_FULL_NODE_RUNTIME_CERTIFIED
networking fully certified
remote TCP / DNS / TLS / HTTP verified
npm functional
child_process verified
```
