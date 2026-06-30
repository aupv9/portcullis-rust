---
name: embedded-perf
description: Optimize portcullis for the RUTM11's tight CPU/RAM/flash/binary-size budgets (MIPS 880 MHz dual-core, 256 MB RAM, target <30 MB RSS and <15 MB binary). Use when reducing memory footprint, shrinking the binary, cutting allocations on the hot path, tuning the Tokio runtime, or profiling resource use.
---

# Performance, memory & space budget (RUTM11)

Hard targets (TDD §14, §5): **< 30 MB RSS steady-state, < 15 MB binary**, on 256 MB RAM / MIPS 1004Kc 880 MHz dual-core, 256 MB NAND. The data plane is in the *kernel* (nftables), so the daemon is control/metering only — per-store load is tiny (dozens–hundreds of clients, a few grants/min). Optimize for **small and steady**, not throughput.

## Binary size (release profile)

```toml
[profile.release]
opt-level = "z"        # or "s"; measure both — "z" smaller, "s" sometimes faster+smaller after LTO
lto = true
codegen-units = 1
panic = "abort"        # no unwinding tables; pairs with build-std panic_immediate_abort
strip = true
```

- Cross-build static musl: `cargo build --release --target mipsel-unknown-linux-musl`; consider `-Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort` to drop panic-format machinery (big win on MIPS).
- Audit fat dependencies with **`cargo bloat --release --target mipsel-unknown-linux-musl`** and `cargo tree`. Common offenders: `regex`, multiple TLS stacks, `chrono`/`time` with all features, `clap`. Prefer minimal feature sets.
- **Tokio:** don't enable `features = ["full"]`. Enable only `rt`, `net`, `time`, `macros`, `signal`, `sync` as needed. Consider the **current-thread runtime** (`rt`, not `rt-multi-thread`) or cap worker threads to 2 — there are only 2 cores and the workload is I/O-bound, not CPU-bound.
- tonic/prost, hyper, rustls pull weight — share one TLS stack across gRPC; don't also link OpenSSL.

## Memory / RSS

- **Compact session representation.** MAC = `[u8; 6]` (`MacAddr`), not `String`. Avoid storing/cloning `String`s per session (`session_id`, `tier` → intern or use `Box<str>`/an enum for `tier`). Hundreds of sessions × fat structs adds up.
- **Bounded everything.** Event queues to the control plane, log ring, and the session map must have caps (see `accounting-metering`). Unbounded channels are a slow OOM on a 256 MB box. Use `mpsc::channel(N)` not `unbounded_channel`.
- Prefer borrowing/`&str` over owned copies on the redirect/accounting hot paths; reuse buffers (e.g. a per-task scratch `Vec`/`BytesMut`) instead of allocating per request/tick.
- Don't add a custom allocator (jemalloc/mimalloc) — extra size and questionable benefit on musl/MIPS at this scale; the system allocator is fine.
- Watch async task count and per-task stack/buffer sizes; a handful of long-lived tasks (control, redirect, accounting, garden, expiry) is the design — don't spawn per-client tasks unboundedly.

## CPU / hot path

- Enforcement is O(1) kernel set lookups — keep it there. Never do per-packet work in userspace.
- **Batch nft mutations** into single atomic transactions through the writer actor; fork/exec to `nft` is acceptable *because* churn is tiny — don't "optimize" it into a per-element exec loop.
- Read accounting via **CTNETLINK**, not by spawning `conntrack`/`nft list` every 15 s. Reuse the netlink socket.
- Avoid busy-polling; drive expiry off the kernel set timeout + a single timer, not a tight scan loop.

## Flash / space (NAND)

- **Zero runtime writes to NAND** — all state in tmpfs (`/tmp/portcullis/`). Flash wear bricks routers (TDD §5.4). Logs are a small tmpfs ring; primary observability is metrics + the event stream, not disk logs.
- The `.ipk` itself lands in NOR/NAND once at install — that's fine; it's *runtime* writes that kill flash.

## Measuring

- On-device: RSS via `cat /proc/$(pidof portcullis)/status | grep VmRSS`, `smem`/`top`; binary size with `ls -l` + `size`. Validate under sustained load (§18 item 4 = flash-write audit; use `iostat`/inotify or RutOS flash counters).
- On x86 (proxy): `cargo bloat`, `heaptrack`/`valgrind --tool=massif` for heap profiles, `cargo build --timings`. Remember RSS differs across arch/allocator — confirm the real numbers on hardware before claiming the budget is met.
