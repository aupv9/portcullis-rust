# Engine tracing — design & rollout plan

Status: **proposal** (no code yet). Author target: `portcullis-control` + `portcullis-engined`, with matching changes in the Go control plane / edge.

## 1. Problem

The Go control plane (CP) and the edge relay are already wired for distributed
tracing: CP has `otelgin` on its HTTP surface, the edge has `otelgrpc` on the
Attach server, both export OTLP to Grafana Tempo through `common-go`'s
`observability` module (grpc/http exporter, W3C `TraceContext` propagator, batch
processor, flush-on-shutdown).

The **engine is dark**. A request that crosses the router boundary —

```
user connect → CP InstantAuth (span) → CP dispatch → edge relay (span) → engine applies nft/ipset
                                                                          ^^^^^^^^^^^^^^^^^^^^^^^^^
                                                                          no span, no trace_id in logs
```

— shows up in Tempo only as far as the edge, then stops. The engine's own work
(command dispatch, nft transaction, session grant, conntrack reap, wireless
commit-confirm) produces neither Tempo spans nor `trace_id`-tagged logs, so it
cannot be correlated with the trace that caused it.

### 1.1 What exists today (audited)

| Surface | State |
|---|---|
| `tracing` facade (spans/events) | present in every crate; used as a structured-log facade |
| Subscriber | `tracing_subscriber::fmt().with_max_level(RUST_LOG)` → **console logs only** (`engined/src/main.rs:55`). No `EnvFilter` (dropped to save ~290 KiB of regex engine, TDD §14). |
| OpenTelemetry / OTLP | **none** — no `opentelemetry`, `tracing-opentelemetry`, or exporter dep anywhere in the workspace |
| Trace context inbound | **none** — `ControlFrame` has no trace field; gRPC metadata can't carry it (see §2.2) |
| `correlation_id` (uint64, `ControlFrame`/`EngineFrame` field 1) | a **local request↔reply matcher** for one stream — NOT a distributed trace id |
| Metrics | present but orthogonal: hand-rolled Prometheus text on loopback (`engined/src/metrics.rs`) + `GetMetrics` RPC. This is the *metrics* pillar, not traces. |

## 2. Constraints that rule out "just add the OTLP SDK"

### 2.1 Size budget (the hard one)

RUTM11 = MIPS 1004Kc, 256 MB RAM. Budget: **binary < 15 MB, RSS < 30 MB** (§5,
TDD §14). The release profile is already squeezed hard: `opt-level=z`, `lto=true`,
`codegen-units=1`, `strip=true`, `panic=abort`, `current_thread` runtime, no
`env-filter`, no `hyper` "full".

The full OTLP export stack — `opentelemetry` + `opentelemetry_sdk` +
`opentelemetry-otlp` + a protobuf/tonic exporter + the batch span processor —
adds roughly **1–3 MB of `.text`**, heap churn from batching, and at least one
extra export task/runtime. That directly fights the budget the rest of the engine
was contorted to hit. **Rejected for the device build.**

### 2.2 Topology: dial-out over one long-lived bidi stream

The engine sits behind CGNAT and **dials outbound** over a single long-lived
mTLS gRPC bidirectional stream (`Attach`, see `cgnat-bidi-control-channel.md`).
Consequences:

- **No inbound, no assumed egress** to an arbitrary collector host. The engine
  cannot be trusted to reach Tempo directly on the device network.
- **gRPC metadata is per-RPC, set once at stream open.** `otelgrpc`'s usual trick
  (inject `traceparent` into request headers) works per-*call*, but here there is
  one call for the lifetime of the connection carrying thousands of commands. So
  trace context **must ride as a field inside `ControlFrame`/`EngineFrame`**,
  exactly like the WinX outbox carries `traceparent` in a DB column across its
  async boundary.

### 2.3 Doctrine

Thin engine, CP-owned, fail-closed (invariant G2). A heavy async exporter with
its own buffering and network egress on-device is against the grain. The engine
should *emit* trace data the same way it emits everything else — up the control
stream — and let the (already-instrumented, egress-capable) Go side do the
export.

## 3. Plan — three tiers

Do them in order. P0 is the high-value, near-zero-cost step; P1 is the "real
spans in Tempo" follow-up that stays device-safe; P2 is a dev-only convenience.

---

## P0 — Trace-context propagation + log correlation

**Goal:** every engine log line produced while handling a CP command carries the
`trace_id` of the trace that caused it, so Grafana can jump trace → logs (Loki).
No spans in Tempo yet, but the black box is labelled. Symmetric with the outbox
`trace_ctx` design already shipped in the CP.

### P0.1 Proto (wire contract — edit BOTH copies)

`proto/enforcement.proto` (Rust) **and** `domain/server/proto/enforcement.proto`
(Go) — same field tag, then regenerate (Rust: `buf generate`; Go: its own
codegen). Adding a scalar field is wire-compatible in both directions (old peer
ignores the unknown field), so CP-first or engine-first rollout is safe.

```proto
message ControlFrame {
  uint64 correlation_id = 1;
  // W3C `traceparent` of the CP request that issued this command; "" when the CP
  // has OTEL off or the trace is unsampled. Top-level (NOT in the oneof) so it
  // accompanies every command variant.
  string trace_ctx = 18;               // next free tag (oneof occupies 2..17)
  oneof msg { /* … unchanged … */ }
}

message EngineFrame {
  uint64 correlation_id = 1;
  string trace_ctx = 15;               // echo back on acks/replies (oneof occupies 2..14)
  oneof msg { /* … unchanged … */ }
}
```

Tags 13/14 in `ControlFrame` remain RESERVED (provision deprecation) — 18 avoids
them. Keep the two proto files and tags in lockstep (CLAUDE.md rule).

### P0.2 CP side (Go) — inject at the single choke point

`server/internal/edge/dispatch/dispatch.go`:

- `roundtrip(ctx, routerID, cf, timeout)` (`:228`) is the one function every
  unary-style command funnels through (Grant `:286`, Revoke `:317`, GetSession,
  Health, GetEngineInfo, GetMetrics, SetEnforcement, …). Inject there:
  `cf.TraceCtx = traceparentFrom(ctx)` using the same
  `otel.GetTextMapPropagator().Inject` helper the outbox repo already uses.
- Wrap the round-trip in a child span `engine.<cmd>` (name from
  `controlFrameKind`, `:277`) so the engine leg shows as a span on the CP side of
  the trace even before P1. Attach `router_id`, `correlation_id` as attributes.
- The edge relays the `ControlFrame` **verbatim** — `trace_ctx` rides along in the
  bytes, so **no edge code change** is needed for P0.

### P0.3 Engine side (Rust) — parse + attach to the span, echo back

`portcullis-control/src/channel.rs`, `handle_control_frame` (`:297`):

- Add a tiny hand-rolled parser (NO `opentelemetry` crate). `traceparent` is a
  fixed ASCII shape `00-<32 hex trace>-<16 hex span>-<2 hex flags>` (55 bytes):
  validate length/version/hex, slice out `trace_id`, `span_id`, `sampled` flag.
  ~30 lines, zero deps, zero heap beyond the input string.
- Open the command span with the ids as fields so *every* downstream log
  inherits them:
  ```rust
  let span = tracing::info_span!("engine.cmd",
      cmd = kind, cid = ctrl.correlation_id,
      trace_id = %tid, parent_span_id = %sid);
  let _e = span.enter();  // dispatch match runs inside
  ```
- Echo `trace_ctx` back on the answering `EngineFrame` (via the `frame()` helper
  at `:508`) so the CP can confirm the engine saw the same trace.
- Empty/absent `trace_ctx` → no fields, behaves exactly as today.

### P0.4 Result / cost

- Grafana: from a Tempo trace, "Logs for this span" surfaces the engine's log
  lines for that exact command (needs the Loki log pipeline to parse `trace_id=` —
  a one-line label extraction).
- Binary cost: a string parse + a few span fields. **Negligible.** No new deps.
- Tests (host): traceparent parse (valid/short/non-hex/version!=00); dispatch
  echoes `trace_ctx`; empty context is a no-op. No netns needed.

---

## P1 — Span relay through the edge (real engine spans in Tempo)

**Goal:** the engine's own spans appear in Tempo as children of the CP/edge span,
in the same trace — without any OTLP dep, egress, or batch runtime on the device.
The engine ships span records up the existing stream; the **edge** (already OTLP-
wired, egress-capable, terminates the Attach stream) does the export.

### P1.1 Proto — a new upward frame variant

```proto
message EngineFrame {
  // …
  oneof msg { /* … */ TraceSpan trace_span = 16; }  // 15 is trace_ctx (P0)
}

message TraceSpan {
  bytes  trace_id       = 1;  // 16 bytes, from the propagated traceparent
  bytes  span_id        = 2;  // 8 bytes, engine-generated (xorshift, see P1.3)
  bytes  parent_span_id = 3;  // 8 bytes; the CP span, or an enclosing engine span
  string name           = 4;  // e.g. "engine.grant", "nft.apply", "conntrack.reap"
  int64  start_unix_ns  = 5;  // SystemTime at span open (engine already uses wall-clock)
  int64  end_unix_ns    = 6;
  int32  status         = 7;  // 0=unset 1=ok 2=error
  map<string,string> attrs = 8;  // bounded: mac, session_id, nft_txn, result …
}
```

Sent unsolicited (`correlation_id = 0`), like `wireless_status`/`liveness`/
`device_report` already are.

### P1.2 Engine — a lightweight capture Layer + one more fan-out arm

- Add a custom `tracing_subscriber::Layer` (registered next to `fmt` in
  `engined/src/main.rs`) that on **span close** builds a `TraceSpan` and pushes it
  onto an `mpsc::Sender<TraceSpan>`. This is a compact hand-written Layer — NOT
  `tracing-opentelemetry` (which drags in the SDK).
- **Sampling gate (free head-based sampling):** the Layer only records a span if
  its root carried a *sampled* remote parent — i.e. P0 populated `trace_id` and the
  traceparent `sampled` flag was `01`. Requests with no context or unsampled cost
  **zero** (no record built, no frame sent). This keeps the thin control channel
  quiet unless the CP is actually collecting, and makes sampling consistent across
  the whole chain (the CP decides once).
- Thread a new `mpsc::Receiver<TraceSpan>` into `run_fanout` and add one
  `tokio::select!` arm (`channel.rs:210`) that wraps each `TraceSpan` with
  `frame(0, EngineFrame::trace_span)` and sends it out — mirrors the existing
  `wireless_status`/`liveness`/`device_reports` arms exactly.
- Span-id generation: reuse the existing `xorshift` PRNG (`channel.rs:545`),
  seeded per-process; span timestamps from `SystemTime` (`UNIX_EPOCH`) — both
  already used in the engine, no new dep and no 64-bit atomics (MIPS constraint).
- **Backpressure:** the `mpsc` is bounded and `try_send`; on full, drop the span
  and bump a counter (spans are best-effort diagnostics — never block or grow
  unbounded, per fail-closed doctrine). Cap spans-per-command to a small N.

### P1.3 Edge — reconstruct + export

`domain/edge` (holds the Attach stream; has `common-go` OTLP). On receiving a
`TraceSpan`:

- **Approach B (recommended, public API):** `tracer.Start(parentCtx, name,
  trace.WithTimestamp(start), …)` then `span.End(trace.WithTimestamp(end))`, where
  `parentCtx` carries the propagated `trace_id`+`parent_span_id` via
  `trace.ContextWithRemoteSpanContext`. The edge keeps a short-lived LRU mapping
  `engine_span_id → edge_generated_span_id` (per trace) so that a later engine
  span whose `parent_span_id` points at an earlier engine span resolves to the
  right parent. Span ids are edge-generated (the SDK owns them) but the **tree
  shape and trace membership are preserved** — which is all Tempo needs.
- Approach A (preserve engine ids exactly) would require emitting OTLP
  `trace.v1.Span` protobuf directly, bypassing the SDK's id generation. More
  faithful, more code, second OTLP client. Documented as the fallback if exact-id
  preservation is ever required (e.g. correlating engine logs' `span_id` to Tempo);
  default to B.

### P1.4 Cost / risk

- Engine: one Layer + serialize a small struct into an existing frame. **No**
  `opentelemetry`/`otlp`/exporter dep, **no** egress, **no** export runtime.
  Binary cost is the Layer code + the `TraceSpan` prost message (small).
- Bandwidth: gated by sampling; cap spans/command; drop-on-full. The control
  channel is control+accounting only and low-volume — spans for sampled traces are
  a small addition, but the cap + gate keep it bounded.
- Main complexity is edge-side id/parent bookkeeping (Approach B) — hence P1 is a
  deliberate follow-up, not part of P0.

---

## P2 — Direct OTLP export (dev-only, feature-gated, NEVER in the .ipk)

For host/dev builds that *do* have egress to a collector, gate a real exporter
behind a Cargo feature so full-fidelity tracing is available locally without
touching the device release:

```toml
[features]
otel-export = ["dep:tracing-opentelemetry", "dep:opentelemetry-otlp", "dep:opentelemetry_sdk"]
```

- Off by default. The `mipsel-*-musl` release build and the `.ipk` packaging
  never enable it. CI's device-size check should assert the feature is off.
- When on (dev), register a `tracing-opentelemetry` layer alongside `fmt` and
  export OTLP to a local collector — useful for netns integration tests and
  on-desk debugging. Same `trace_ctx` propagation from P0 makes these spans nest
  under the CP trace automatically.

---

## 4. Recommendation & sequencing

1. **P0 now** — best value/cost, symmetric with the shipped outbox design, no size
   risk, wire-compatible rollout. Delivers trace→logs correlation for the engine.
2. **P1 next** — when real engine spans in Tempo are wanted. Device-safe (export
   stays on the Go edge). Main work is edge-side span reconstruction.
3. **P2 opportunistic** — dev ergonomics only; keep it out of the device build.

## 5. Cross-cutting checklist

- [ ] Proto edited in **both** `core/portcullis-rust/proto/` and
      `domain/server/proto/`, tags identical; `buf generate` + Go regen; `buf lint`.
- [ ] Wire-compat verified both directions (old CP ↔ new engine and vice-versa).
- [ ] Loki pipeline extracts `trace_id=` label so trace→logs works (P0).
- [ ] Sampling: engine relays (P1) only when the propagated flag is sampled; CP is
      the single sampling authority.
- [ ] Size regression check after each phase (`cargo bloat --release` / stripped
      binary size vs the <15 MB gate); confirm P2 feature is off in the device
      profile.
- [ ] No `unwrap`/panic on the parse path (fail-closed: bad `trace_ctx` → treat as
      absent, never abort a command).
```

