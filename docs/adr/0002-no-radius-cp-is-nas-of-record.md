# ADR-0002: No RADIUS — the control plane is NAS-of-record

- Status: Accepted
- Recorded: 2026-07-08

## Context

Captive-portal stacks traditionally use RADIUS for auth + accounting. RADIUS is
heavyweight to run per-site, and the platform decision was to drop it entirely.

## Decision

`portcullis` never speaks RADIUS. It emits domain `SessionEvent`s (GRANTED,
INTERIM, EXPIRED, REVOKED, QUOTA_EXCEEDED, IDLE_TIMEOUT) over the control stream;
the Go control plane is the **NAS-of-record** and records them as session
accounting in Postgres. Auth decisions (ad-gate / OTP / voucher) happen in the
portal, which then calls `GrantSession`.

## Consequences

- No FreeRADIUS anywhere; one less per-site daemon.
- The engine's accounting job is "report bytes + lifecycle", not "be an AAA server".
- The CP owns the durable record; the engine keeps only RAM state (see
  [0006](0006-no-flash-writes-ram-tmpfs-only.md)).

## Where it lives

`crates/portcullis-session` (event emission), `crates/portcullis-control`
(event fan-out), `proto/enforcement.proto` (`SessionEvent`, `EventKind`).
