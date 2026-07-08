# ADR-0009: MAC is the session key, signed by the redirect responder

- Status: Accepted (CLAUDE.md invariants #7, #8)
- Recorded: 2026-07-08

## Context

Traffic breaks out locally, so the router sees the client's **MAC** at L2 — a
stable, local identity. IP is NAT'd/DHCP-churned and not a safe key. The portal
(off-router) needs to tell the CP *which* client cleared the gate, but it can't be
trusted to assert a MAC unaided (a client could claim another's MAC).

## Decision

The MAC is the session key throughout (nft `auth` set is `ether_addr`). The `:8080`
redirect responder resolves the source IP → MAC (neigh table) and emits a 302 whose
query carries `sig = HMAC-SHA256(key, "<mac>|<store_id>|<ts>")`. The portal/CP trust
`mac`/`store` **only because the signature validates** (constant-time verify). The
per-store key never reaches the client.

## Consequences

- A client cannot forge another's MAC into a grant.
- The responder is the primary unauthenticated attack surface → strict bounded
  parsing, no client-controlled data in privileged paths, per-IP rate limit, and
  fuzzing the parser (cf. CVE-2023-38314). Nothing but the kernel-supplied source
  IP feeds the decision.

## Where it lives

`crates/portcullis-redirect/src/{lib.rs,sign.rs,location.rs,resolver.rs,ratelimit.rs}`;
session keys on `MacAddr` throughout.
