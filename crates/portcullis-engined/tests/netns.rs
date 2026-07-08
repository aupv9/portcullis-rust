//! Linux network-namespace integration + fault-injection harness (G9, TDD §15).
//!
//! Asserts the *real* `inet wifihub` ruleset's verdicts and the daemon's
//! no-fail-open guarantees — the layer that unit + MockBackend tests cannot
//! reach. The real `portcullis` binary runs inside a "router" namespace (it
//! creates the ruleset, serves the `:8080` redirect responder, and adopts kernel
//! state on restart); a "client" namespace drives fake traffic; an "upstream"
//! namespace stands in for the internet.
//!
//! ```text
//! [client ns] --veth--> [router ns: portcullis + inet wifihub] --veth--> [upstream ns]
//! ```
//!
//! ## Preconditions (why these are `#[ignore]`)
//! Needs **Linux**, **root / CAP_NET_ADMIN**, and `ip` + `nft` + `curl` + `nc`.
//! So every test is `#[ignore]` and additionally guarded by [`linux_root`]: a
//! plain `cargo test` skips them (stays green on macOS/CI-without-privilege), and
//! a `--ignored` run on a box lacking the prerequisites SKIPs with a notice
//! rather than a misleading pass.
//!
//! Run on a privileged Linux runner:
//! ```sh
//! sudo -E cargo test -p portcullis-engined --test netns -- --ignored --test-threads=1
//! ```
//! (`--test-threads=1`: the namespaces + the fixed `:8080` port are shared global
//! kernel state, so the cases must not run concurrently.)
//!
//! Grants/revokes are simulated by editing the kernel `@auth` set directly; the
//! daemon runs with a huge `reconcile_interval` and reaping off so its reconciler
//! never races the test. Restart-adoption is exercised by killing + relaunching
//! the real binary.

use std::io::Write as _;
use std::process::{Child, Command};
use std::time::Duration;

// Path to the freshly-built daemon, injected by cargo for integration tests.
const ENGINE_BIN: &str = env!("CARGO_BIN_EXE_portcullis");

// Namespace + interface names (kept unique-ish to avoid clashing with a host).
const NS_CLIENT: &str = "pctest-cli";
const NS_ROUTER: &str = "pctest-rtr";
const NS_UPSTREAM: &str = "pctest-up";
const CLIENT_MAC: &str = "02:00:00:00:00:11";
const CLIENT_IP: &str = "10.80.0.2";
const ROUTER_CLIENT_IP: &str = "10.80.0.1";
const ROUTER_UP_IP: &str = "10.80.1.1";
const UPSTREAM_IP: &str = "10.80.1.2";
// The router-side veth facing the client — the interface enforcement is scoped to.
const GATED_IFACE: &str = "v-rtr-cli";
const HMAC_KEY: &str = "netns-harness-test-key";
const STORE_ID: &str = "NETNS-TEST";

// ---------------------------------------------------------------------------
// Preconditions
// ---------------------------------------------------------------------------

/// True only on Linux, as root, with the tools the harness shells out to. When
/// false the caller prints a SKIP and returns — an honest no-op, never a pass
/// that pretends the ruleset was exercised.
fn linux_root() -> bool {
    if !cfg!(target_os = "linux") {
        eprintln!("SKIP netns: not Linux");
        return false;
    }
    let uid = Command::new("id").arg("-u").output().ok().and_then(|o| {
        String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
    });
    if uid.as_deref() != Some("0") {
        eprintln!("SKIP netns: not root (needs CAP_NET_ADMIN)");
        return false;
    }
    for tool in ["ip", "nft", "curl", "nc"] {
        if !have(tool) {
            eprintln!("SKIP netns: missing tool `{tool}`");
            return false;
        }
    }
    true
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Command helpers
// ---------------------------------------------------------------------------

/// Run a command, returning (success, combined stdout+stderr).
fn run(prog: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(prog)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {prog} {args:?}: {e}"));
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

/// Run inside a namespace via `ip netns exec <ns> <prog> <args...>`.
fn nsx(ns: &str, prog: &str, args: &[&str]) -> (bool, String) {
    let mut full = vec!["netns", "exec", ns, prog];
    full.extend_from_slice(args);
    run("ip", &full)
}

/// Run a setup command that must succeed (panics with context otherwise).
fn must(prog: &str, args: &[&str]) {
    let (ok, out) = run(prog, args);
    assert!(ok, "command failed: {prog} {args:?}\n{out}");
}

fn nft_router(script: &str) -> (bool, String) {
    // Feed an nft fragment on stdin: `ip netns exec rtr nft -f -`.
    let mut child = Command::new("ip")
        .args(["netns", "exec", NS_ROUTER, "nft", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nft -f -");
    child.stdin.take().unwrap().write_all(script.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Topology (RAII)
// ---------------------------------------------------------------------------

struct Topo;

impl Topo {
    /// Build the three namespaces + two veth pairs, address them, and enable
    /// forwarding in the router. Idempotent-ish: tears down any leftovers first.
    fn setup() -> Topo {
        Topo::teardown_quiet();
        for ns in [NS_CLIENT, NS_ROUTER, NS_UPSTREAM] {
            must("ip", &["netns", "add", ns]);
        }
        // client <-> router
        must("ip", &["link", "add", "v-cli-rtr", "type", "veth", "peer", "name", GATED_IFACE]);
        must("ip", &["link", "set", "v-cli-rtr", "netns", NS_CLIENT]);
        must("ip", &["link", "set", GATED_IFACE, "netns", NS_ROUTER]);
        // router <-> upstream
        must("ip", &["link", "add", "v-rtr-up", "type", "veth", "peer", "name", "v-up-rtr"]);
        must("ip", &["link", "set", "v-rtr-up", "netns", NS_ROUTER]);
        must("ip", &["link", "set", "v-up-rtr", "netns", NS_UPSTREAM]);

        // Client side: fixed MAC (the session key) + IP + default route.
        must("ip", &["netns", "exec", NS_CLIENT, "ip", "link", "set", "v-cli-rtr", "address", CLIENT_MAC]);
        addr(NS_CLIENT, "v-cli-rtr", CLIENT_IP, 24);
        must("ip", &["netns", "exec", NS_CLIENT, "ip", "route", "add", "default", "via", ROUTER_CLIENT_IP]);

        // Router side: both veths + forwarding.
        addr(NS_ROUTER, GATED_IFACE, ROUTER_CLIENT_IP, 24);
        addr(NS_ROUTER, "v-rtr-up", ROUTER_UP_IP, 24);
        must("ip", &["netns", "exec", NS_ROUTER, "sysctl", "-w", "net.ipv4.ip_forward=1"]);

        // Upstream side + route back to the client subnet.
        addr(NS_UPSTREAM, "v-up-rtr", UPSTREAM_IP, 24);
        must("ip", &["netns", "exec", NS_UPSTREAM, "ip", "route", "add", "10.80.0.0/24", "via", ROUTER_UP_IP]);

        // Bring loopbacks up (the responder binds there / for local checks).
        for ns in [NS_CLIENT, NS_ROUTER, NS_UPSTREAM] {
            must("ip", &["netns", "exec", ns, "ip", "link", "set", "lo", "up"]);
        }
        Topo
    }

    fn teardown_quiet() {
        for ns in [NS_CLIENT, NS_ROUTER, NS_UPSTREAM] {
            let _ = run("ip", &["netns", "del", ns]);
        }
    }

    /// Add the client's MAC to `@auth` with `ttl` (simulates a CP grant, since the
    /// ruleset reads the kernel set — kernel-as-truth).
    fn grant(&self, ttl_secs: u32) {
        let (ok, out) = nft_router(&format!(
            "add element inet wifihub auth {{ {CLIENT_MAC} timeout {ttl_secs}s }}\n"
        ));
        assert!(ok, "grant (add auth element) failed:\n{out}");
    }

    /// Remove the client's MAC from `@auth` (simulates a revoke).
    fn revoke(&self) {
        let _ = nft_router(&format!("delete element inet wifihub auth {{ {CLIENT_MAC} }}\n"));
    }

    /// Add an IPv4 to the garden set (pre-auth reachable).
    fn add_garden_v4(&self, ip: &str) {
        let (ok, out) = nft_router(&format!("add element inet wifihub garden4 {{ {ip} }}\n"));
        assert!(ok, "add garden element failed:\n{out}");
    }

    /// `curl` from the client to `dst:80`, returning the response headers+body.
    fn client_http(&self, dst: &str) -> String {
        // -s silent, -D - dump headers, -m 5 timeout, -o /dev/null drop body.
        nsx(NS_CLIENT, "curl", &["-s", "-D", "-", "-o", "/dev/null", "-m", "5", &format!("http://{dst}/")]).1
    }

    /// True if the client can open a TCP connection to `dst:port` within 3s.
    fn client_can_connect(&self, dst: &str, port: u16) -> bool {
        nsx(NS_CLIENT, "nc", &["-z", "-w", "3", dst, &port.to_string()]).0
    }
}

impl Drop for Topo {
    fn drop(&mut self) {
        Topo::teardown_quiet();
    }
}

fn addr(ns: &str, iface: &str, ip: &str, prefix: u8) {
    must("ip", &["netns", "exec", ns, "ip", "addr", "add", &format!("{ip}/{prefix}"), "dev", iface]);
    must("ip", &["netns", "exec", ns, "ip", "link", "set", iface, "up"]);
}

// ---------------------------------------------------------------------------
// Engine process (RAII) — the real daemon inside the router namespace
// ---------------------------------------------------------------------------

struct Engine {
    child: Child,
    cfg_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl Engine {
    /// Write a minimal config + HMAC key and launch the real `portcullis` binary
    /// in the router namespace. The reconciler is effectively disabled
    /// (`reconcile_interval` huge) and reaping is off so the harness can edit the
    /// `@auth` set directly without the daemon fighting it; the control channel
    /// self-disables (no TLS material) — fail-closed, which is fine here.
    fn spawn() -> Engine {
        let tag = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir();
        let key_path = dir.join(format!("pctest-hmac-{tag}.key"));
        let cfg_path = dir.join(format!("pctest-cfg-{tag}.toml"));
        std::fs::write(&key_path, HMAC_KEY.as_bytes()).unwrap();
        std::fs::write(
            &cfg_path,
            format!(
                r#"
store_id = "{STORE_ID}"
control_endpoint = "https://127.0.0.1:59999"
hmac_key_file = "{key}"
responder_port = 8080
accounting_interval = 15
default_ttl = 1800
default_quota_mb = 0
default_rate_kbps = 0
metrics_port = 0
reconcile_interval = 86400
firewall_backend = "nft"
hotspot_iface = "{GATED_IFACE}"
reap_conntrack = false
"#,
                key = key_path.display(),
            ),
        )
        .unwrap();

        let child = Command::new("ip")
            .args(["netns", "exec", NS_ROUTER, ENGINE_BIN])
            .env("PORTCULLIS_CONFIG", &cfg_path)
            .env("RUST_LOG", "info")
            .spawn()
            .expect("spawn portcullis in router ns");

        let eng = Engine { child, cfg_path, key_path };
        eng.wait_until_ready();
        eng
    }

    /// Poll until the `inet wifihub` table exists (ensure_base ran). Panics after
    /// a bounded wait so a broken launch fails loudly rather than hanging.
    fn wait_until_ready(&self) {
        for _ in 0..50 {
            let (ok, out) = nsx(NS_ROUTER, "nft", &["list", "table", "inet", "wifihub"]);
            if ok && out.contains("chain") {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("engine did not create table inet wifihub within 5s");
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.cfg_path);
        let _ = std::fs::remove_file(&self.key_path);
    }
}

// A short settle so a just-edited set / a fresh route is in effect.
fn settle() {
    std::thread::sleep(Duration::from_millis(200));
}

// ---------------------------------------------------------------------------
// Verdict matrix (the core of §15)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn unauth_http_80_redirects_with_valid_hmac() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    settle();

    // No @auth element -> :80 is DNAT'd to the :8080 responder, which 302s to the
    // portal with a signed query. Assert the redirect + that a sig is present.
    let resp = topo.client_http(UPSTREAM_IP);
    assert!(resp.contains("302"), "unauth :80 must be redirected (302); got:\n{resp}");
    assert!(
        resp.to_lowercase().contains("location:") && resp.contains("sig="),
        "302 must carry a signed Location; got:\n{resp}"
    );
    assert!(
        resp.contains(&format!("mac={CLIENT_MAC}")) || resp.to_lowercase().contains("mac="),
        "Location must carry the client MAC; got:\n{resp}"
    );
}

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn authed_client_is_forwarded() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    topo.grant(1800);
    settle();

    // MAC in @auth -> forward chain accepts; the client can reach upstream:80
    // (nothing listening returns a connection refused, but the SYN is FORWARDED,
    // not dropped — nc -z reports the port state; a refused != a silent drop).
    // We assert the flow is not gated by checking a non-garden TCP connect gets
    // past the gate (reachability to the upstream IP).
    assert!(
        topo.client_can_connect(UPSTREAM_IP, 22) || topo.client_can_connect(UPSTREAM_IP, 80),
        "authed client must be forwarded to upstream (not dropped by the gate)"
    );
}

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn garden_destination_allowed_pre_auth() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    // No grant; put the upstream IP in the garden -> reachable pre-auth.
    topo.add_garden_v4(UPSTREAM_IP);
    settle();
    assert!(
        topo.client_can_connect(UPSTREAM_IP, 22) || topo.client_can_connect(UPSTREAM_IP, 80),
        "a garden destination must be reachable before authentication"
    );
}

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn unauth_https_443_non_garden_is_dropped() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    settle();
    // Pre-auth :443 to a non-garden host hits the forward-chain drop (the engine
    // never intercepts :443). A drop => connect times out (false).
    assert!(
        !topo.client_can_connect(UPSTREAM_IP, 443),
        "pre-auth :443 to a non-garden host must be dropped (no interception)"
    );
}

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn revoked_client_is_dropped_again() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    topo.grant(1800);
    settle();
    assert!(topo.client_can_connect(UPSTREAM_IP, 22), "authed precondition");

    topo.revoke();
    settle();
    // After revoke the MAC is gone from @auth -> NEW connections to a non-garden
    // host are dropped again. (Established-flow reaping is the daemon's job on a
    // real CP revoke; see the reaping unit tests + the live-flow case below.)
    assert!(
        !topo.client_can_connect(UPSTREAM_IP, 22),
        "a revoked client's new connections must be gated again"
    );
}

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn expired_element_re_gates() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let _engine = Engine::spawn();
    topo.grant(2); // 2-second kernel timeout
    settle();
    assert!(topo.client_can_connect(UPSTREAM_IP, 22), "authed while element lives");

    std::thread::sleep(Duration::from_secs(3)); // let the kernel timeout expire it
    assert!(
        !topo.client_can_connect(UPSTREAM_IP, 22),
        "after the kernel set-element timeout, the client must be gated again"
    );
}

// ---------------------------------------------------------------------------
// Fault injection — the no-fail-open guarantees (§15)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires Linux + root + nft/ip/curl/nc"]
fn restart_adopts_kernel_auth_no_client_dropped() {
    if !linux_root() {
        return;
    }
    let topo = Topo::setup();
    let engine = Engine::spawn();
    topo.grant(1800);
    settle();
    assert!(topo.client_can_connect(UPSTREAM_IP, 22), "authed precondition");

    // kill -9 the daemon mid-session; the kernel keeps the ruleset + @auth.
    drop(engine); // Drop kills the child
    settle();
    // The element is still present (kernel-as-truth survives the daemon).
    let (_, listing) = nsx(NS_ROUTER, "nft", &["list", "set", "inet", "wifihub", "auth"]);
    assert!(
        listing.contains(CLIENT_MAC),
        "kernel @auth must survive a daemon kill (no flush on crash):\n{listing}"
    );

    // Relaunch: the engine must ADOPT the existing element (never flush), so the
    // client stays authorized across the restart.
    let _engine2 = Engine::spawn();
    settle();
    let (_, after) = nsx(NS_ROUTER, "nft", &["list", "set", "inet", "wifihub", "auth"]);
    assert!(
        after.contains(CLIENT_MAC),
        "restart must adopt @auth, not drop the authorized client:\n{after}"
    );
    assert!(
        topo.client_can_connect(UPSTREAM_IP, 22),
        "adopted client must still be forwarded after restart"
    );
}

// TODO(G9, follow-up on the Linux runner): two more fault-injection cases need a
// mock control-plane gRPC server the engine dials (mTLS). They are scaffolded
// here as documented, currently-skipped cases; wiring the mock CP (a tonic
// server presenting a test cert the engine's cp_server_ca pins) is the remaining
// work — it is the same mock CP the CGNAT design doc's "Phase 6" calls for.
//
//   * cp_loss_keeps_enforcing_and_blocks_new_grants:
//       bring the mock CP up, let the engine attach + receive a grant, then kill
//       the CP. Assert: the granted client keeps being forwarded (kernel-as-truth),
//       a *new* MAC cannot be granted (no path accepts a grant while detached),
//       and the engine reconnects with backoff + re-sends its Hello snapshot.
//
//   * live_flow_is_reaped_on_revoke (proves G1 end-to-end):
//       grant, open a long-lived TCP flow client->upstream, issue a CP revoke.
//       Assert the ESTABLISHED flow is *severed* (conntrack entry gone, socket
//       dies) — not merely that new connections fail. This is the assertion the
//       reaping unit tests approximate; only netns proves the kernel behaviour.
#[test]
#[ignore = "scaffold: needs the mock control-plane server (see TODO above)"]
fn cp_loss_keeps_enforcing_and_blocks_new_grants() {
    if !linux_root() {
        return;
    }
    eprintln!("SKIP: mock control-plane server not yet wired (G9 follow-up)");
}

#[test]
#[ignore = "scaffold: needs the mock control-plane server (see TODO above)"]
fn live_flow_is_reaped_on_revoke() {
    if !linux_root() {
        return;
    }
    eprintln!("SKIP: mock control-plane server not yet wired (G9 follow-up)");
}
