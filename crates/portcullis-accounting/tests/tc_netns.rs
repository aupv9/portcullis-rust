//! Real-kernel TcShaper smoke test (netns-harness style: Linux + root + tc).
//!
//! Ignored by default so plain `cargo test` stays hermetic on any host; run
//! explicitly where a kernel is available (CI Linux runner or the router):
//!
//! ```sh
//! sudo -E cargo test -p portcullis-accounting --test tc_netns -- --ignored
//! ```
//!
//! Verifies the real command shapes against a veth pair: root qdisc install,
//! per-MAC class + dst-MAC u32 filters (the §18-class on-device risk), and
//! teardown. Bandwidth is NOT measured here — only that the kernel accepts
//! the objects.

use portcullis_accounting::{Shaper, TcShaper};

async fn sh(cmd: &str) -> (bool, String) {
    let out = tokio::process::Command::new("sh")
        .args(["-c", cmd])
        .output()
        .await
        .expect("spawn sh");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[tokio::test]
#[ignore = "requires Linux + root + tc (kernel objects); run via the netns CI job"]
async fn tc_shaper_programs_a_real_interface() {
    let iface = "pcltc0";
    // Fresh veth pair; clean up any leftover from a previous run first.
    let _ = sh(&format!("ip link del {iface} 2>/dev/null")).await;
    let (ok, out) = sh(&format!("ip link add {iface} type veth peer name {iface}p && ip link set {iface} up")).await;
    assert!(ok, "veth setup failed (root? Linux?): {out}");

    let shaper = TcShaper::new(iface);
    let mac = "aa:bb:cc:dd:ee:ff".parse().unwrap();

    shaper.ensure_root().await.expect("root HTB qdisc");
    shaper.apply(mac, 2_000_000).await.expect("apply cap");

    let (_, classes) = sh(&format!("tc class show dev {iface}")).await;
    assert!(classes.contains("htb 1:2"), "class missing: {classes}");
    assert!(classes.contains("rate 2Mbit"), "rate missing: {classes}");
    let (_, filters) = sh(&format!("tc filter show dev {iface}")).await;
    assert!(filters.contains("u32"), "u32 filter missing: {filters}");

    shaper.clear(mac).await.expect("clear cap");
    let (_, classes) = sh(&format!("tc class show dev {iface}")).await;
    assert!(!classes.contains("htb 1:2"), "class not removed: {classes}");

    let _ = sh(&format!("ip link del {iface}")).await;
}
