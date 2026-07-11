//! Optional 802.11 deauth on revoke — the L2 companion to the L3 revoke.
//!
//! The L3 revoke (drop the MAC from `@auth` + reap conntrack, invariant #9) gates
//! the client at the router but leaves the phone *associated* to Wi-Fi
//! ("connected, no internet") until the OS re-probes the captive portal. When the
//! control plane sets `deauth` on the revoke, the engine ALSO asks hostapd to
//! deauthenticate the client so it drops off Wi-Fi and re-onboards into the portal
//! cleanly.
//!
//! Best-effort, like the [`FlowReaper`](portcullis_types::FlowReaper): a deauth
//! failure is a bonus that didn't land, never a fail-open — the caller has already
//! completed the L3 revoke. A missing `ubus`/hostapd is `Ok(())` (the device may
//! not run hostapd — e.g. a wired test box), and "client not on this AP" is a
//! harmless no-op. [`parse_hostapd_objects`] is the pure test seam.

use async_trait::async_trait;
use portcullis_types::{Deauthenticator, Error, MacAddr, Result};
use tokio::process::Command;

/// hostapd's `del_client` deauth reason code. 5 = `WLAN_REASON_DISASSOC_AP_BUSY`
/// (a benign, standards-defined disassociation reason that prompts a clean
/// reconnect); it is not a hard ban.
const DEAUTH_REASON: u32 = 5;

/// Production [`Deauthenticator`]: drives hostapd over ubus.
///
/// For a revoked MAC it enumerates the hostapd AP objects (`ubus -S list`, keeping
/// `hostapd.*`) and calls `del_client` on each. The client is associated to exactly
/// one AP iface; `del_client` on the others is a harmless no-op, so we fan out
/// rather than track which iface a MAC lives on. Args are engine-constructed (a
/// validated `MacAddr`, never raw client text) and `Command` runs no shell — no
/// injection surface.
#[derive(Clone)]
pub struct UbusDeauth {
    program: String,
}

impl Default for UbusDeauth {
    fn default() -> Self {
        UbusDeauth { program: "ubus".to_string() }
    }
}

impl UbusDeauth {
    pub fn new(program: impl Into<String>) -> Self {
        UbusDeauth { program: program.into() }
    }

    /// `ubus -S list` → the hostapd AP object names. A missing `ubus` (or any
    /// spawn/exec failure) yields an empty list, NOT an error: on a device without
    /// hostapd there is simply nothing to deauth (best-effort).
    async fn hostapd_objects(&self) -> Vec<String> {
        let out = match Command::new(&self.program).arg("-S").arg("list").output().await {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!(program = %self.program, error = %e, "ubus list unavailable; skipping deauth");
                return Vec::new();
            }
        };
        if !out.status.success() {
            tracing::debug!(
                program = %self.program,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "ubus list failed; skipping deauth"
            );
            return Vec::new();
        }
        parse_hostapd_objects(&String::from_utf8_lossy(&out.stdout))
    }
}

#[async_trait]
impl Deauthenticator for UbusDeauth {
    async fn deauth(&self, mac: MacAddr) -> Result<()> {
        let objects = self.hostapd_objects().await;
        if objects.is_empty() {
            // No hostapd (or no APs) → nothing to do. Best-effort success.
            return Ok(());
        }
        // Lowercase colon-separated, the form hostapd expects (MacAddr::Display).
        let addr = mac.to_string();
        let params =
            format!(r#"{{"addr":"{addr}","reason":{DEAUTH_REASON},"deauth":true,"ban_time":0}}"#);

        let mut hits = 0usize;
        let mut last_err: Option<String> = None;
        for obj in &objects {
            match Command::new(&self.program)
                .arg("call")
                .arg(obj)
                .arg("del_client")
                .arg(&params)
                .output()
                .await
            {
                Ok(out) if out.status.success() => hits += 1,
                Ok(out) => {
                    // A non-success exit here is almost always "client not on this
                    // AP" (it's associated to exactly one) — benign. Record it in
                    // case EVERY object failed, but never treat one as fatal.
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::debug!(object = %obj, %addr, stderr = %stderr, "del_client non-success (client likely on another AP)");
                    last_err = Some(stderr.trim().to_string());
                }
                Err(e) => {
                    // A genuine spawn failure mid-loop: `ubus` existed for `list`
                    // but vanished/erroring now. Record and keep trying the rest.
                    tracing::debug!(object = %obj, %addr, error = %e, "del_client spawn failed");
                    last_err = Some(e.to_string());
                }
            }
        }

        if hits > 0 {
            tracing::info!(%addr, objects = objects.len(), hits, "deauthenticated client off Wi-Fi");
            Ok(())
        } else {
            // No AP accepted the del_client. Usually the client had already left
            // (nothing to deauth) — still Ok. Only surface an Err if we never got a
            // clean exit AND saw a real failure, so the caller can log it (it stays
            // best-effort and never changes the revoke ack).
            match last_err {
                Some(msg) => Err(Error::Other(format!("ubus del_client {addr}: {msg}"))),
                None => Ok(()),
            }
        }
    }
}

/// Parse `ubus -S list` output into the hostapd AP object names (`hostapd.*`).
///
/// `ubus -S list` prints one object name per line (no JSON, no quoting). We keep
/// only the `hostapd.` namespace (e.g. `hostapd.wlan0`, `hostapd.phy0-ap0`) — the
/// per-AP objects that expose `del_client` — and drop `hostapd` (the global
/// object) and every unrelated object. Pure → unit-testable without ubus.
fn parse_hostapd_objects(list_output: &str) -> Vec<String> {
    list_output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("hostapd."))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_per_ap_hostapd_objects() {
        // `ubus -S list` output: one object per line. Keep the per-AP hostapd.*
        // objects; drop the bare `hostapd` global and every unrelated object.
        let out = "\
dnsmasq
hostapd
hostapd.wlan0
hostapd.phy0-ap0
network.interface.lan
network.wireless
";
        let objs = parse_hostapd_objects(out);
        assert_eq!(objs, vec!["hostapd.wlan0", "hostapd.phy0-ap0"]);
    }

    #[test]
    fn parse_empty_or_no_hostapd_yields_empty() {
        assert!(parse_hostapd_objects("").is_empty());
        assert!(parse_hostapd_objects("dnsmasq\nnetwork.interface.lan\n").is_empty());
        // The bare global `hostapd` object has no `del_client`, so it's excluded.
        assert!(parse_hostapd_objects("hostapd\n").is_empty());
    }

    /// A missing `ubus` binary must be a best-effort `Ok(())`, not an error — a
    /// device without hostapd (e.g. a wired test box) has nothing to deauth.
    #[tokio::test]
    async fn missing_ubus_is_ok_noop() {
        let d = UbusDeauth::new("/nonexistent/portcullis-test-ubus");
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert!(d.deauth(mac).await.is_ok(), "absent ubus must be a best-effort no-op");
    }
}
