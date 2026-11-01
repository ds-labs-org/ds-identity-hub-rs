//! 2026-10-16 project audit, finding C1 (CRITICAL), pinned against the
//! **real binary**: `--sts-client-secret` used to default to the DCP TCK's
//! public `tck-secret`. On a hub started without it, anyone could mint STS
//! tokens (and read every stored credential through the Presentation API)
//! or create OID4VCI offers (and get credentials signed by this issuer).
//!
//! Now the binary refuses to start without an operator secret, and the
//! TCK pair opens nothing on a hub configured with its own.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::TcpListener;

const SECRET: &str = "operator-secret-for-this-test";

/// Kills the spawned binary when the test ends, however it ends.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("free port");
    probe.local_addr().expect("local addr").port()
}

fn hub(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_identity-hub"));
    command
        .args(args)
        .env_remove("IDENTITY_HUB_STS_CLIENT_SECRET")
        .env_remove("IDENTITY_HUB_ADMIN_TOKEN");
    command
}

/// Boots `issuer-service` with `extra` flags and waits until it answers.
async fn spawn_issuer(extra: &[&str]) -> (ChildGuard, String) {
    let port = free_port().await;
    let bind = format!("127.0.0.1:{port}");
    let mut args = vec!["issuer-service", "--bind", &bind];
    args.extend_from_slice(extra);
    let child = hub(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the identity-hub binary starts");
    let guard = ChildGuard(child);
    let base = format!("http://{bind}");
    for _ in 0..150 {
        if let Ok(response) = reqwest::get(format!("{base}/metadata")).await
            && response.status().is_success()
        {
            return (guard, base);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the identity-hub binary never became ready on {base}");
}

#[test]
fn the_binary_refuses_to_start_without_an_operator_secret() {
    for mode in ["credential-service", "issuer-service"] {
        let output = hub(&[mode, "--bind", "127.0.0.1:0"])
            .output()
            .expect("the identity-hub binary runs");
        assert!(
            !output.status.success(),
            "{mode} started with no --sts-client-secret"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--sts-client-secret"),
            "{mode}: the error names the missing flag: {stderr}"
        );
    }
}

#[tokio::test]
async fn the_tck_credentials_open_nothing_on_a_configured_hub() {
    let (_hub, base) = spawn_issuer(&["--sts-client-secret", SECRET]).await;
    let client = reqwest::Client::new();
    let issuer_did = client
        .get(format!("{base}/metadata"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["issuer"]
        .as_str()
        .expect("issuer DID")
        .to_string();

    let sts = |secret: &'static str| {
        client
            .post(format!("{base}/sts/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "tck-client"),
                ("client_secret", secret),
                ("audience", issuer_did.as_str()),
            ])
            .send()
    };
    let refused = sts("tck-secret").await.unwrap();
    assert!(
        refused.status().is_client_error(),
        "STS minted a token for the TCK secret: {}",
        refused.status()
    );
    assert!(sts(SECRET).await.unwrap().status().is_success());

    let offer = |secret: &'static str| {
        client
            .post(format!("{base}/oid4vci/offers"))
            .basic_auth("tck-client", Some(secret))
            .json(&json!({}))
            .send()
    };
    assert_eq!(
        offer("tck-secret").await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an OID4VCI offer was created with the TCK secret"
    );
    assert_eq!(
        offer(SECRET).await.unwrap().status(),
        reqwest::StatusCode::CREATED
    );
}
