//! TDD coverage for the 2026-09-20 independent security audit's
//! open-write/format-bypass finding (HIGH) on the **Storage API**
//! (`POST /credentials`) - two independent halves of one signing oracle.
//!
//! Half (a), **the default posture is "trust everyone"**:
//! `Config::trusted_issuer_dids` ships empty (`main.rs`'s
//! `--trusted-issuer-did` defaults to no values at all), and
//! `auth::check_trusted_issuer` reads an empty allow-list as "no restriction
//! is configured", so a bare `cargo run -- credential-service` accepts a
//! `CredentialMessage` from *any* party that can host a well-formed
//! `did:web` document and self-sign a Self-Issued ID Token - no
//! configuration, no relationship, no prior request. The existing
//! `trusted_issuer_allowlist.rs` only ever exercises a *non-empty*
//! allow-list, so nothing in this suite pinned what happens when nothing is
//! configured, which is precisely the shipped default.
//!
//! Half (b), **a non-JWT `format` skips proof verification entirely**:
//! `validation::verify_credential_proofs` verifies a container's own
//! embedded proof only when its `format` field contains the substring
//! `"jwt"`; every other value (`"ldp_vc"`, `""`, anything) `continue`s past
//! the check and is stored unverified. Combined with
//! `handlers::build_presentation`, which copies a stored credential's
//! `payload` verbatim into a Verifiable Presentation signed with *this
//! service's own key*, that turns the Storage API into a signing oracle for
//! arbitrary attacker-supplied JSON.
//!
//! The two are tested separately and deliberately do not lean on each other:
//! the format tests below configure an explicit trusted issuer, so they stay
//! red for their own reason (the format bypass) rather than being carried by
//! the fix for (a).
//!
//! **TCK compatibility is the constraint, not an afterthought.** The real
//! `eclipsedataspacetck/dcp-tck-runtime` Credential-Service setup phase
//! writes its own dynamically generated credentials through this same
//! Storage API - which is the documented reason the allow-lists default
//! empty (`../../ARCHITECTURE.md`, "What's simplified or stubbed"). But the
//! TCK's own SUT configuration already opts in explicitly:
//! `tests/dcp.tck.properties` pins `dataspacetck.did.issuer` and
//! `tests/dcp_tck.rs` wires the identical value into
//! `Config::trusted_issuer_dids` via `with_trusted_issuer_dids`. The gap
//! these tests are about is therefore the *unconfigured* default, not the
//! TCK's own correctly-scoped configuration, and
//! `explicitly_configured_trusted_issuer_is_still_accepted` below is the
//! guard that the opt-in mechanism the TCK depends on keeps working
//! unchanged. Likewise for (b): the TCK's own `CredentialFormat` enum has
//! exactly two constants, `VC1_0_JWT` (`vc11-sl2021/jwt`) and `VC2_0_JOSE`
//! (`vc20-bssl/jwt`), and only `VC1_0_JWT` is ever used by the two
//! Credential-Service test packages this bootstrap runs (verified by
//! unpacking `/app/tck-runtime.jar` out of the real image and grepping the
//! classes, not guessed) - every format label the TCK actually puts on the
//! wire contains `jwt`, so a rule that rejects what this service cannot
//! verify cannot regress it. The two guards at the bottom pin exactly that.
//!
//! Same real-HTTP, real-ES256 harness `storage_offer_auth.rs` /
//! `trusted_issuer_allowlist.rs` / `message_content_validation.rs`
//! established, plus - for the default-posture half only - one test that
//! boots the **real binary** with no allow-list flags at all, so the
//! shipped CLI default is pinned rather than a library-level stand-in for
//! it.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::{Json, Router};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Kills the spawned `identity-hub` binary when the test ends, however it
/// ends (including a panicking assertion).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boots the **real `identity-hub` binary** in Credential Service mode with
/// no configuration beyond the one flag required to make it reachable on a
/// free port: no `--trusted-issuer-did`, no `--known-holder-pid`, no
/// `--allow-resolve-host`. Every other value - `did_host`
/// (`localhost:<port>`), `insecure_http` (`true`), and both allow-lists
/// (empty) - is whatever `main.rs`'s own clap defaults say it is, which is
/// exactly what this test is about.
async fn spawn_default_config_binary() -> (ChildGuard, String, String) {
    // Take an ephemeral port from the OS, then release it so the binary can
    // bind it itself (the binary has no "port 0, tell me what you got"
    // mode - a real deployment always names its own port, since its own
    // `did:web` identity embeds it).
    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve a free loopback port for the binary under test");
    let port = probe
        .local_addr()
        .expect("bound listener has a local address")
        .port();
    drop(probe);

    let child = Command::new(env!("CARGO_BIN_EXE_identity-hub"))
        .args(["credential-service", "--bind", &format!("127.0.0.1:{port}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the identity-hub binary starts");
    let guard = ChildGuard(child);

    let base = format!("http://127.0.0.1:{port}");
    // `did_host` defaults to `localhost:<bind port>` (main.rs), so this is
    // the DID an incoming Self-Issued ID Token must be addressed to.
    let own_did = format!("did:web:localhost%3A{port}:credential-service");
    let ready_url = format!("{base}/credential-service/did.json");
    for _ in 0..150 {
        if let Ok(response) = reqwest::get(&ready_url).await
            && response.status().is_success()
        {
            return (guard, base, own_did);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the identity-hub binary never became ready on {base}");
}

/// Boots this crate's real Credential Service in-process, with
/// `trusted_issuer_dids` configured as given - an empty vector is exactly
/// the posture `main.rs`'s CLI default produces.
async fn spawn_credential_service(trusted_issuer_dids: Vec<String>) -> (Arc<AppState>, String) {
    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        "localhost:0",
    )
    .with_trusted_issuer_dids(trusted_issuer_dids);
    let (state, router) = identity_hub_http::build(config);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the credential service under test");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("credential service under test");
    });
    (state, format!("http://{addr}"))
}

/// The same stand-in `did:web` server every other test file here uses: a
/// real, resolvable identity with a real `capabilityInvocation` key, so the
/// caller below is rejected (or accepted) purely on *who it is* and *what it
/// sends*, never on a malformed envelope.
async fn spawn_caller_identity(path_segment: &str) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the stand-in DID server");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), path_segment);
    let doc = identity.did_document(&[]);
    let route = format!("/{path_segment}/did.json");
    let app = Router::new().route(
        &route,
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("stand-in caller DID server");
    });
    identity
}

fn sign(signer: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(
        &payload,
        &signer.key_pair.signing_key(),
        signer.own_key_id(),
    )
}

/// A genuinely valid Self-Issued ID Token: correctly self-signed,
/// `iss == sub`, addressed to `aud`, unexpired, with a fresh `jti`. Nothing
/// below ever fails on the envelope.
fn bearer_token(caller: &ServiceIdentity, aud: &str) -> String {
    let now = dcp_core::now_secs();
    sign(
        caller,
        json!({
            "iss": caller.own_did(),
            "sub": caller.own_did(),
            "aud": aud,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

/// A genuinely verifiable JWT-format credential container, signed by
/// `issuer` itself and verifiable against `issuer`'s own real, resolvable
/// `did:web` document - the shape this service can actually check. `format`
/// is passed in so the guards below can pin both this bootstrap's own label
/// (`"jwt"`) and the real TCK's (`"VC1_0_JWT"`).
fn verifiable_credential_container(issuer: &ServiceIdentity, format: &str) -> Value {
    let now = dcp_core::now_secs();
    let jws = sign(
        issuer,
        json!({
            "iss": issuer.own_did(),
            "sub": issuer.own_did(),
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "MembershipCredential"],
                "credentialSubject": {"id": issuer.own_did()},
            },
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    );
    json!({"credentialType": "MembershipCredential", "format": format, "payload": jws})
}

fn credential_message_body(credentials: Vec<Value>) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialMessage",
        "issuerPid": "issuer-pid-1",
        "holderPid": "holder-pid-1",
        "status": "ISSUED",
        "credentials": credentials,
    })
}

async fn post(url: &str, bearer: &str, body: &Value) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {bearer}"))
        .json(body)
        .send()
        .await
}

// ---- (a) the shipped default posture ----

/// The headline case, against the **real binary** started the way a
/// newcomer following `README.md` starts it: an arbitrary party this
/// service has never heard of, has no configured relationship with, and
/// never issued a Credential Request to, writes a credential batch into its
/// store and is told `200 OK`.
///
/// Red at the time of writing: the binary answers `200 OK` and stores the
/// batch. A Storage API write must be an authorization decision, not a
/// side effect of being able to host a DID document.
#[tokio::test]
async fn default_config_storage_write_rejects_an_unrecognized_issuer() {
    let (_binary, base, service_did) = spawn_default_config_binary().await;
    let stranger = spawn_caller_identity("stranger").await;
    let token = bearer_token(&stranger, &service_did);

    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![verifiable_credential_container(&stranger, "jwt")]),
    )
    .await
    .expect("request completes");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "with no trusted issuer configured, a Credential Service must trust nobody by default - \
         an unconfigured deployment accepting writes from any resolvable DID is the open-write \
         half of the 2026-09-20 audit's signing-oracle finding"
    );
}

/// The same rule at the library level, so the semantics are pinned even
/// where spawning a child process isn't practical: an empty
/// `Config::trusted_issuer_dids` (what `main.rs`'s CLI default produces)
/// must mean "no issuer is trusted", not "every issuer is trusted".
#[tokio::test]
async fn empty_trusted_issuer_allowlist_rejects_an_unrecognized_issuer() {
    let stranger = spawn_caller_identity("stranger").await;
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let token = bearer_token(&stranger, "did:web:localhost%3A0:credential-service");

    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![verifiable_credential_container(&stranger, "jwt")]),
    )
    .await
    .expect("request completes");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an empty trusted-issuer allow-list must fail closed"
    );
    assert!(
        state.store.all().is_empty(),
        "nothing may reach the store when no issuer is trusted"
    );
}

/// The compatibility guard the fix for (a) must not break: the explicit
/// opt-in the real TCK's own SUT configuration already uses
/// (`dataspacetck.did.issuer` -> `Config::with_trusted_issuer_dids`, see
/// `tests/dcp.tck.properties` and `tests/dcp_tck.rs`) keeps working exactly
/// as it does today. Green before and after.
#[tokio::test]
async fn explicitly_configured_trusted_issuer_is_still_accepted() {
    let issuer = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer, "did:web:localhost%3A0:credential-service");

    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![verifiable_credential_container(&issuer, "jwt")]),
    )
    .await
    .expect("request completes");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        state.store.all().len(),
        1,
        "an explicitly configured issuer's write must still be stored"
    );
}

// ---- (b) the format-bypass signing oracle ----

/// The live PoC from the audit, reduced to a test: a credential whose
/// `format` is anything this service cannot actually verify (`"ldp_vc"`
/// here) carries a `payload` that is arbitrary attacker JSON rather than a
/// signed JWS, and is stored unverified - from where
/// `handlers::build_presentation` will copy it verbatim into a Verifiable
/// Presentation signed with this service's own key.
///
/// The caller here is an *explicitly trusted* issuer, so this test isolates
/// the format bypass: it must stay red until the format rule itself is
/// fixed, and must not be carried by the fix for (a).
///
/// Red at the time of writing: `200 OK`, batch stored.
#[tokio::test]
async fn storage_write_rejects_a_credential_whose_format_cannot_be_verified() {
    let issuer = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer, "did:web:localhost%3A0:credential-service");

    let unverifiable = json!({
        "credentialType": "MembershipCredential",
        "format": "ldp_vc",
        "payload": {"secret": "arbitrary attacker JSON this service would sign into a VP"},
    });
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![unverifiable]),
    )
    .await
    .expect("request completes");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a credential whose proof this service cannot verify must be rejected outright, not \
         accepted unverified - accepting it makes this service a signing oracle for arbitrary \
         JSON via build_presentation"
    );
    assert!(
        state.store.all().is_empty(),
        "an unverifiable credential must never reach the store"
    );
}

/// The same rule at its edge: an empty `format` is not a free pass either.
/// `"".contains(\"jwt\")` is false, so today this takes the exact same
/// silent skip as `"ldp_vc"`.
///
/// Red at the time of writing: `200 OK`, batch stored.
#[tokio::test]
async fn storage_write_rejects_a_credential_with_an_empty_format() {
    let issuer = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer, "did:web:localhost%3A0:credential-service");

    let unlabelled = json!({
        "credentialType": "MembershipCredential",
        "format": "",
        "payload": {"secret": "arbitrary attacker JSON"},
    });
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![unlabelled]),
    )
    .await
    .expect("request completes");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an unlabelled credential format is not verifiable either"
    );
    assert!(
        state.store.all().is_empty(),
        "an unverifiable credential must never reach the store"
    );
}

/// Compatibility guard: this bootstrap's own Issuer Service labels every
/// credential it delivers `"jwt"` (`handlers::try_deliver_issued_credential`),
/// and that path must keep working. Green before and after.
#[tokio::test]
async fn storage_write_still_accepts_a_genuinely_verifiable_jwt_credential() {
    let issuer = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer, "did:web:localhost%3A0:credential-service");

    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(vec![verifiable_credential_container(&issuer, "jwt")]),
    )
    .await
    .expect("request completes");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

/// Compatibility guard for the real TCK's own format label: its
/// `CredentialFormat` enum's only Credential-Service-side constant is
/// `VC1_0_JWT` (profile string `vc11-sl2021/jwt`) - both spellings contain
/// `jwt`, so whichever of the two it serializes must stay on the verified,
/// accepted path. Green before and after; this is the test that says the
/// fix for (b) may not simply narrow the accepted set to the literal
/// string `"jwt"`.
#[tokio::test]
async fn storage_write_still_accepts_the_tck_s_own_jwt_format_label() {
    let issuer = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;

    for label in ["VC1_0_JWT", "vc11-sl2021/jwt"] {
        let token = bearer_token(&issuer, "did:web:localhost%3A0:credential-service");
        let response = post(
            &format!("{base}/credentials"),
            &token,
            &credential_message_body(vec![verifiable_credential_container(&issuer, label)]),
        )
        .await
        .expect("request completes");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "format label '{label}' names a JWT credential this service can verify"
        );
    }
    assert_eq!(state.store.all().len(), 2);
}
