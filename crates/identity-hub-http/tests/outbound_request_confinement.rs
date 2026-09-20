//! RED coverage for the three outbound-request findings of the 2026-09-20
//! independent security audit: this service makes HTTP requests to
//! destinations an *unauthenticated caller* chooses, to any host, with no
//! bound on how long it will wait.
//!
//! - **Finding 4 (HIGH) - pre-auth SSRF via unverified `iss` DID
//!   resolution.** `auth::verify_bearer_token` must resolve the caller's
//!   `iss` before it can check the caller's signature (it needs the
//!   verification key the DID document carries), so `dcp_core::resolve_did`
//!   (and through it `did_web_to_url`, which does no host filtering
//!   whatsoever) is reached by anyone who can POST an arbitrary,
//!   entirely unsigned string to `/presentations/query`. The destination is
//!   whatever host the attacker typed into their own `iss` claim. A live PoC
//!   run against this build produced distinguishable responses for an open
//!   port, a closed port, and a black-holed address: a credential-free
//!   internal port scanner and host-liveness oracle.
//! - **Finding 5 (HIGH) - Issuer Service SSRF, a stronger primitive.**
//!   `handlers::try_deliver_issued_credential` takes its delivery
//!   destination from `service_endpoint_url(&holder_doc,
//!   "CredentialService")` - a string lifted verbatim out of the
//!   *requester's own* DID document, never validated - and then POSTs an
//!   authenticated request (bearer token, JSON body) to it. The requester
//!   controls the host, the port, and the body.
//! - **Finding 6 (MEDIUM) - no timeout on any outbound call.**
//!   `AppState::new`'s `reqwest::Client::builder()` sets neither
//!   `.timeout()` nor `.connect_timeout()`, so a destination that accepts a
//!   connection and then says nothing pins the handling task (and the
//!   caller's connection) open indefinitely.
//!
//! ## Why these tests use loopback addresses, and what that means for the fix
//!
//! The hard constraint (see `../../ARCHITECTURE.md`, "A real networking
//! gotcha") is that a blanket "block loopback and private ranges" fix would
//! break this project's own 54/54 DCP TCK conformance: the real TCK hosts
//! its own `verifier`/`issuer`/`thirdparty` DIDs at `host.docker.internal`,
//! which `AppState::new` deliberately pins to `127.0.0.1` with a static
//! `reqwest` DNS override so the hairpin round trip through the container's
//! published port works. This service also resolves its *own* synthetic STS
//! party DID at `127.0.0.1:<bind port>`. Loopback is, for this bootstrap,
//! legitimate traffic.
//!
//! So these tests do not assert "loopback is refused". They assert the
//! narrower, actually-correct property: **a destination host that no part of
//! this service's configuration ever named is not contacted at all.** The
//! unconfigured destinations below live at `127.0.0.2`/`127.0.0.3` - still
//! loopback, so the tests stay hermetic and need no network, but a *different
//! host string* from the `127.0.0.1`/`host.docker.internal` this service's
//! own configuration implies. A fix that allow-lists hosts explicitly passes
//! these; a fix that allow-lists "anything on 127.0.0.0/8" does not, and a
//! fix that blanket-blocks loopback breaks the TCK. See the accompanying
//! handoff spec for the exact mechanism expected.
//!
//! `did_resolution_gives_up_on_a_host_that_never_responds` deliberately puts
//! its black hole on `127.0.0.1` - a host the allow-list *does* contain - so
//! that the host check cannot make it pass vacuously. Only a real timeout
//! can.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// How long a test waits before declaring that an outbound request is
/// unbounded. Comfortably above any sane connect+read timeout a fix would
/// configure (the handoff spec proposes 2s connect / 5s total), and well
/// below the point where a hung request would be mistaken for a slow CI box.
const NO_TIMEOUT_BUDGET: Duration = Duration::from_secs(20);

/// How long a test waits for the Issuer Service's *asynchronous* delivery
/// task to reach a terminal state on `GET /requests/<id>`.
const DELIVERY_BUDGET: Duration = Duration::from_secs(10);

/// Boots this crate's real server on an ephemeral loopback port, with its
/// own `did:web` host pinned to that same port so both `state.identity` and
/// `state.sts_party` are genuinely resolvable by the service's own `reqwest`
/// client - the same pattern `nested_token_authorization.rs` establishes.
async fn spawn_service(mode: Mode) -> (Arc<AppState>, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the service under test");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let config = Config::for_test(mode, addr, format!("127.0.0.1:{}", addr.port()));
    let (state, router) = identity_hub_http::build(config);
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("service under test");
    });
    (state, format!("http://{addr}"))
}

/// A listener on `bind_host` that answers *any* method and path with `200
/// {}` and counts every request it receives. Standing in for whatever an
/// SSRF target actually is - an internal admin API, a metadata service, a
/// closed port's liveness signal - the only thing under test is whether this
/// service can be made to talk to it at all.
///
/// Returns the `host:port` it is reachable at and its hit counter.
async fn spawn_probe(bind_host: &str) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(format!("{bind_host}:0"))
        .await
        .expect("bind an ephemeral port for the SSRF probe target");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move || {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({}))
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("SSRF probe server");
    });
    (format!("{bind_host}:{}", addr.port()), hits)
}

/// A listener that completes the TCP handshake and then says nothing, ever,
/// holding every accepted connection open - the behaviour of a filtered
/// port, a wedged internal service, or (as the audit's live PoC found) a
/// cloud metadata endpoint reached from outside its expected context.
async fn spawn_black_hole(bind_host: &str) -> String {
    let listener = TcpListener::bind(format!("{bind_host}:0"))
        .await
        .expect("bind an ephemeral port for the black-hole target");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            // Never read, never write, never drop: the peer waits forever.
            held.push(stream);
        }
    });
    format!("{bind_host}:{}", addr.port())
}

fn sign(identity: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(
        &payload,
        &identity.key_pair.signing_key(),
        identity.own_key_id(),
    )
}

/// Mints the outer Self-Issued ID Token a caller presents. Its `iss` is the
/// signer's own DID, which is exactly the string `verify_bearer_token` feeds
/// to `resolve_did` *before* it has verified anything at all.
fn mint_outer_envelope(caller: &ServiceIdentity, audience: &str) -> String {
    let now = dcp_core::now_secs();
    sign(
        caller,
        json!({
            "iss": caller.own_did(),
            "sub": caller.own_did(),
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

async fn query(base: &str, bearer: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/presentations/query"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationQueryMessage",
            "scope": [MEMBERSHIP_SCOPE],
        }))
        .send()
        .await
        .expect("presentation query request completes")
}

/// RED - **Finding 4 (HIGH)**. An unauthenticated caller names a host this
/// service was never configured to talk to (`127.0.0.2:<ephemeral>`: a
/// different host string from the `127.0.0.1`/`host.docker.internal` this
/// service's own config and DNS override imply) inside the `iss` of a token
/// it then presents to `/presentations/query`. Today `verify_bearer_token`
/// hands that attacker-chosen string straight to `dcp_core::resolve_did`,
/// which does no host filtering, and the request goes out - before a single
/// signature has been checked. Whether the token is ultimately rejected is
/// beside the point: the outbound request itself *is* the vulnerability, and
/// its success/failure/hang is the oracle.
#[tokio::test]
async fn did_resolution_does_not_reach_an_unconfigured_host() {
    let (state, base) = spawn_service(Mode::CredentialService).await;
    let (probe_host, probe_hits) = spawn_probe("127.0.0.2").await;

    // The attacker controls this DID's host segment entirely - it is simply
    // whatever they wrote in their own `iss` claim.
    let attacker = ServiceIdentity::new(&probe_host, "attacker");
    let outer = mint_outer_envelope(&attacker, state.identity.own_did());

    let response = query(&base, &outer).await;
    assert!(
        response.status().is_client_error(),
        "a token signed by an unresolvable party must still be rejected"
    );

    assert_eq!(
        probe_hits.load(Ordering::SeqCst),
        0,
        "an unauthenticated caller made this service issue an HTTP request to \
         {probe_host}, a host no part of its configuration ever named - DID \
         resolution must be confined to explicitly allow-listed hosts"
    );
}

/// RED - **Finding 5 (HIGH)**. The Issuer Service's delivery step reads its
/// destination out of the requester's own DID document. Here the requester's
/// document is served from an allow-listed host (`127.0.0.1`, so resolution
/// itself is legitimate and the fix for Finding 4 cannot mask this one), but
/// its `CredentialService` `serviceEndpoint` points at `127.0.0.2:<ephemeral>` -
/// somewhere this service was never configured to send anything. Today
/// `try_deliver_issued_credential` POSTs a bearer-authenticated
/// `CredentialMessage` there without looking at the URL at all.
#[tokio::test]
async fn issued_credential_delivery_does_not_follow_a_service_endpoint_to_an_unconfigured_host() {
    use axum::Json;
    use axum::routing::get;

    let (state, base) = spawn_service(Mode::IssuerService).await;
    let (sink_host, sink_hits) = spawn_probe("127.0.0.2").await;

    // The holder's own DID document, hosted on an allow-listed host, but
    // advertising a delivery endpoint that is not.
    let holder_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the holder's DID server");
    let holder_addr = holder_listener
        .local_addr()
        .expect("bound listener has a local address");
    let holder = ServiceIdentity::new(&format!("127.0.0.1:{}", holder_addr.port()), "holder");
    let holder_doc = holder.did_document(&[("CredentialService", &format!("http://{sink_host}"))]);
    let holder_app = axum::Router::new().route(
        "/holder/did.json",
        get(move || {
            let doc = holder_doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(holder_listener, holder_app)
            .await
            .expect("holder DID server");
    });

    let si_token = mint_outer_envelope(&holder, state.identity.own_did());
    let response = reqwest::Client::new()
        .post(format!("{base}/credentials"))
        .header("Authorization", format!("Bearer {si_token}"))
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialRequestMessage",
            "holderPid": "holder-pid-ssrf",
            "credentials": [{"id": state.supported_credential.id}],
        }))
        .send()
        .await
        .expect("credential request completes");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::CREATED,
        "a well-formed, correctly signed credential request is accepted (the delivery \
         step it triggers is what this test is about)"
    );
    let request_path = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("credential request response carries a Location header")
        .to_string();

    // Wait for the asynchronous delivery task to reach a terminal state, so
    // the assertion below is about what delivery *did*, not about racing it.
    let deadline = std::time::Instant::now() + DELIVERY_BUDGET;
    loop {
        let status_body: Value = reqwest::Client::new()
            .get(format!("{base}{request_path}"))
            .send()
            .await
            .expect("credential request status request completes")
            .json()
            .await
            .expect("credential request status response is JSON");
        if status_body["status"] != json!("RECEIVED") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the credential request never left RECEIVED within {DELIVERY_BUDGET:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        sink_hits.load(Ordering::SeqCst),
        0,
        "the Issuer Service delivered an authenticated POST to {sink_host}, a destination \
         chosen purely by the requester's own DID document - a serviceEndpoint must be \
         validated against the same allow-list before anything is sent to it"
    );
}

/// RED - **Finding 6 (MEDIUM)**. The black hole sits on `127.0.0.1`, a host
/// this service's own configuration legitimately names, so the host
/// allow-list demanded by the two tests above cannot make this one pass
/// vacuously: resolution really is attempted, and only a configured timeout
/// can end it. Today `AppState::new` builds its `reqwest::Client` with
/// neither `.connect_timeout()` nor `.timeout()`, so the handler - and the
/// caller's connection with it - waits forever.
#[tokio::test]
async fn did_resolution_gives_up_on_a_host_that_never_responds() {
    let (state, base) = spawn_service(Mode::CredentialService).await;
    let black_hole_host = spawn_black_hole("127.0.0.1").await;

    let stalled = ServiceIdentity::new(&black_hole_host, "black-hole");
    let outer = mint_outer_envelope(&stalled, state.identity.own_did());

    let response = tokio::time::timeout(NO_TIMEOUT_BUDGET, query(&base, &outer))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "resolving a DID at {black_hole_host}, which accepts the connection and then \
                 never responds, did not return within {NO_TIMEOUT_BUDGET:?} - every outbound \
                 request needs a connect and total timeout"
            )
        });
    assert!(
        response.status().is_client_error(),
        "a DID that cannot be resolved must be rejected, not waited on"
    );
}
