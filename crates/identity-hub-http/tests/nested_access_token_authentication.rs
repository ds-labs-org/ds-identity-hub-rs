//! TDD coverage for the last two of the originally-documented 11 real DCP
//! TCK failures this bootstrap tracked - the "one gap, two severities" left
//! after `presentation_scope_enforcement.rs` closed
//! `cs_05_04_01_02_invalidScopeEscalationRequest`: the nested `token` claim
//! (the actual Verifiable-Presentation access token a caller forwards
//! inside its Self-Issued ID Token) had its own `scope` claim read and
//! enforced, but its **signature was never verified**, and nothing bound it
//! back to the outer envelope's own caller:
//!
//! - `cs_04_03_03_idTokenInvalidIssuerSub`
//!   (`org.eclipse.dataspacetck.dcp.verification.presentation.cs.PresentationFlowSection4Test`):
//!   a **confused-deputy forward**. Decompiled directly from the real
//!   `dcp-tck-runtime` image (no guessing from the test name): the outer
//!   Self-Issued ID Token envelope is `iss == sub == thirdPartyDid`,
//!   genuinely signed by the third party's own key, correctly audienced at
//!   this service - by every *outer-envelope* check this bootstrap already
//!   had, a perfectly valid request. What makes it invalid is the nested
//!   `token` claim: obtained via `@AuthToken`, which the TCK's own
//!   `DcpSystemLauncher.createAuthToken` always requests bound to
//!   `baseAssembly.getVerifierDid()` (`SecureTokenServerImpl.obtainReadToken`
//!   sets the minted access token's own `aud` claim to that requesting
//!   party's DID - confirmed by reading `SecureTokenServerImpl` directly).
//!   So the forwarded nested token's `aud` is the *verifier's* DID, not
//!   `thirdPartyDid` - it was minted for the verifier to present, and the
//!   third party is presenting it instead. A scope-only check (this
//!   bootstrap's pre-existing behavior) can't catch this: the forwarded
//!   token's `scope` claim is itself completely genuine.
//! - `cs_05_04_invalidTokenNotAuthorized`
//!   (`...cs.PresentationFlowSection5Test`): the outer envelope is
//!   perfectly valid (`iss == sub == verifierDid`, correctly signed and
//!   audienced), but its nested `token` claim is the literal string
//!   `"faketoken"` - not a JWS at all. Before this module's fix,
//!   `granted_credential_types` (`../src/handlers.rs`) failed to decode it
//!   and fell back to the old, pre-nested-token-checking default of *no*
//!   scope restriction - i.e. the request would *succeed*. Once nested-token
//!   authentication is a real, enforced step rather than a best-effort scope
//!   hint, an undecodable nested token must reject the whole request
//!   outright instead.
//!
//! Both are one underlying gap - `auth::verify_nested_access_token` (new in
//! this module's fix) genuinely authenticates the nested token (signature
//! verified against its own resolved `did:web` issuer, not expired) and
//! binds it back to the outer envelope's own caller (`aud` must equal the
//! outer envelope's `sub`) - any failure now rejects the whole request
//! (`401`), rather than silently degrading to unrestricted access.

use std::sync::Arc;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Boots this crate's real Credential Service (the system under test) on an
/// ephemeral loopback port. Unlike every sibling test file in this crate
/// (which use `Config::for_test`'s fixed, never-actually-dialed
/// `"localhost:0"` `did_host` - fine as long as nothing ever needs to
/// resolve the *service's own* DID over real HTTP), this module's fix
/// genuinely resolves `state.sts_party`'s own `did:web` document to verify
/// a nested access token's signature - so the listener is bound *first*,
/// and its real ephemeral port is threaded into `Config::for_test` as both
/// `bind_addr` (which `AppState::new` derives `sts_party`'s own `did:web`
/// host from) and `did_host`, so `state.identity`/`state.sts_party`'s own
/// DID documents are genuinely reachable at the address this test's
/// `reqwest` client will actually dial - the same pattern `dcp_tck.rs`
/// already establishes for the real TCK run, just on loopback instead of
/// `host.docker.internal`.
async fn spawn_credential_service() -> (Arc<AppState>, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the credential service under test");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let config = Config::for_test(
        Mode::CredentialService,
        addr,
        format!("127.0.0.1:{}", addr.port()),
    );
    let (state, router) = identity_hub_http::build(config);
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("credential service under test");
    });
    (state, format!("http://{addr}"))
}

/// A stand-in party this test controls a real keypair for, hosting its own
/// real `did:web` document on an ephemeral loopback port - used both for the
/// "outer caller" and the "verifier" role a nested access token is bound to,
/// exactly like `presentation_scope_enforcement.rs`'s own
/// `spawn_caller_identity`.
async fn spawn_identity(path_segment: &str) -> ServiceIdentity {
    use axum::Json;
    use axum::routing::get;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for a stand-in DID server");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), path_segment);
    let doc = identity.did_document(&[]);
    let route = format!("/{path_segment}/did.json");
    let app = axum::Router::new().route(
        &route,
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("stand-in DID server");
    });
    identity
}

fn sign(identity: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(
        &payload,
        &identity.key_pair.signing_key(),
        identity.own_key_id(),
    )
}

fn container(credential_type: &str, marker: &str) -> CredentialContainer {
    CredentialContainer {
        credential_type: credential_type.to_string(),
        payload: json!(marker),
        format: "jwt".to_string(),
    }
}

const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";
const MEMBERSHIP_MARKER: &str = "membership-vc-jws";

fn seed_membership_credential(state: &AppState) {
    state.store.store(StoredCredentialBatch {
        issuer_pid: "issuer-pid-membership".to_string(),
        holder_pid: Some("holder-pid".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![container("MembershipCredential", MEMBERSHIP_MARKER)],
    });
}

/// Mints a real, correctly-signed nested Verifiable-Presentation access
/// token - the exact shape this bootstrap's own embedded STS
/// (`identity_hub_core::sts::issue_token`) produces for its `token` claim -
/// but bound (`aud`) to whichever party the caller asks for, so a test can
/// mint one bound to a party *other* than whoever presents it (the
/// confused-deputy setup).
fn mint_access_token(sts_party: &ServiceIdentity, bound_to_did: &str, scope: &str) -> String {
    let now = dcp_core::now_secs();
    sign(
        sts_party,
        json!({
            "iss": sts_party.own_did(),
            "sub": sts_party.own_did(),
            "aud": bound_to_did,
            "scope": scope,
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

/// Mints the outer Self-Issued ID Token a querying caller presents,
/// forwarding `nested_token` (if any) as its `token` claim exactly as
/// `credential.issuance.protocol.md`/`base.protocol.md` describe.
fn mint_outer_envelope(
    caller: &ServiceIdentity,
    audience: &str,
    nested_token: Option<&str>,
) -> String {
    let now = dcp_core::now_secs();
    let mut payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(token) = nested_token {
        payload["token"] = json!(token);
    }
    sign(caller, payload)
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

/// RED (before this module's fix): `cs_04_03_03_idTokenInvalidIssuerSub`.
/// The outer envelope is perfectly valid and signed by `third_party`
/// (`iss == sub == thirdPartyDid`), but the nested access token it forwards
/// was minted bound to a *different* party (`verifier`'s DID, standing in
/// for the TCK's own `baseAssembly.getVerifierDid()`) - a forwarded token,
/// not a legitimate grant to whoever is actually presenting this request.
#[tokio::test]
async fn presentation_query_rejects_a_nested_token_forwarded_to_a_different_party() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let third_party = spawn_identity("third-party").await;
    let verifier = spawn_identity("verifier").await;

    // Minted for/bound to `verifier`, exactly like a genuine grant the
    // real STS would issue in response to `@AuthToken` - but it is
    // `third_party` who ends up presenting it.
    let nested = mint_access_token(&state.sts_party, verifier.own_did(), MEMBERSHIP_SCOPE);
    let outer = mint_outer_envelope(&third_party, state.identity.own_did(), Some(&nested));

    let response = query(&base, &outer).await;
    assert!(
        response.status().is_client_error(),
        "a nested access token minted for a different party must be rejected outright \
         (confused-deputy forward), got {}",
        response.status()
    );
}

/// RED (before this module's fix): `cs_05_04_invalidTokenNotAuthorized`. The
/// outer envelope is perfectly valid, but its nested `token` claim is the
/// literal string `"faketoken"` - not a real JWS at all. This must reject
/// the whole request, not silently fall back to unrestricted access (this
/// bootstrap's old, pre-nested-token-authentication default).
#[tokio::test]
async fn presentation_query_rejects_an_undecodable_nested_token() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let verifier = spawn_identity("verifier").await;

    let outer = mint_outer_envelope(&verifier, state.identity.own_did(), Some("faketoken"));

    let response = query(&base, &outer).await;
    assert!(
        response.status().is_client_error(),
        "an undecodable nested access token must reject the request outright, got {}",
        response.status()
    );
}

/// Regression guard: a nested access token that is genuinely well-formed,
/// correctly signed, not expired, and bound (`aud`) back to the very party
/// presenting it must still work exactly as before - authentication must
/// not reject a legitimate grant.
#[tokio::test]
async fn presentation_query_accepts_a_nested_token_bound_to_its_own_presenter() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let verifier = spawn_identity("verifier").await;

    let nested = mint_access_token(&state.sts_party, verifier.own_did(), MEMBERSHIP_SCOPE);
    let outer = mint_outer_envelope(&verifier, state.identity.own_did(), Some(&nested));

    let response = query(&base, &outer).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a nested token correctly bound to its own presenter must still succeed"
    );
}

/// Regression guard: an expired nested access token (well-formed and
/// correctly bound, but past its own `exp`) must also be rejected outright,
/// same as an undecodable one - authenticating a nested token means
/// checking it is actually still valid, not merely that it once was.
#[tokio::test]
async fn presentation_query_rejects_an_expired_nested_token() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let verifier = spawn_identity("verifier").await;

    let now = dcp_core::now_secs();
    let expired_nested = sign(
        &state.sts_party,
        json!({
            "iss": state.sts_party.own_did(),
            "sub": state.sts_party.own_did(),
            "aud": verifier.own_did(),
            "scope": MEMBERSHIP_SCOPE,
            "iat": now - 1000,
            "exp": now - 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    );
    let outer = mint_outer_envelope(&verifier, state.identity.own_did(), Some(&expired_nested));

    let response = query(&base, &outer).await;
    assert!(
        response.status().is_client_error(),
        "an expired nested access token must be rejected outright, got {}",
        response.status()
    );
}

/// Regression guard: a request with no nested `token` claim at all keeps
/// this bootstrap's pre-existing, deliberately permissive default (the
/// bare-outer-envelope case is not one of the two gaps this module closes -
/// see `presentation_scope_enforcement.rs`'s own identical guard).
#[tokio::test]
async fn presentation_query_without_a_nested_token_still_succeeds() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let verifier = spawn_identity("verifier").await;

    let outer = mint_outer_envelope(&verifier, state.identity.own_did(), None);

    let response = query(&base, &outer).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
