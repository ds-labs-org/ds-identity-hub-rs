//! TDD coverage for the last of the originally-documented 36 real DCP TCK
//! failures this bootstrap tracked: `cs_05_04_01_02_invalidScopeEscalationRequest`
//! (`org.eclipse.dataspacetck.dcp.verification.presentation.cs.PresentationFlowSection5Test`).
//!
//! Read directly from the real `dcp-tck-runtime` image's own bytecode
//! (`javap` on the extracted `PresentationFlowSection5Test`/
//! `AbstractPresentationFlowTest`/`SecureTokenServerImpl` classes - no
//! guessing), the test's actual shape is *not* "reject the whole request
//! with a 4xx when scope exceeds what was granted" (a plausible-sounding
//! guess this module's own name invites): it's a **silent filter to the
//! intersection**, on an otherwise-successful (`2xx`) response.
//! `PresentationFlowSection5Test.cs_05_04_01_02_invalidScopeEscalationRequest`:
//!
//! - `@IssueCredentials(["MembershipCredential", "SensitiveDataCredential"])`
//!   pre-loads both credential types into the Credential Service's store.
//! - `@AuthToken(["org.eclipse.dspace.dcp.vc.type:MembershipCredential"])`
//!   has the TCK's harness call this service's own `/sts/token` (see
//!   `SecureTokenServerImpl.obtainReadToken`/`requestRemoteAccessToken` in
//!   the real TCK) with `bearer_access_scope` set to *only* that one scope
//!   alias, and extracts the resulting Self-Issued ID Token's own nested
//!   `token` claim (a real access-token JWS, itself carrying a `scope`
//!   claim) - this is the caller's actual **granted** scope.
//! - The `PresentationQueryMessage` itself then requests `scope: [scopeFor
//!   ("MembershipCredential"), scopeFor("SensitiveDataCredential")]` - both
//!   types, escalating beyond what was granted.
//! - `verifyCredentials(response, "MembershipCredential")` asserts the
//!   response `isSuccessful()` (2xx) *and* that the returned Verifiable
//!   Presentation's credential types are `containsOnly`
//!   `{"VerifiableCredential", "MembershipCredential"}` - i.e.
//!   `SensitiveDataCredential`, despite being both requested and actually
//!   in the store, must be silently omitted, not returned and not the
//!   reason for an error response.
//!
//! Before this module's fix, `presentation_query` (`crate::handlers`)
//! looked up stored credentials purely by the *requested* `scope` -
//! confirmed red below: a caller granted only `MembershipCredential` who
//! requests both types back gets both, including one it was never
//! authorized to read.

use std::sync::Arc;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Boots this crate's real Credential Service (the system under test) on an
/// ephemeral loopback port - the same shape `si_token_validation.rs` and
/// `storage_offer_auth.rs` already establish. The listener is bound
/// *before* `Config::for_test` so the real ephemeral port can be threaded
/// into it as `bind_addr` (`AppState::new` derives `state.sts_party`'s own
/// `did:web` host from `bind_addr`'s port) - required since
/// `nested_access_token_authentication.rs`'s fix made `state.sts_party`'s
/// DID genuinely resolved over real HTTP (to verify a nested access
/// token's signature), not just compared as an opaque string.
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

async fn spawn_caller_identity(path_segment: &str) -> ServiceIdentity {
    use axum::Json;
    use axum::routing::get;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the stand-in caller DID server");
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
            .expect("stand-in caller DID server");
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
const SENSITIVE_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:SensitiveDataCredential";
const MEMBERSHIP_MARKER: &str = "membership-vc-jws";
const SENSITIVE_MARKER: &str = "sensitive-vc-jws";

/// Seeds the store exactly like the real TCK's own
/// `@IssueCredentials(["MembershipCredential", "SensitiveDataCredential"])`
/// setup step does (via the Storage API, in the real TCK run) - both types
/// genuinely present and `ISSUED`.
fn seed_both_credential_types(state: &AppState) {
    state.store.store(StoredCredentialBatch {
        issuer_pid: "issuer-pid-membership".to_string(),
        holder_pid: Some("holder-pid".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![container("MembershipCredential", MEMBERSHIP_MARKER)],
    });
    state.store.store(StoredCredentialBatch {
        issuer_pid: "issuer-pid-sensitive".to_string(),
        holder_pid: Some("holder-pid".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![container("SensitiveDataCredential", SENSITIVE_MARKER)],
    });
}

/// Mints a nested Verifiable-Presentation access token exactly the shape
/// this bootstrap's own embedded STS (`identity_hub_core::sts::issue_token`)
/// produces for its `token` claim when `bearer_access_scope` is requested -
/// signed by the STS-party identity, `scope` set to whatever was granted
/// (space-delimited when more than one, per `SecureTokenServerImpl`'s own
/// `String.join(" ", scopes)` in the real TCK - RFC 6749 ยง3.3's own
/// scope-string convention), and `aud` bound to `bound_to_did` - the party
/// this grant is actually for (matches the real TCK's own
/// `SecureTokenServerImpl.obtainReadToken`, which always requests the
/// nested token's `aud` set to whichever party will present it - see
/// `nested_access_token_authentication.rs`'s module doc for the full
/// decompiled trace). Since `presentation_query_rejects_a_nested_token_forwarded_to_a_different_party`
/// (that module) now enforces this binding, every caller here must pass its
/// own DID.
fn mint_granted_access_token(state: &AppState, bound_to_did: &str, granted_scope: &str) -> String {
    let now = dcp_core::now_secs();
    sign(
        &state.sts_party,
        json!({
            "iss": state.sts_party.own_did(),
            "sub": state.sts_party.own_did(),
            "aud": bound_to_did,
            "scope": granted_scope,
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

async fn query(base: &str, bearer: &str, scope: &[&str]) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/presentations/query"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationQueryMessage",
            "scope": scope,
        }))
        .send()
        .await
        .expect("presentation query request completes")
}

/// Extracts the set of `type` entries (minus the boilerplate
/// `"VerifiableCredential"` marker every VC carries) actually present in a
/// `PresentationResponseMessage`'s wrapped VP - here, simply which of our
/// two marker payload strings appear, since this bootstrap's
/// `build_presentation` copies each stored container's `payload` verbatim
/// into `vp.verifiableCredential` (see `handlers::build_presentation`).
async fn returned_markers(response: reqwest::Response) -> Vec<String> {
    let body: Value = response.json().await.expect("valid JSON response body");
    let presentation = body["presentation"]
        .as_array()
        .expect("presentation array")
        .clone();
    assert_eq!(
        presentation.len(),
        1,
        "this bootstrap always wraps every matched credential in one VP"
    );
    let vp_jws = presentation[0]
        .as_str()
        .expect("presentation entry is a JWS string");
    let (_, _, vp_payload) = dcp_core::decode_jws_unverified(vp_jws).expect("valid VP JWS");
    vp_payload["vp"]["verifiableCredential"]
        .as_array()
        .expect("verifiableCredential array")
        .iter()
        .map(|v| v.as_str().expect("marker payload is a string").to_string())
        .collect()
}

/// RED (before this module's fix): a caller whose nested access token
/// grants only `MembershipCredential` requests `scope` for both
/// `MembershipCredential` and `SensitiveDataCredential` (both genuinely
/// `ISSUED` and present in the store). The DCP TCK's own
/// `cs_05_04_01_02_invalidScopeEscalationRequest` expects a *successful*
/// response containing only `MembershipCredential` - `SensitiveDataCredential`
/// must never be handed back even though it was both requested and stored.
#[tokio::test]
async fn presentation_query_filters_response_to_the_tokens_own_granted_scope() {
    let (state, base) = spawn_credential_service().await;
    seed_both_credential_types(&state);
    let caller = spawn_caller_identity("holder").await;

    let nested = mint_granted_access_token(&state, caller.own_did(), MEMBERSHIP_SCOPE);
    let outer = mint_outer_envelope(&caller, state.identity.own_did(), Some(&nested));

    let response = query(&base, &outer, &[MEMBERSHIP_SCOPE, SENSITIVE_SCOPE]).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a scope-escalation attempt must be silently filtered, not rejected outright - \
         verifyCredentials in the real TCK asserts isSuccessful()"
    );
    let markers = returned_markers(response).await;
    assert_eq!(
        markers,
        vec![MEMBERSHIP_MARKER.to_string()],
        "only the credential type actually granted by the token's own nested scope \
         may be returned, even though SensitiveDataCredential was both requested and stored"
    );
}

/// Regression guard: when the token's own granted scope already covers
/// everything requested (the ordinary, non-escalating case), nothing
/// should be filtered out - matches the real TCK's own
/// `cs_05_04_01_02_lessScopesThanAuthorizedByTypeRequest` /
/// `cs_05_04_01_02_scopeByTypeRequest`, both already passing before this
/// change and which must keep passing after it.
#[tokio::test]
async fn presentation_query_returns_everything_within_a_broad_grant() {
    let (state, base) = spawn_credential_service().await;
    seed_both_credential_types(&state);
    let caller = spawn_caller_identity("holder").await;

    // Granted scope covers both types (space-delimited, matching the real
    // TCK's own SecureTokenServerImpl.obtainReadToken /
    // `String.join(" ", scopes)` when more than one scope is granted).
    let nested = mint_granted_access_token(
        &state,
        caller.own_did(),
        &format!("{MEMBERSHIP_SCOPE} {SENSITIVE_SCOPE}"),
    );
    let outer = mint_outer_envelope(&caller, state.identity.own_did(), Some(&nested));

    let response = query(&base, &outer, &[MEMBERSHIP_SCOPE, SENSITIVE_SCOPE]).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let mut markers = returned_markers(response).await;
    markers.sort();
    let mut expected = vec![MEMBERSHIP_MARKER.to_string(), SENSITIVE_MARKER.to_string()];
    expected.sort();
    assert_eq!(markers, expected);
}

/// Regression guard: a caller with no nested `token` claim at all (this
/// bootstrap's pre-existing, unauthenticated-scope behavior - see
/// `../../ARCHITECTURE.md`'s "No nested-access-token validation") is not
/// newly broken by this change: with nothing to check the requested scope
/// against, the existing requested-type-only lookup still applies. This is
/// a deliberate, documented default (see this module's own top doc
/// comment), not evidence a bare outer envelope should ever be trusted
/// with a real access grant in a production deployment.
#[tokio::test]
async fn presentation_query_without_a_nested_token_keeps_the_pre_existing_behavior() {
    let (state, base) = spawn_credential_service().await;
    seed_both_credential_types(&state);
    let caller = spawn_caller_identity("holder").await;

    let outer = mint_outer_envelope(&caller, state.identity.own_did(), None);

    let response = query(&base, &outer, &[MEMBERSHIP_SCOPE]).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let markers = returned_markers(response).await;
    assert_eq!(markers, vec![MEMBERSHIP_MARKER.to_string()]);
}
