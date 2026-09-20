//! RED coverage for the read-authorization model behind three findings of
//! the 2026-09-20 independent security audit of this project. All three are
//! the *same* underlying defect seen from three sides: the Presentation API
//! treats the caller's nested `token` claim as an **authentication** artifact
//! only, and never asks whether whoever minted it had any authority to grant
//! read access to *this* service's credentials.
//!
//! `nested_access_token_authentication.rs` (the previous change) made the
//! nested token genuinely *authentic* - signature verified against its own
//! resolved `did:web` issuer, not expired, bound back (`aud`) to the outer
//! envelope's own caller. Every one of those checks is necessary and stays.
//! None of them is *authorization*:
//!
//! - **Finding 1 (CRITICAL) - read-auth bypass by omission.**
//!   `handlers::granted_credential_types` opens with
//!   `let Some(nested_token) = claims.get("token") ... else { return Ok(None) }`,
//!   and `presentation_query` reads `Ok(None)` as "no restriction". A caller
//!   that simply *omits* the `token` claim is therefore handed every stored
//!   credential matching whatever type it asked for. The weakest possible
//!   request wins: presenting no grant at all beats presenting a narrow one.
//!   A missing grant must mean *no* access, not *all* access.
//! - **Finding 2 (CRITICAL) - a self-asserted grant is not authority.**
//!   `auth::verify_nested_access_token` checks that the nested token decodes,
//!   that its signature verifies against *its own* `iss`'s resolved DID
//!   document, that it has not expired, and that its `aud` equals the outer
//!   envelope's `sub`. Every one of those is satisfiable by an attacker who
//!   hosts their own `did:web` document: mint `{iss: sub: <own did>,
//!   aud: <own did>, scope: "<anything>", exp: <future>}`, sign it with your
//!   own key, wrap it in a matching outer envelope, and you have granted
//!   yourself whatever scope you cared to type. Verifying *who signed* a
//!   grant is not the same as verifying *that the signer could grant it*.
//! - **Finding 9 (MEDIUM, and the reason the correct fix is not simply
//!   "reject more") - this hub's own STS mints tokens its own verifier
//!   always rejects.** `identity_hub_core::sts::issue_token` sets the nested
//!   access token's `aud` to `req.audience`, while
//!   `auth::verify_nested_access_token` requires that `aud` to equal the
//!   *outer* envelope's `sub`. For a token this hub's own `/sts/token`
//!   minted and a caller presents as-is, the outer `sub` is always
//!   `state.sts_party`'s DID while the nested `aud` is `req.audience`, which
//!   `verify_bearer_token` separately forces to be this service's *own* DID -
//!   so the two can never both hold. The one flow that ought to be the
//!   textbook legitimate case is a guaranteed `401`, which is precisely why
//!   the bypass in Finding 1 is load-bearing rather than theoretical: the
//!   only way to actually get a presentation out of this service today is to
//!   present no grant at all.
//!
//! Not guessed from the finding text: the real TCK's own
//! `SecureTokenServerImpl.obtainReadToken(bearerDid, scopes)` calls
//! `requestRemoteAccessToken(stsUrl, ..., audience = bearerDid, ...)` against
//! *this* hub's `/sts/token` (`dataspacetck.sts.url` in
//! `tests/dcp.tck.properties`), extracts only the nested `token` claim out of
//! the response, and `DcpSystemLauncher.createAuthToken` passes
//! `baseAssembly.getVerifierDid()` as that `bearerDid` -
//! `AbstractPresentationFlowTest.createIdToken` then wraps it in an outer
//! envelope whose `iss`/`sub` is that same verifier DID. Two consequences
//! matter for whoever implements the fix, and both were read off the
//! decompiled TCK runtime rather than assumed:
//!
//! 1. Every nested access token the TCK ever presents was minted by **this
//!    hub's own STS**, so its `iss` is `state.sts_party`'s DID - an
//!    authoritative-issuer check against `sts_party` cannot regress the
//!    54/54 conformance baseline.
//! 2. Every TCK presentation test passes an `@AuthToken`-derived nested
//!    token; not one of them presents a bare outer envelope and expects a
//!    successful presentation - so denying by default cannot regress it
//!    either.
//!
//! See the handoff spec accompanying this change for the exact rule each
//! test expects.

use std::sync::Arc;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";
const MEMBERSHIP_MARKER: &str = "membership-vc-jws";

/// Boots this crate's real Credential Service on an ephemeral loopback port,
/// with its own `did:web` host pinned to that same port so both
/// `state.identity` and `state.sts_party` are genuinely resolvable by the
/// service's own `reqwest` client - the same pattern
/// `nested_access_token_authentication.rs` establishes.
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
/// real `did:web` document on an ephemeral loopback port. Used for the
/// ordinary caller and - the point of `presentation_query_rejects_a_nested_token_self_signed_by_an_untrusted_party` -
/// for an attacker who hosts a perfectly well-formed `did:web` document of
/// their own.
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

fn seed_membership_credential(state: &AppState) {
    state.store.store(StoredCredentialBatch {
        issuer_pid: "issuer-pid-membership".to_string(),
        holder_pid: Some("holder-pid".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![CredentialContainer {
            credential_type: "MembershipCredential".to_string(),
            payload: json!(MEMBERSHIP_MARKER),
            format: "jwt".to_string(),
        }],
    });
}

/// Mints the outer Self-Issued ID Token a querying caller presents,
/// optionally forwarding `nested_token` as its `token` claim.
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

/// The credential payload markers carried by a 2xx
/// `PresentationResponseMessage`, so a test can assert on *what was handed
/// back* rather than only on the status code - the difference between "the
/// request was refused" and "the request succeeded but disclosed nothing".
async fn returned_markers(response: reqwest::Response) -> Vec<String> {
    let body: Value = response
        .json()
        .await
        .expect("successful presentation response is JSON");
    let presentation = body["presentation"]
        .as_array()
        .expect("presentation array")
        .clone();
    presentation
        .iter()
        .flat_map(|vp| {
            let vp_jws = vp.as_str().expect("presentation entry is a JWS string");
            let (_, _, vp_payload) = dcp_core::decode_jws_unverified(vp_jws).expect("valid VP JWS");
            vp_payload["vp"]["verifiableCredential"]
                .as_array()
                .expect("verifiableCredential array")
                .iter()
                .map(|v| v.as_str().expect("marker payload is a string").to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Asserts that a response disclosed no credential at all: either it was
/// refused outright (4xx) or it succeeded with an empty presentation. Which
/// of the two a fix picks is an implementation choice; disclosing the seeded
/// credential is not.
async fn assert_disclosed_nothing(response: reqwest::Response, context: &str) {
    let status = response.status();
    if status.is_client_error() {
        return;
    }
    assert!(status.is_success(), "{context}: unexpected status {status}");
    let markers = returned_markers(response).await;
    assert!(
        markers.is_empty(),
        "{context}: the request disclosed {markers:?} with no verifiable grant to justify it"
    );
}

/// RED - **Finding 1 (CRITICAL)**. A caller presents a perfectly valid outer
/// Self-Issued ID Token and simply omits the nested `token` claim. Today
/// `granted_credential_types` returns `Ok(None)`, `presentation_query` reads
/// that as "no restriction", and the caller is handed the seeded
/// `MembershipCredential`'s full payload. Omitting a grant must never be
/// more powerful than presenting one: with nothing to authorize the read,
/// the correct default is no access.
#[tokio::test]
async fn presentation_query_without_a_nested_token_discloses_nothing() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let caller = spawn_identity("caller").await;

    let outer = mint_outer_envelope(&caller, state.identity.own_did(), None);

    let response = query(&base, &outer).await;
    assert_disclosed_nothing(response, "a bare outer envelope carrying no nested grant").await;
}

/// RED - **Finding 2 (CRITICAL)**. The attacker hosts their own, entirely
/// well-formed `did:web` document and mints their own nested access token
/// with it: `iss == sub == <attacker did>`, `aud == <attacker did>` (so the
/// binding check back to the outer envelope's `sub` passes), a `scope` they
/// simply wrote themselves, and a future `exp`. Every check
/// `verify_nested_access_token` performs today passes, because every one of
/// them is about the token's *authenticity*, not about the issuer's
/// *authority*. Only a grant issued by a party this service actually
/// recognizes as authoritative over its own credentials may grant anything.
#[tokio::test]
async fn presentation_query_rejects_a_nested_token_self_signed_by_an_untrusted_party() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);
    let attacker = spawn_identity("attacker").await;

    let now = dcp_core::now_secs();
    let self_granted = sign(
        &attacker,
        json!({
            "iss": attacker.own_did(),
            "sub": attacker.own_did(),
            "aud": attacker.own_did(),
            "scope": MEMBERSHIP_SCOPE,
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    );
    let outer = mint_outer_envelope(&attacker, state.identity.own_did(), Some(&self_granted));

    let response = query(&base, &outer).await;
    assert_disclosed_nothing(
        response,
        "a nested access token an arbitrary did:web party minted for itself",
    )
    .await;
}

/// RED - **Finding 9 (MEDIUM)**, the legitimate-use side of the same model.
/// This obtains a token from this hub's own real `/sts/token` endpoint with
/// the real configured client credentials and a `bearer_access_scope`, then
/// presents that token - unmodified, exactly as the STS handed it over - to
/// `/presentations/query`. Today the request is refused with `401 nested
/// access token is not bound to the party presenting it`, because
/// `sts::issue_token` binds the nested token's `aud` to `req.audience` (which
/// `verify_bearer_token` separately forces to be this service's own DID)
/// while `verify_nested_access_token` compares that `aud` against the outer
/// envelope's `sub` (always `state.sts_party`'s DID). A hub whose own STS
/// cannot mint a token its own Presentation API accepts has no working
/// authorized path at all - which is exactly what makes the unauthorized one
/// in Finding 1 the only path that works.
#[tokio::test]
async fn a_token_from_this_hubs_own_sts_is_accepted_by_its_own_presentation_api() {
    let (state, base) = spawn_credential_service().await;
    seed_membership_credential(&state);

    let sts_response = reqwest::Client::new()
        .post(format!("{base}/sts/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", state.config.sts_client_id.as_str()),
            ("client_secret", state.config.sts_client_secret.as_str()),
            ("audience", state.identity.own_did()),
            ("bearer_access_scope", MEMBERSHIP_SCOPE),
        ])
        .send()
        .await
        .expect("sts token request completes");
    assert_eq!(
        sts_response.status(),
        reqwest::StatusCode::OK,
        "this hub's own STS must mint a token for its own configured client credentials"
    );
    let sts_body: Value = sts_response.json().await.expect("sts response is JSON");
    let access_token = sts_body["access_token"]
        .as_str()
        .expect("sts response carries an access_token");

    let response = query(&base, access_token).await;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a token this hub's own STS minted, presented unmodified to this hub's own \
         Presentation API, must be accepted - got {status}: {body}"
    );

    let parsed: Value = serde_json::from_str(&body).expect("successful response is JSON");
    let vp_jws = parsed["presentation"][0]
        .as_str()
        .expect("presentation entry is a JWS string");
    let (_, _, vp_payload) = dcp_core::decode_jws_unverified(vp_jws).expect("valid VP JWS");
    let markers: Vec<String> = vp_payload["vp"]["verifiableCredential"]
        .as_array()
        .expect("verifiableCredential array")
        .iter()
        .map(|v| v.as_str().expect("marker payload is a string").to_string())
        .collect();
    assert_eq!(
        markers,
        vec![MEMBERSHIP_MARKER.to_string()],
        "the STS token's own bearer_access_scope grants MembershipCredential, so the \
         presentation must actually carry it"
    );
}
