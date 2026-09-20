//! Benchmark-only helper: plays the DCP "verifier" role against a running
//! `ds-identity-hub-rs` Credential Service, so `bench/`'s k6 load test has a
//! real, genuinely-authenticated bearer token to send to `POST
//! /presentations/query` - see `bench/README.md` for the full picture and
//! why this can't just call the target's own embedded STS once and be done.
//!
//! ## Why a whole extra process, not just a curl one-liner
//!
//! `identity_hub_http::auth::verify_bearer_token` requires the outer
//! Self-Issued ID Token's `iss`/`sub` to be a `did:web` DID this process can
//! itself resolve over HTTP (see `crates/identity-hub-http/src/auth.rs`).
//! The target's own embedded STS only ever signs as its own `sts_party`
//! identity - there is no way to make it sign as an arbitrary external
//! caller. So this binary generates and *hosts* its own real `did:web`
//! identities (an "issuer" and a "verifier", exactly the roles
//! `crates/identity-hub-http/tests/nested_access_token_authentication.rs`
//! spins up in-process for its own tests) and plays the same choreography
//! externally, over real HTTP, against a real running server:
//!
//! 1. At startup: seeds one credential into the target via its Storage API,
//!    signed by this process's own "issuer" identity.
//! 2. `GET /mint` on this process's own tiny HTTP server: fetches a nested
//!    Verifiable-Presentation access token from the target's STS (bound to
//!    this process's own "verifier" DID), then wraps it in a fresh outer
//!    Self-Issued ID Token signed by that same "verifier" key, and returns
//!    it - the exact recipe `nested_access_token_authentication.rs`'s
//!    `presentation_query_accepts_a_nested_token_bound_to_its_own_presenter`
//!    regression guard proves the target accepts.
//!
//! This process must keep running for the *entire* k6 load test window
//! (warmup and measured run alike): the target resolves the caller's
//! `did:web` document on every single `/presentations/query` call (no
//! caching - see `../../ARCHITECTURE.md`), so the "verifier" identity's DID
//! document must stay resolvable throughout. The target's own STS-minted
//! tokens are fixed at a 300-second TTL
//! (`identity_hub_core::sts::TOKEN_TTL_SECS`, not configurable) - `GET
//! /mint` is called fresh immediately before each k6 run specifically so
//! that constraint is a non-issue, rather than racing a single token
//! against the whole benchmark's wall-clock duration.
//!
//! ## `GET /mint-batch?n=<count>` - why one token per k6 request, not one for the whole run
//!
//! Unlike EDC IdentityHub's leg of this benchmark (which reuses ONE fixed
//! bearer token for an entire k6 run - EDC's own
//! `edc.iam.accesstoken.jti.validation` is disabled in the environment this
//! benchmark's sibling `dcp-test-env` documents), `verify_bearer_token`'s
//! `jti`-replay protection is always on here and cannot be disabled - it is
//! a real, permanent security feature this project just finished closing
//! the last TCK gaps for (see `../../ARCHITECTURE.md`'s "DCP TCK conformance
//! snapshot"), not a bootstrap artifact to work around. Reusing one token
//! for an entire k6 run would succeed exactly once and then reject every
//! subsequent request with `401` (replay). `GET /mint-batch?n=<count>`
//! mints `count` distinct, genuinely valid tokens in one call - each with
//! its own fresh `jti`, all wrapping the SAME nested access token (safe:
//! the nested token has no `jti`-replay check of its own, only the outer
//! envelope does - see [`fetch_nested_token`]'s doc comment) - and returns
//! them one per line so `bench-rust.sh` can pre-mint a large pool before
//! each k6 run and hand every iteration a token no other iteration in the
//! same run will ever reuse. Signing is parallelized across every available
//! core (`std::thread::scope` in [`mint_batch`]) since a single core only
//! manages ~5,000 signs/s, too slow to mint the hundreds of thousands of
//! tokens a real 20-VU/30s run needs in reasonable wall-clock time.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::{CredentialContainer, CredentialMessage, DCP_CONTEXT};
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "verifier-token")]
struct Args {
    /// Base URL of the running Credential Service under test, e.g.
    /// `http://127.0.0.1:8080`.
    #[arg(long)]
    target_base_url: String,
    /// The target's own `did:web` DID, e.g.
    /// `did:web:127.0.0.1%3A8080:credential-service`.
    #[arg(long)]
    target_did: String,
    #[arg(long, default_value = "tck-client")]
    sts_client_id: String,
    #[arg(long, default_value = "tck-secret")]
    sts_client_secret: String,
    /// DCP scope alias to request/grant, e.g.
    /// `org.eclipse.dspace.dcp.vc.type:MembershipCredential`.
    #[arg(long)]
    scope: String,
    /// Credential type to seed and to embed in the granted scope's matching
    /// credential, e.g. `MembershipCredential`.
    #[arg(long)]
    credential_type: String,
    /// `host:port` this process's own "issuer"/"verifier" DIDs are
    /// externally reachable at - must be what the target can actually
    /// resolve `did:web:<this, %3A-encoded>:issuer`/`:verifier` at.
    #[arg(long)]
    host: String,
    /// Address this process's own HTTP server binds.
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long, default_value = "bench-holder-pid")]
    holder_pid: String,
    #[arg(long, default_value = "bench-issuer-pid")]
    issuer_pid: String,
}

struct MintState {
    http: reqwest::Client,
    target_base_url: String,
    target_did: String,
    sts_client_id: String,
    sts_client_secret: String,
    scope: String,
    verifier: ServiceIdentity,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let issuer = ServiceIdentity::new(&args.host, "issuer");
    let verifier = ServiceIdentity::new(&args.host, "verifier");
    println!("issuer DID:   {}", issuer.own_did());
    println!("verifier DID: {}", verifier.own_did());

    let http = reqwest::Client::new();
    let state = Arc::new(MintState {
        http: http.clone(),
        target_base_url: args.target_base_url.clone(),
        target_did: args.target_did.clone(),
        sts_client_id: args.sts_client_id.clone(),
        sts_client_secret: args.sts_client_secret.clone(),
        scope: args.scope.clone(),
        verifier: verifier.clone(),
    });

    let issuer_doc = issuer.did_document(&[]);
    let verifier_doc = verifier.did_document(&[]);
    let app = Router::new()
        .route(
            "/issuer/did.json",
            get(move || {
                let doc = issuer_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/verifier/did.json",
            get(move || {
                let doc = verifier_doc.clone();
                async move { Json(doc) }
            }),
        )
        .route("/mint", get(mint_handler))
        .route("/mint-batch", get(mint_batch_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());

    let listener = TcpListener::bind(args.bind).await?;
    println!("verifier-token DID-hosting server listening on {}", args.bind);
    let serve_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("verifier-token DID server");
    });

    // Wait until our own DID documents are actually resolvable over real
    // HTTP before seeding - the target will do exactly this same GET the
    // moment we call its Storage API.
    let self_base = format!("http://{}", args.bind);
    wait_until_ready(&http, &format!("{self_base}/issuer/did.json")).await?;

    seed_credential(
        &http,
        &args,
        &issuer,
        &args.credential_type,
        &args.holder_pid,
        &args.issuer_pid,
    )
    .await?;
    println!(
        "seeded 1 '{}' credential into {} (issuerPid={}, holderPid={})",
        args.credential_type, args.target_base_url, args.issuer_pid, args.holder_pid
    );
    println!("ready: GET http://{}/mint for a fresh presentation-query bearer token", args.bind);

    serve_handle.await?;
    Ok(())
}

async fn wait_until_ready(http: &reqwest::Client, url: &str) -> anyhow::Result<()> {
    for attempt in 0..50 {
        if let Ok(resp) = http.get(url).send().await
            && resp.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if attempt == 49 {
            anyhow::bail!("verifier-token's own DID server never became ready at {url}");
        }
    }
    Ok(())
}

/// Signs a real VC JWT (issuer identity) and delivers it to the target's
/// Storage API, authenticated with a Self-Issued ID Token minted by the
/// *target's own* embedded STS (audience = the target's own DID - exactly
/// what `verify_bearer_token` requires, no separate identity needed for
/// this call since we're not claiming to be anyone in particular here,
/// only delivering a message the target's permissive default - empty
/// `trusted_issuer_dids`/`known_holder_pids` - already accepts).
async fn seed_credential(
    http: &reqwest::Client,
    args: &Args,
    issuer: &ServiceIdentity,
    credential_type: &str,
    holder_pid: &str,
    issuer_pid: &str,
) -> anyhow::Result<()> {
    let now = dcp_core::now_secs();
    let vc_payload = json!({
        "iss": issuer.own_did(),
        "sub": format!("did:example:{holder_pid}"),
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", credential_type],
            "credentialSubject": { "id": format!("did:example:{holder_pid}") },
        },
        "iat": now,
        "nbf": now,
        "exp": now + 3600 * 24 * 365,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let vc_jwt = dcp_core::sign_jws(&vc_payload, &issuer.key_pair.signing_key(), issuer.own_key_id());

    let container = CredentialContainer {
        credential_type: credential_type.to_string(),
        payload: json!(vc_jwt),
        format: "jwt".to_string(),
    };
    let message = CredentialMessage {
        context: vec![DCP_CONTEXT.to_string()],
        message_type: "CredentialMessage".to_string(),
        issuer_pid: issuer_pid.to_string(),
        holder_pid: holder_pid.to_string(),
        status: "ISSUED".to_string(),
        credentials: vec![container],
        rejection_reason: None,
    };

    let storage_token = sts_token(
        http,
        &args.target_base_url,
        &args.sts_client_id,
        &args.sts_client_secret,
        &args.target_did,
        None,
    )
    .await?;

    let response = http
        .post(format!("{}/credentials", args.target_base_url))
        .bearer_auth(storage_token)
        .json(&message)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Storage API seeding failed: HTTP {status}: {body}");
    }
    Ok(())
}

/// Calls the target's real `POST /sts/token`, exactly per
/// `identity_hub_core::sts`'s own `StsTokenRequest` shape.
async fn sts_token(
    http: &reqwest::Client,
    target_base_url: &str,
    sts_client_id: &str,
    sts_client_secret: &str,
    audience: &str,
    bearer_access_scope: Option<&str>,
) -> anyhow::Result<String> {
    let mut form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", sts_client_id.to_string()),
        ("client_secret", sts_client_secret.to_string()),
        ("audience", audience.to_string()),
    ];
    if let Some(scope) = bearer_access_scope {
        form.push(("bearer_access_scope", scope.to_string()));
    }
    let response = http
        .post(format!("{target_base_url}/sts/token"))
        .form(&form)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("STS token request failed: HTTP {status}: {body}");
    }
    let body: Value = response.json().await?;
    Ok(body["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("STS response had no access_token"))?
        .to_string())
}

/// `GET /mint` - see this module's doc comment for the full recipe. Returns
/// `{"token": "<bearer token, without the 'Bearer ' prefix>"}`.
async fn mint_handler(State(state): State<Arc<MintState>>) -> Response {
    match mint(&state).await {
        Ok(token) => Json(json!({"token": token})).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mint failed: {err}"),
        )
            .into_response(),
    }
}

/// Fetches ONE nested Verifiable-Presentation access token from the
/// target's own STS, bound (`aud`) to our verifier's own DID - the same
/// shape `identity_hub_core::sts::issue_token` produces for its `token`
/// claim. This nested token has no `jti`-replay check on the target
/// (`auth::verify_nested_access_token` never touches `state.seen_jti` - only
/// the *outer* envelope's own `jti` is tracked, in
/// `auth::verify_bearer_token`), so a single nested token is safe to wrap in
/// many distinct outer envelopes - see [`mint_batch`]'s doc comment for why
/// that matters.
async fn fetch_nested_token(state: &MintState) -> anyhow::Result<String> {
    let outer_from_target = sts_token(
        &state.http,
        &state.target_base_url,
        &state.sts_client_id,
        &state.sts_client_secret,
        state.verifier.own_did(),
        Some(&state.scope),
    )
    .await?;
    let (_, _, outer_payload) = dcp_core::decode_jws_unverified(&outer_from_target)
        .map_err(|e| anyhow::anyhow!("could not decode target STS response: {e}"))?;
    outer_payload
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("target STS response had no nested token claim"))
}

/// Wraps `nested_token` in a fresh outer Self-Issued ID Token, signed by our
/// verifier identity, addressed to the target's own DID, with a brand new
/// `jti` - exactly `mint_outer_envelope` in
/// `nested_access_token_authentication.rs`.
fn mint_outer_envelope(state: &MintState, nested_token: &str) -> String {
    let now = dcp_core::now_secs();
    let outer_payload = json!({
        "iss": state.verifier.own_did(),
        "sub": state.verifier.own_did(),
        "aud": state.target_did,
        "iat": now,
        "nbf": now,
        // Comfortably inside the target's own fixed 300s nested-token TTL -
        // see this module's doc comment.
        "exp": now + 250,
        "jti": uuid::Uuid::new_v4().to_string(),
        "token": nested_token,
    });
    dcp_core::sign_jws(
        &outer_payload,
        &state.verifier.key_pair.signing_key(),
        state.verifier.own_key_id(),
    )
}

async fn mint(state: &MintState) -> anyhow::Result<String> {
    let nested_token = fetch_nested_token(state).await?;
    Ok(mint_outer_envelope(state, &nested_token))
}

#[derive(serde::Deserialize)]
struct MintBatchQuery {
    n: usize,
}

/// `GET /mint-batch?n=<count>` - mints `n` distinct, genuinely valid bearer
/// tokens in one call, all wrapping the SAME nested access token (safe - see
/// [`fetch_nested_token`]'s doc comment) but each with its own fresh `jti`,
/// so a k6 run can send `n` requests without ever tripping the target's real
/// `jti`-replay protection (`identity_hub_http::auth::verify_bearer_token`,
/// permanent behavior, not a bootstrap artifact - see bench/README.md's
/// "Why every request needs its own token" for the full explanation of why
/// this exists at all and why reusing one fixed token, as the EDC leg of
/// this benchmark does, is not an option here). Returns one token per line,
/// `text/plain` (not a JSON array) so `n` in the hundreds of thousands
/// doesn't pay JSON-escaping overhead for no benefit.
async fn mint_batch_handler(
    State(state): State<Arc<MintState>>,
    Query(query): Query<MintBatchQuery>,
) -> Response {
    match mint_batch(&state, query.n).await {
        Ok(body) => ([(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("mint-batch failed: {err}"),
        )
            .into_response(),
    }
}

/// Signing `n` outer envelopes one at a time on a single thread is the
/// throughput bottleneck for a large pool (measured ~5,000/s on this host's
/// single core - see bench/README.md's "Why every request needs its own
/// token"), so this spreads the (embarrassingly parallel - each envelope is
/// independent) signing loop across every available core via
/// `std::thread::scope`, cutting a 500,000-token mint from ~100s to a few
/// seconds on a 22-core host.
async fn mint_batch(state: &MintState, n: usize) -> anyhow::Result<String> {
    let nested_token = fetch_nested_token(state).await?;
    let threads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
        .min(n.max(1));
    let base = n / threads;
    let remainder = n % threads;

    let chunks: Vec<String> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for i in 0..threads {
            let count = base + if i < remainder { 1 } else { 0 };
            let nested_token = &nested_token;
            handles.push(scope.spawn(move || {
                let mut out = String::with_capacity(count * 1100);
                for _ in 0..count {
                    out.push_str(&mint_outer_envelope(state, nested_token));
                    out.push('\n');
                }
                out
            }));
        }
        handles.into_iter().map(|h| h.join().expect("mint worker thread panicked")).collect()
    });

    Ok(chunks.concat())
}

