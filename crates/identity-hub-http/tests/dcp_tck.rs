//! Runs the real, official Eclipse Dataspace TCK for DCP
//! (`eclipsedataspacetck/dcp-tck-runtime:latest`) against a real, fully
//! booted instance of this crate's Credential Service
//! (`identity_hub_http::build`/`serve`) - not a mock, and not a
//! reimplementation of the TCK's own assertions. Modelled directly on
//! `ds-sql-dps-rs/dataplane/tests/dps_tck.rs` (same
//! `testcontainers`-driven pattern, same honest-exact-failure-set
//! methodology), adapted for the DCP TCK's own log format and networking
//! quirks (see below).
//!
//! ## Scope: what this actually proves, and what it doesn't
//!
//! This is scoped to the **Credential Service** test packages only
//! (`org.eclipse.dataspacetck.dcp.verification.presentation.cs` +
//! `....issuance.cs`, per `tests/dcp.tck.properties`'
//! `dataspacetck.test.package`) - the two VPP+CIP obligations a Credential
//! Service has per the TCK's own SUT matrix (see `../../ARCHITECTURE.md`).
//! It does not run the `....issuance.issuer` package against this crate's
//! separate Issuer Service mode - out of scope for this bootstrap.
//!
//! Rather than asserting "no failures" (false at this bootstrap stage - see
//! `../../ARCHITECTURE.md`, "DCP TCK conformance snapshot" for the honest
//! numbers and why) or skipping the exercise, this test asserts the
//! **exact** set of TCK test method names ([`EXPECTED_FAILURES`]) already
//! known to fail, for the documented reasons in `../../ARCHITECTURE.md`.
//! That means:
//!
//! - a regression on any test *not* in [`EXPECTED_FAILURES`] fails this
//!   test;
//! - the TCK reporting *fewer* failures than [`EXPECTED_FAILURES`] also
//!   fails this test - a sign the list (and `../../ARCHITECTURE.md`'s scope
//!   claims) have gone stale, not a reason to celebrate a silent
//!   improvement;
//! - an entirely new/different failure fails this test the same way a
//!   missing expected failure does - the assertion is an exact-set
//!   comparison, not a subset check.
//!
//! Test method names (not the TCK's own numbered `@DisplayName`, which
//! several unrelated tests share verbatim, e.g. two different test classes
//! both display as "6.5.1 CredentialService rejects an invalid auth token -
//! kid resolves to no verification method") are the stable identifier here,
//! per `eclipse-dataspacetck/dcp-tck`'s own README ("the key is the
//! **method** name ... unique across the whole suite").
//!
//! ## A real networking gotcha this test's config works around
//!
//! The DCP TCK runtime's own embedded callback HTTP server (hosting its
//! self-generated `verifier`/`issuer`/`thirdparty`/... DIDs and STS) always
//! binds container port 8083, regardless of
//! `dataspacetck.callback.address`'s configured port - that property only
//! *constructs* those DIDs' `host:port` strings. Since this test's own
//! server runs natively (not inside a container), and the TCK container
//! itself needs to resolve *its own* self-hosted DIDs (checking a Verifiable
//! Credential's issuer proof), `tests/dcp.tck.properties` uses
//! `host.docker.internal` (not `localhost`) for the callback address too, so
//! the TCK's in-container resolution hairpins back out through the host's
//! published port. This crate's own `AppState::new` applies a matching
//! `host.docker.internal -> 127.0.0.1` DNS override to its `reqwest::Client`
//! so *this* process's outbound DID resolution (verifying an incoming
//! Self-Issued ID Token's `iss`) works the same way. See
//! `tests/dcp.tck.properties`'s comments and `src/state.rs` for the full
//! picture; found and fixed by actually running the TCK against this
//! bootstrap and reading the resulting `ConnectException`s, not written
//! blind.
//!
//! ## Running this
//!
//! Requires Docker (pulls and runs `eclipsedataspacetck/dcp-tck-runtime:latest`).
//! Not run by plain `cargo test` or the "quality" CI job - `#[ignore]`d so
//! neither needs Docker:
//!
//! ```sh
//! cargo test --test dcp_tck -- --ignored --nocapture
//! ```
//!
//! Verified genuinely green against a real run of
//! `eclipsedataspacetck/dcp-tck-runtime:latest` (not written blind) - see
//! `../../ARCHITECTURE.md`, "DCP TCK conformance snapshot" for the exact,
//! date-stamped run this was checked against, reproduced twice with an
//! identical failure set.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{self, Path};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;
use identity_hub_http::config::{Config, Mode};
use regex::Regex;
use testcontainers::core::logs::LogFrame;
use testcontainers::core::logs::consumer::LogConsumer;
use testcontainers::core::{ContainerPort, Host, IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

/// This crate's own server port, as booted by this test. Must match
/// `tests/dcp.tck.properties`' `dataspacetck.did.holder`/`sts.url`.
const SERVER_PORT: u16 = 19180;
/// Host port the TCK container's own (always-8083) callback server is
/// published to. Must match `tests/dcp.tck.properties`'
/// `dataspacetck.callback.address`.
const TCK_CALLBACK_PORT: u16 = 19183;
/// The TCK's own "issuer" role DID, exactly as `tests/dcp.tck.properties`
/// pins it (`dataspacetck.did.issuer`) - the DID this test's own Credential
/// Service is configured to trust, per `Config::trusted_issuer_dids`.
const TCK_ISSUER_DID: &str = "did:web:host.docker.internal%3A19183:issuer";
/// The TCK's own fixed `holderPid` correlation id, exactly as
/// `tests/dcp.tck.properties` pins it
/// (`dataspacetck.credentials.correlation.id`) - the `holderPid` this test's
/// own Credential Service is configured to expect, per
/// `Config::known_holder_pids`. See `BaseAssembly::getHolderPid`
/// (decompiled from `eclipsedataspacetck/dcp-tck-runtime:latest`): every
/// `@HolderPid`-annotated test parameter resolves to this same fixed value
/// unless a test overrides it with its own
/// `dataspacetck.credentials.correlation.id.<method>` property, which this
/// file's properties do not.
const TCK_HOLDER_PID: &str = "bootstrap-correlation-id";

/// The exact TCK test method names expected to fail against this
/// bootstrap, and why. See this file's module doc comment for what
/// asserting an exact set (rather than "no failures") buys, and
/// `../../ARCHITECTURE.md`'s "DCP TCK conformance snapshot" for the full,
/// categorized narrative this list summarizes.
///
/// **2026-09-20 update (sixth change today):** `storage_write` and
/// `credential_offer` (`../src/handlers.rs`) now also validate the message
/// *body* itself, via the new `identity_hub_http::validation` module -
/// distinct from, and applied after, every token/issuer check above, since
/// every one of the six tests this closes presents a genuinely valid,
/// genuinely trusted token. Investigated by decompiling the real TCK's own
/// `CredentialIssuanceTest`/`CredentialOfferTest` and their shared
/// `org.eclipse.dataspacetck.dcp.system.cs` model classes (`CredentialMessage`/
/// `CredentialOfferMessage`/`CredentialObject`), not guessed from test names
/// alone - see `identity_hub_http::validation`'s own module doc comment for
/// the full per-check reasoning. Four independent fixes:
///
/// - `CredentialMessage`'s `@context`/`type`/`issuerPid`/`holderPid`/
///   `status` are now all required fields (no permissive `#[serde(default)]`,
///   `holder_pid` no longer `Option<String>`) - a message missing any of
///   them now fails to deserialize, which axum's `Json` extractor already
///   turns into a `400`. Closes `cs_06_05_01_credentialMessage_invalidBody`.
/// - `validation::validate_status` rejects a `status` outside `{"ISSUED",
///   "REJECTED"}` (the same two values the real TCK's own, decompiled
///   `CredentialMessage.validate()` checks). Closes
///   `cs_06_05_01_credentialMessage_invalidStatus`.
/// - `validation::check_known_holder_pid`, checked against the new
///   `Config::known_holder_pids` (wired here to [`TCK_HOLDER_PID`], the
///   TCK's own fixed `dataspacetck.credentials.correlation.id`), rejects a
///   `holderPid` this service wasn't configured to expect. Closes
///   `cs_06_05_credentialMessage_unknownHolderPid`.
/// - `validation::verify_credential_proofs` genuinely verifies every
///   JWT-format embedded credential's own JWS proof (resolve its `iss`'s
///   `did:web` document, find the `kid`'s verification method, check the
///   signature) - reusing `crate::auth::verify_bearer_token`'s own
///   primitives, not a reimplementation. Closes
///   `cs_06_05_02_credentialMessage_unverifiableProof`.
/// - `validation::validate_offer_credentials` rejects an empty
///   `CredentialOfferMessage.credentials` array outright, and - for a
///   *sparse* (id-only, no `credentialType`) entry specifically - resolves
///   the offering issuer's own `IssuerService` DID-document entry and
///   fetches its real Issuer Metadata API (`GET <endpoint>/metadata`) to
///   check the id against that issuer's own catalog; a *full* entry
///   (`credentialType` present) is self-describing and needs no catalog
///   lookup at all, confirmed by the TCK's own always-passing default offer
///   using an unregistered random id but always carrying a `credentialType`.
///   Closes `cs_06_06_01_credentialOfferMessage_emptyCredentials` and
///   `cs_06_06_01_credentialOfferMessage_sparse_randomIds_expect400`.
///
/// TDD'd in `tests/message_content_validation.rs` (all six red-then-green
/// against the real HTTP layer, no TCK/Docker dependency), confirmed against
/// the real TCK, reproduced identically twice, with zero regressions on the
/// other 46 previously-passing tests (8 -> 2).
///
/// **2026-09-20 update (fifth change today):** `storage_write` and
/// `credential_offer` (`../src/handlers.rs`) now enforce a trusted-issuer
/// allow-list (`Config::trusted_issuer_dids`, checked by the new
/// `crate::auth::check_trusted_issuer` after `verify_bearer_token`'s
/// envelope checks pass) - a caller whose Self-Issued ID Token is otherwise
/// perfectly valid (correctly self-signed, `iss == sub`, real
/// `capabilityInvocation`) is now still rejected if its `iss` isn't on the
/// configured list. Investigated by decompiling the real TCK's own
/// `CredentialIssuanceTest`/`AbstractCredentialIssuanceTest`/`BaseAssembly`
/// (from `eclipsedataspacetck/dcp-tck-runtime:latest`, not guessed from the
/// test name): `cs_06_05_01_credentialMessage_untrustedIssuer` signs a
/// genuinely valid outer envelope as `thirdPartyDid` (a real, resolvable
/// `did:web` with its own real `capabilityInvocation`) and expects a `4xx`
/// purely because `thirdPartyDid` isn't `this.issuerDid` - the TCK's own SUT
/// convention for "the issuer this Credential Service should trust"
/// (`dataspacetck.did.issuer`, `BaseAssembly::parseDid`/`getIssuerDid`),
/// which `tests/dcp.tck.properties` now pins explicitly and this test wires
/// into `Config::trusted_issuer_dids` via [`TCK_ISSUER_DID`]. TDD'd in
/// `tests/trusted_issuer_allowlist.rs` (rejection and acceptance cases for
/// both endpoints, red-then-green). This closes exactly
/// `cs_06_05_01_credentialMessage_untrustedIssuer` (9 -> 8), confirmed
/// against the real TCK, reproduced identically twice, with zero
/// regressions on the other 45 tests.
///
/// **2026-09-20 update (fourth change today):** `verify_bearer_token`
/// (`../src/auth.rs`) now also rejects a token whose `iat` (issued-at) claim
/// is in the future, using the same `NBF_LEEWAY_SECS` clock-skew leeway the
/// existing `nbf` check already used. TDD'd in `tests/si_token_validation.rs`
/// (`storage_write_rejects_token_with_iat_in_the_future` red-then-green,
/// plus a `storage_write_accepts_a_token_with_iat_within_clock_skew_leeway`
/// regression guard). This closes exactly the two `iat`-in-the-future TCK
/// failures (11 -> 9), confirmed against the real TCK, reproduced with an
/// identical 9-failure set, zero regressions on the other 45 tests
/// (43 previously-passing plus these 2 newly-passing).
///
/// **2026-09-20 update (third change today):** `presentation_query`
/// (`../src/handlers.rs`) now enforces scope escalation: it decodes the
/// caller's nested `token` claim (still unverified as a signature - see
/// category 1 below) purely to read its own `scope` claim
/// (`identity_hub_core::scope::split_scope_string` +
/// `ScopeMatcher::credential_types`, the same matcher the requested `scope`
/// already went through), and intersects the requested credential types
/// against it before looking anything up in the store - a caller can no
/// longer read a credential type it wasn't granted just by asking for it,
/// even though its outer envelope is perfectly valid. TDD'd in
/// `tests/presentation_scope_enforcement.rs`, confirmed against the real
/// TCK (reproduced identically twice) to close exactly
/// `cs_05_04_01_02_invalidScopeEscalationRequest` (12 -> 11) with zero
/// regressions on the other 42 previously-passing tests. The two remaining
/// nested-token-related failures are untouched by this - they need the
/// nested token's own *signature* verified and bound back to the outer
/// envelope's caller, which this change deliberately does not do (see
/// category 1's own doc comment for exactly why that's still a distinct,
/// larger gap).
///
/// **2026-09-20 update (second change today):** `verify_bearer_token`
/// (`../src/auth.rs`) now also checks `iss == sub`, `nbf` (with a small
/// clock-skew leeway), the `capabilityInvocation` verification-relationship
/// restriction on the signing key (using `ds-dcp-core-rs`'s newly-added
/// `DidDocument::capability_invocation`, bumped in for exactly this - see
/// "Provenance: ds-dcp-core-rs" above), and in-memory `jti` replay tracking
/// (`AppState::seen_jti`). TDD'd in `tests/si_token_validation.rs`. This
/// moved 10 more tests from failing to passing (22 -> 12): the presentation
/// API's `idTokenInvalidSub`/`idtokenNbfInFuture`/`idTokenKidNoCapabilityInvocation`/
/// `idtokenJtiUsedTwice`, plus the Storage/Offer APIs' `issNotEqualToSub`/
/// `nbfViolated`/`jtiAlreadyUsed` (both endpoints). The 11 that remain fall
/// into four categories:
const EXPECTED_FAILURES: &[&str] = &[
    // The nested `token` claim (the actual Verifiable-Presentation access
    // token a caller forwards inside its Self-Issued ID Token) is never
    // itself *authenticated* - `verify_bearer_token` checks the *outer*
    // envelope (now including iss==sub/nbf/capabilityInvocation/jti) and
    // does read the nested token's own `scope` claim to enforce it (closing
    // `invalidScopeEscalationRequest`, no longer listed here) - but its
    // *signature* is still never verified, and nothing binds it back to the
    // outer envelope's own caller. Both failures below are that one
    // remaining gap, confirmed by reading the real TCK's own source
    // (`PresentationFlowSection4Test`/`PresentationFlowSection5Test` in
    // `eclipse-dataspacetck/dcp-tck`), not guessed from test names alone:
    // `idTokenInvalidIssuerSub`'s outer envelope is a perfectly valid,
    // correctly self-issued token (iss==sub==thirdPartyDid, real signature,
    // real capabilityInvocation) that forwards a nested access token
    // originally minted for a *different* party (the verifier) - a
    // confused-deputy case only a nested-token iss/sub binding check would
    // catch (this bootstrap's scope check reads the `scope` claim but never
    // checks who signed it or for whom, so a forwarded token with someone
    // else's genuinely-granted scope still passes); `invalidTokenNotAuthorized`
    // forwards a nested token that isn't even a real JWS ("faketoken")
    // inside an otherwise-valid outer envelope - this bootstrap's
    // `granted_credential_types` (`../src/handlers.rs`) fails to decode it
    // and falls back to *no* restriction being applied (the pre-existing,
    // unauthenticated-scope default), rather than the outright rejection
    // this test expects. A real fix here is nested-token signature
    // verification plus an iss/sub binding check back to the outer
    // envelope's caller - out of this bootstrap's scope so far; see
    // `../../ARCHITECTURE.md`'s "What's simplified or stubbed" ("No
    // nested-access-token authentication").
    "cs_04_03_03_idTokenInvalidIssuerSub",
    "cs_05_04_invalidTokenNotAuthorized",
];

#[tokio::test]
#[ignore = "needs Docker; run explicitly with `cargo test --test dcp_tck -- --ignored --nocapture`"]
async fn dcp_tck_matches_documented_credential_service_scope() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([0, 0, 0, 0], SERVER_PORT)),
        format!("host.docker.internal:{SERVER_PORT}"),
    )
    .with_trusted_issuer_dids(vec![TCK_ISSUER_DID.to_string()])
    .with_known_holder_pids(vec![TCK_HOLDER_PID.to_string()]);
    let (_state, router) = identity_hub_http::build(config.clone());
    tokio::spawn(async move {
        let _ = identity_hub_http::serve(&config, router).await;
    });
    wait_for_port(SERVER_PORT).await;

    let reporter = TckReporter::default();
    let properties_path = Path::new("tests/dcp.tck.properties");
    let properties_path = path::absolute(properties_path)
        .expect("dcp.tck.properties path resolves to an absolute path");

    let _tck = GenericImage::new("eclipsedataspacetck/dcp-tck-runtime", "latest")
        .with_exposed_port(8083.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Test run complete"))
        .with_mapped_port(TCK_CALLBACK_PORT, ContainerPort::Tcp(8083))
        .with_mount(Mount::bind_mount(
            properties_path
                .to_str()
                .expect("dcp.tck.properties path is valid UTF-8"),
            "/etc/tck/config.properties",
        ))
        // The TCK container both calls back into this host's own server
        // (this test's identity-hub instance) and, for its own self-hosted
        // DIDs, hairpins back through the host's published port - see this
        // file's module doc comment.
        .with_host("host.docker.internal", Host::HostGateway)
        .with_log_consumer(reporter.clone())
        .start()
        .await
        .expect("failed to start the dcp-tck-runtime container");

    let actual: BTreeSet<String> = reporter.failing_test_methods();
    let expected: BTreeSet<String> = EXPECTED_FAILURES.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        actual, expected,
        "TCK failure set no longer matches EXPECTED_FAILURES. Either a real \
         regression, or this bootstrap now covers more than EXPECTED_FAILURES \
         documents (some entries no longer fail). Update EXPECTED_FAILURES and \
         ../../ARCHITECTURE.md together with whichever is true - never just to \
         make this test pass again. Actual failures reported by the TCK this \
         run: {actual:?}"
    );
}

async fn wait_for_port(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("identity-hub server on {addr} never came up");
}

/// Accumulates the TCK container's full stdout (its process always exits 0
/// regardless of test outcome - watching its logs is the only way to learn
/// which tests actually failed) and, once the run is complete, extracts the
/// fully-qualified test method name of every genuine test failure from the
/// "There were failing tests:" stack-trace block it prints.
#[derive(Clone, Default)]
struct TckReporter {
    log: Arc<Mutex<String>>,
}

/// Matches an `at org.eclipse.dataspacetck.dcp.verification.<pkg>.cs.<Class>Test.<method>(`
/// stack-trace frame naming the actual failing test method - the innermost
/// frame of that shape in each failure's trace (excluding the shared
/// `AbstractPresentationFlowTest` helper, which every presentation-flow
/// failure's trace also passes through but which is never itself a test).
static TEST_METHOD_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"at org\.eclipse\.dataspacetck\.dcp\.verification\.(?:presentation|issuance)\.cs\.([A-Za-z0-9]+Test)\.([A-Za-z0-9_]+)\(")
        .expect("valid regex")
});

impl LogConsumer for TckReporter {
    fn accept<'a>(&'a self, record: &'a LogFrame) -> BoxFuture<'a, ()> {
        let line = String::from_utf8_lossy(record.bytes());
        print!("{line}");
        self.log.lock().expect("log lock poisoned").push_str(&line);
        futures::future::ready(()).boxed()
    }
}

impl TckReporter {
    fn failing_test_methods(&self) -> BTreeSet<String> {
        let log = self.log.lock().expect("log lock poisoned").clone();
        TEST_METHOD_REGEX
            .captures_iter(&log)
            .filter(|caps| &caps[1] != "AbstractPresentationFlowTest")
            .map(|caps| caps[2].to_string())
            .collect()
    }
}
