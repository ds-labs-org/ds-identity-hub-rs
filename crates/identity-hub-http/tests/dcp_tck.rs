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

/// The exact TCK test method names expected to fail against this
/// bootstrap, and why. See this file's module doc comment for what
/// asserting an exact set (rather than "no failures") buys, and
/// `../../ARCHITECTURE.md`'s "DCP TCK conformance snapshot" for the full,
/// categorized narrative this list summarizes.
const EXPECTED_FAILURES: &[&str] = &[
    // Self-Issued ID Token validation this bootstrap does not implement
    // beyond signature + DID-resolvability + audience + expiry (see
    // identity_hub_http::auth's module doc): no iss==sub equality check, no
    // nbf leeway/check, no capabilityInvocation verification-relationship
    // restriction on the signing key, and no jti replay tracking.
    "cs_04_03_03_idTokenInvalidIssuerSub",
    "cs_04_03_03_idTokenInvalidSub",
    "cs_04_03_03_idtokenJtiUsedTwice",
    "cs_04_03_03_idTokenKidNoCapabilityInvocation",
    "cs_04_03_03_idtokenNbfInFuture",
    "cs_05_04_invalidTokenNotAuthorized",
    // Scope-based authorization is not enforced against what a caller's own
    // access token (the nested `token` claim) was actually scoped to - any
    // successfully authenticated caller receives every stored credential
    // matching the requested type, not just ones its token entitles it to.
    "cs_05_04_01_02_invalidScopeEscalationRequest",
    // The Storage API (`storage_write`) and Credential Offer API
    // (`credential_offer`) deliberately accept every well-formed message
    // unconditionally, with no Authorization-header/token validation at
    // all - see those handlers' doc comments for why (the TCK's own
    // Credential-Service setup phase depends on the Storage API accepting
    // its dynamically generated test credentials unconditionally). Every
    // "rejects an invalid/missing/malformed auth token" or
    // "rejects a malformed message body" test against either API fails as
    // a direct, documented consequence:
    "cs_06_05_01_credentialMessage_iatInFuture",
    "cs_06_05_01_credentialMessage_incorrectAudience",
    "cs_06_05_01_credentialMessage_invalidBody",
    "cs_06_05_01_credentialMessage_invalidStatus",
    "cs_06_05_01_credentialMessage_issNotEqualToSub",
    "cs_06_05_01_credentialMessage_jtiAlreadyUsed",
    "cs_06_05_01_credentialMessage_missingBearerPrefix",
    "cs_06_05_01_credentialMessage_nbfViolated",
    "cs_06_05_01_credentialMessage_noAuthHeader",
    "cs_06_05_01_credentialMessage_tokenExpired",
    "cs_06_05_01_credentialMessage_tokenSignedWithWrongKey",
    "cs_06_05_01_credentialMessage_unknownKid",
    "cs_06_05_01_credentialMessage_unresolvableSubject",
    "cs_06_05_01_credentialMessage_untrustedIssuer",
    "cs_06_05_02_credentialMessage_unverifiableProof",
    "cs_06_05_credentialMessage_unknownHolderPid",
    "cs_06_06_01_credentialOfferMessage_emptyCredentials",
    "cs_06_06_01_credentialOfferMessage_iatInFuture",
    "cs_06_06_01_credentialOfferMessage_incorrectAudience",
    "cs_06_06_01_credentialOfferMessage_issNotEqualToSub",
    "cs_06_06_01_credentialOfferMessage_jtiAlreadyUsed",
    "cs_06_06_01_credentialOfferMessage_missingBearerPrefix",
    "cs_06_06_01_credentialOfferMessage_nbfViolated",
    "cs_06_06_01_credentialOfferMessage_noAuthHeader",
    "cs_06_06_01_credentialOfferMessage_sparse_randomIds_expect400",
    "cs_06_06_01_credentialOfferMessage_tokenExpired",
    "cs_06_06_01_credentialOfferMessage_tokenSignedWithWrongKey",
    "cs_06_06_01_credentialOfferMessage_unknownKid",
    "cs_06_06_01_credentialOfferMessage_unresolvableSubject",
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
    );
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
