use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use identity_hub_core::scope::DEFAULT_SCOPE_PATTERN;
use identity_hub_http::config::Mode;
use identity_hub_http::{Config, build, serve};

/// ds-identity-hub-rs: a from-scratch Rust DCP Identity Hub bootstrap. Boots
/// as either a Credential Service (Verifiable Presentation Protocol +
/// Credential Issuance Protocol) or a minimal Issuer Service (Credential
/// Issuance Protocol only) - see ARCHITECTURE.md.
#[derive(Debug, Parser)]
#[command(name = "identity-hub", version)]
struct Cli {
    #[command(subcommand)]
    mode: CliMode,
}

#[derive(Debug, Subcommand)]
enum CliMode {
    /// Run as a Credential Service: Presentation API, Storage API,
    /// Credential Offer API, DID hosting, and the embedded STS.
    CredentialService(CommonArgs),
    /// Run as a minimal Issuer Service: Credential Request API, Credential
    /// Request Status API, Issuer Metadata API, DID hosting, and the
    /// embedded STS.
    IssuerService(CommonArgs),
}

#[derive(Debug, clap::Args)]
struct CommonArgs {
    /// Address to bind the HTTP server on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// `host[:port]` this service is externally reachable at - embedded in
    /// its own `did:web` identity and advertised service endpoint. Defaults
    /// to `localhost:<bind port>`.
    #[arg(long)]
    did_host: Option<String>,
    #[arg(long, default_value = "tck-client")]
    sts_client_id: String,
    #[arg(long, default_value = "tck-secret")]
    sts_client_secret: String,
    #[arg(long, default_value = DEFAULT_SCOPE_PATTERN)]
    scope_pattern: String,
    /// Resolve/advertise `did:web` over plain HTTP instead of HTTPS - for
    /// local/test environments only. Defaults to `true` (unchanged); pass
    /// `--insecure-http false` (or `--insecure-http=false`) to turn it off
    /// and switch every `did:web` resolution this process performs, and
    /// the `serviceEndpoint` it advertises in its own DID document, to
    /// HTTPS (2026-09-20 fix, MEDIUM: previously a bare `bool` field, for
    /// which clap derives `ArgAction::SetTrue` - the flag took no value
    /// and there was no way, on any command line, to reach
    /// `insecure_http == false`; see `cli_scheme_switch_tests` below).
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    insecure_http: bool,
    /// A DID trusted to deliver a `CredentialMessage`/`CredentialOfferMessage`
    /// to this Credential Service (may be repeated). Empty (the default)
    /// means NO issuer is trusted - the Storage API and Credential Offer
    /// API reject every write with 401 until at least one of these is
    /// given (2026-09-20 fix, HIGH; see `Config::trusted_issuer_dids`'s doc
    /// comment).
    #[arg(long = "trusted-issuer-did")]
    trusted_issuer_dids: Vec<String>,
    /// A `holderPid` this Credential Service should accept on the Storage
    /// API (may be repeated). Empty (the default) means no restriction is
    /// configured - see `Config::known_holder_pids`'s doc comment for why
    /// that's this bootstrap's default, not a recommendation for a real
    /// deployment.
    #[arg(long = "known-holder-pid")]
    known_holder_pids: Vec<String>,
    /// An extra host (no port) this process is allowed to make outbound
    /// HTTP requests to (may be repeated), on top of the hosts
    /// `AppState::new` always derives from this process's own
    /// configuration (its own `did_host`, `127.0.0.1`, and
    /// `host.docker.internal`) - see `identity_hub_http::outbound` and
    /// `Config::allowed_outbound_hosts`'s doc comment. Empty (the default)
    /// is normally sufficient.
    #[arg(long = "allow-resolve-host")]
    allow_resolve_host: Vec<String>,
}

impl CommonArgs {
    fn into_config(self, mode: Mode) -> Config {
        let did_host = self
            .did_host
            .unwrap_or_else(|| format!("localhost:{}", self.bind.port()));
        Config {
            mode,
            bind_addr: self.bind,
            did_host,
            sts_client_id: self.sts_client_id,
            sts_client_secret: self.sts_client_secret,
            scope_pattern: self.scope_pattern,
            insecure_http: self.insecure_http,
            trusted_issuer_dids: self.trusted_issuer_dids,
            known_holder_pids: self.known_holder_pids,
            allowed_outbound_hosts: self.allow_resolve_host,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = match cli.mode {
        CliMode::CredentialService(args) => args.into_config(Mode::CredentialService),
        CliMode::IssuerService(args) => args.into_config(Mode::IssuerService),
    };

    tracing::info!(
        mode = ?config.mode,
        bind = %config.bind_addr,
        did_host = %config.did_host,
        "starting ds-identity-hub-rs"
    );

    // 2026-09-20 fix (HIGH): an empty trusted-issuer allow-list now means
    // "trust nobody", not "no restriction" - see
    // `Config::trusted_issuer_dids`'s doc comment. Booting still succeeds
    // (a real deployment may legitimately add its first `--trusted-issuer-did`
    // after standing the process up), but an operator who forgot the flag
    // entirely should find out from the logs, not from every write silently
    // getting 401.
    if config.mode == Mode::CredentialService && config.trusted_issuer_dids.is_empty() {
        tracing::warn!(
            "no --trusted-issuer-did configured: the Storage API (POST /credentials) and \
             Credential Offer API (POST /offers) will reject every write with 401 until at \
             least one is given"
        );
    }

    let (state, router) = build(config.clone());

    // Proves the Contreforts round trip at startup, mirroring
    // ds-sql-dps-rs's dataplane/src/lib.rs::build(): the same graph this
    // process's Storage API/Credential Offer API write into
    // (state.store.graph()) is reachable through Contreforts' own
    // connector interface, keyed by this project's own EntityKinds - see
    // identity-hub-contreforts's crate docs and ../../ARCHITECTURE.md,
    // "Provenance: Contreforts". Only meaningful in Credential Service mode
    // (the Issuer Service mode has no credential graph to speak of).
    if config.mode == Mode::CredentialService {
        use contreforts_core::ContrefortsConnector;
        let connector =
            identity_hub_contreforts::CredentialGraphConnector::new(state.store.graph());
        match connector
            .pull(
                contreforts_core::EntityKind::new(identity_hub_contreforts::STORED_CREDENTIAL_KIND),
                None,
            )
            .await
        {
            Ok(docs) => {
                tracing::info!(
                    count = docs.len(),
                    "ContrefortsConnector::pull round trip (stored credentials)"
                )
            }
            Err(e) => tracing::warn!(error = %e, "ContrefortsConnector::pull round trip failed"),
        }
    }

    if let Err(err) = serve(&config, router).await {
        tracing::error!(error = %err, "server exited with an error");
        std::process::exit(1);
    }
}

/// TDD coverage for the 2026-09-20 independent security audit's
/// `--insecure-http` finding (MEDIUM): the flag that selects plain-HTTP
/// `did:web` resolution cannot be turned off by any command line, so this
/// binary has no way to do HTTPS `did:web` resolution at all.
///
/// `CommonArgs::insecure_http` is a bare `bool` field, for which clap
/// derives [`clap::ArgAction::SetTrue`]: the flag takes no value, so
/// `--insecure-http false` is rejected as an unexpected positional
/// argument, `--insecure-http=false` as "a value was provided but none was
/// expected", and there is no generated `--no-insecure-http` counterpart
/// (clap only derives one for [`clap::ArgAction::SetFalse`], which is not
/// what a `default_value_t = true` bare `bool` gets). The explicit
/// `default_value_t = true` then pins the field permanently `true` -
/// present or absent, the parsed value is the same.
///
/// Whether that matters is not a style question: [`Config::scheme`] turns
/// this one `bool` into the scheme used for *every* `did:web` resolution
/// this process performs (`auth::verify_bearer_token`,
/// `validation`'s issuer checks, `outbound::check_did`) and for the
/// `serviceEndpoint` this service advertises in its own DID document.
/// Stuck `true`, the binary can only ever fetch counterparties' DID
/// documents - the documents whose keys it then verifies signatures
/// against - over unauthenticated plain HTTP, and can only ever advertise
/// an `http://` endpoint of its own, which `base.protocol.md` forbids for
/// a real deployment.
///
/// ## Why the tests below enumerate candidate command lines
///
/// The fix has more than one defensible shape (an explicit-value
/// `--insecure-http <true|false>`, or a second `--secure-http` flag), and
/// this half of the pair deliberately does not pick one: what the finding
/// says is that *no* invocation reaches `insecure_http == false`, so the
/// tests try each form an operator would reasonably reach for and require
/// that at least one of them work. Today every one of them fails, three
/// by clap rejection and one by silently parsing to `true`.
///
/// ## What must not regress
///
/// The permissive default is not the bug and is not in scope: a bare
/// `credential-service` with no scheme flag at all must still come out
/// `insecure_http == true`, matching this bootstrap's local/test-only
/// scope and every existing invocation in `ARCHITECTURE.md`, the TCK
/// harness, and `bench/`. `insecure_http_still_defaults_to_true` pins
/// that, and passes both before and after the fix.
#[cfg(test)]
mod cli_scheme_switch_tests {
    use super::*;

    /// Every command line an operator could reasonably reach for to ask
    /// this binary for HTTPS `did:web` resolution. The fix needs to make
    /// (at least) one of them work; it does not matter to these tests
    /// which.
    const OFF_SWITCH_CANDIDATES: &[&[&str]] = &[
        &["--insecure-http", "false"],
        &["--insecure-http=false"],
        &["--no-insecure-http"],
        &["--secure-http"],
    ];

    fn argv(subcommand: &str, extra: &[&str]) -> Vec<String> {
        let mut argv = vec!["identity-hub".to_string(), subcommand.to_string()];
        argv.extend(extra.iter().map(|arg| (*arg).to_string()));
        argv
    }

    fn parse(subcommand: &str, extra: &[&str]) -> Result<Cli, String> {
        Cli::try_parse_from(argv(subcommand, extra)).map_err(|err| {
            err.to_string()
                .lines()
                .next()
                .unwrap_or("<no message>")
                .to_string()
        })
    }

    fn parsed_insecure_http(subcommand: &str, extra: &[&str]) -> Result<bool, String> {
        parse(subcommand, extra).map(|cli| match cli.mode {
            CliMode::CredentialService(args) | CliMode::IssuerService(args) => args.insecure_http,
        })
    }

    fn parsed_config(subcommand: &str, extra: &[&str]) -> Result<Config, String> {
        parse(subcommand, extra).map(|cli| match cli.mode {
            CliMode::CredentialService(args) => args.into_config(Mode::CredentialService),
            CliMode::IssuerService(args) => args.into_config(Mode::IssuerService),
        })
    }

    /// The first candidate command line that actually reaches
    /// `insecure_http == false` for `subcommand`, or a report of why every
    /// one of them failed.
    fn off_switch_for(subcommand: &str) -> Result<&'static [&'static str], String> {
        let mut report = String::new();
        for candidate in OFF_SWITCH_CANDIDATES {
            match parsed_insecure_http(subcommand, candidate) {
                Ok(false) => return Ok(candidate),
                Ok(true) => report.push_str(&format!(
                    "  {candidate:?}: accepted, but insecure_http still parsed as true\n"
                )),
                Err(err) => {
                    report.push_str(&format!("  {candidate:?}: rejected by clap: {err}\n"));
                }
            }
        }
        Err(report)
    }

    #[test]
    fn insecure_http_can_be_turned_off_from_the_command_line() {
        if let Err(report) = off_switch_for("credential-service") {
            panic!(
                "no command line makes `identity-hub credential-service` resolve `did:web` over \
                 HTTPS - `insecure_http` is unreachable except as `true`:\n{report}"
            );
        }
    }

    #[test]
    fn turning_insecure_http_off_selects_https_did_web_resolution() {
        let off_switch = off_switch_for("credential-service").unwrap_or_else(|report| {
            panic!("no command line turns plain-HTTP `did:web` resolution off:\n{report}")
        });

        let config = parsed_config("credential-service", off_switch)
            .unwrap_or_else(|err| panic!("{off_switch:?} no longer parses: {err}"));

        assert!(
            !config.insecure_http,
            "{off_switch:?} must reach Config::insecure_http == false"
        );
        assert_eq!(
            config.scheme(),
            "https",
            "with the scheme switch off, every did:web resolution and this service's own \
             advertised serviceEndpoint must use HTTPS"
        );
        assert!(
            config.base_url().starts_with("https://"),
            "advertised base URL must be HTTPS, got {}",
            config.base_url()
        );
    }

    #[test]
    fn both_subcommands_accept_the_scheme_switch() {
        let off_switch = off_switch_for("credential-service").unwrap_or_else(|report| {
            panic!("no command line turns plain-HTTP `did:web` resolution off:\n{report}")
        });

        // The flag lives on the shared `CommonArgs`, so whatever shape the
        // fix gives it must work identically for the Issuer Service, which
        // resolves holder DIDs on exactly the same code path.
        assert_eq!(
            parsed_insecure_http("issuer-service", off_switch),
            Ok(false),
            "{off_switch:?} works for credential-service but not for issuer-service"
        );
    }

    /// Regression floor: the permissive default is out of scope for this
    /// finding and must survive the fix untouched.
    #[test]
    fn insecure_http_still_defaults_to_true() {
        assert_eq!(
            parsed_insecure_http("credential-service", &[]),
            Ok(true),
            "omitting the scheme flag must still mean plain-HTTP did:web resolution"
        );
        assert_eq!(
            parsed_insecure_http("issuer-service", &["--bind", "0.0.0.0:8081"]),
            Ok(true),
            "omitting the scheme flag must still mean plain-HTTP did:web resolution"
        );
        let config = parsed_config("credential-service", &[])
            .expect("the documented default invocation must keep parsing");
        assert_eq!(config.scheme(), "http");
    }
}
