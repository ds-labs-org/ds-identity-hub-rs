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
    /// local/test environments only.
    #[arg(long, default_value_t = true)]
    insecure_http: bool,
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

    let (_state, router) = build(config.clone());
    if let Err(err) = serve(&config, router).await {
        tracing::error!(error = %err, "server exited with an error");
        std::process::exit(1);
    }
}
