//! Scratchstack implementation of the AWS Identity and Access Management (IAM) Service
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

pub(crate) mod authz;
pub(crate) mod config;
pub(crate) mod constants;
pub(crate) mod operations;
pub(crate) mod service;

use {
    crate::{
        config::{IamServiceConfig, ResolvedIamServiceConfig},
        constants::*,
        service::ServiceState,
    },
    axum::{
        Router,
        http::Method,
        routing::{get, post, put},
    },
    clap::Parser,
    log::{debug, error, info},
    scratchstack_aws_signature::{AwsSigV4VerifierLayer, NoSignedHeaderRequirements, XmlErrorMapper},
    scratchstack_config::Resolvable as _,
    scratchstack_core::TlsListener,
    scratchstack_iam_database::GetSigningKeyFromDatabase,
    std::{
        path::PathBuf,
        process::{ExitCode, exit},
        sync::Arc,
    },
    tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder},
    tower::BoxError,
};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack-iam.cfg.toml";

#[derive(Parser)]
#[command(version, about)]
struct CliOptions {
    /// Configuration file to read
    #[arg(short, long, value_name = "FILENAME")]
    config: Option<PathBuf>,
}

fn main() -> ExitCode {
    env_logger::init();
    let cli_options = CliOptions::parse();

    let config_filename = match cli_options.config {
        Some(filename) => filename,
        None => PathBuf::from(DEFAULT_CONFIG_FILENAME),
    };

    // Parse the configuration.
    info!("Reading configuration from {}", config_filename.display());
    let config = match IamServiceConfig::read_file(&config_filename) {
        Ok(c) => c,
        Err(e) => {
            error!("Unable to read configuration file {}: {}", config_filename.display(), e);
            exit(2);
        }
    };
    info!("Configuration read from {}", config_filename.display());
    debug!("Configuration: {config:?}");

    let config = match config.resolve() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to resolve configuration: {}", e);
            exit(2);
        }
    };

    debug!("Resolved configuration: {config:?}");
    let runtime = match RuntimeBuilder::new_multi_thread()
        .worker_threads(config.common.runtime.threads)
        .thread_name("iam")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to create runtime: {e}");
            exit(1);
        }
    };

    match runtime.block_on(run_server_from_config(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Server error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(unused_variables, clippy::useless_vec)]
async fn run_server_from_config(config: ResolvedIamServiceConfig) -> Result<(), BoxError> {
    use crate::service::serve_request;

    let common = config.common;
    debug!("Connecting to database at {}", common.database.url);
    let pool = common.database.pool_options.connect(&common.database.url).await?;
    let pool = Arc::new(pool);
    let allowed_content_types = vec!["application/x-www-form-urlencoded".to_string()];
    let gsk = GetSigningKeyFromDatabase::new(pool.clone(), &common.scope.partition, &common.scope.region, SERVICE_IAM);

    let verifier = AwsSigV4VerifierLayer::builder()
        .region(common.scope.region.clone())
        .service(SERVICE_IAM)
        .allowed_request_methods(vec![Method::GET, Method::POST, Method::PUT])
        .allowed_content_types(vec![CT_APPLICATION_X_WWW_FORM_URLENCODED.to_string()])
        .signed_header_requirements(NoSignedHeaderRequirements)
        .get_signing_key(gsk)
        .error_mapper(XmlErrorMapper::new(XML_NS_IAM))
        .build();

    let svc_state = ServiceState {
        db: pool,
        secure_transport: common.listener.tls.is_some(),
    };

    let app = Router::new()
        .route("/", get(serve_request))
        .route("/", post(serve_request))
        .route("/", put(serve_request))
        .layer(verifier)
        .with_state(svc_state);

    let listener = TcpListener::bind(&common.listener.socket_addr).await?;

    match common.listener.tls {
        Some(tls) => {
            info!("Listening for HTTPS requests on {}", common.listener.socket_addr);
            let listener = TlsListener::new(listener, Arc::new(tls))?;
            Ok(axum::serve(listener, app).await?)
        }
        None => {
            info!("Listening for HTTP requests on {}", common.listener.socket_addr);
            Ok(axum::serve(listener, app).await?)
        }
    }
}
