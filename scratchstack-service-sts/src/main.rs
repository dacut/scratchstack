//! Scratchstack implementation of the AWS Security Token Service (STS).

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

pub(crate) mod config;
pub(crate) mod constants;
pub(crate) mod error;
pub(crate) mod model;
pub(crate) mod operations;
pub(crate) mod service;

use {
    crate::{
        config::{ResolvedStsServiceConfig, StsServiceConfig},
        error::ServiceError,
    },
    axum::{
        Router,
        routing::{get, post, put},
    },
    clap::Parser,
    log::{debug, error, info},
    scratchstack_config::Resolvable as _,
    scratchstack_core::TlsListener,
    scratchstack_iam_database::GetSigningKeyFromDatabase,
    std::{path::PathBuf, process::exit, sync::Arc},
    tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder},
};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg";
// const CONTENT_LENGTH_LIMIT: u64 = 10 << 20;

#[derive(Parser)]
#[command(version, about)]
struct CliOptions {
    /// Configuration file to read
    #[arg(short, long, value_name = "FILENAME")]
    config: Option<PathBuf>,
}

fn main() {
    env_logger::init();
    let cli = CliOptions::parse();

    let config_filename = match cli.config {
        Some(filename) => filename,
        None => PathBuf::from(DEFAULT_CONFIG_FILENAME),
    };

    // Parse the configuration.
    info!("Reading configuration from {}", config_filename.display());
    let config = match StsServiceConfig::read_file(&config_filename) {
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
            error!("Error resolving configuration: {}", e);
            exit(2);
        }
    };

    debug!("Resolved configuration: {config:?}");

    let runtime = match RuntimeBuilder::new_multi_thread()
        .worker_threads(config.common.runtime.threads)
        .thread_name("sts")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to create runtime: {e}");
            exit(1);
        }
    };

    println!("{:#?}", runtime.block_on(run_server_from_config(config)));
}

#[allow(unused_variables, clippy::useless_vec)]
async fn run_server_from_config(config: ResolvedStsServiceConfig) -> Result<(), ServiceError> {
    use crate::service::serve_request;

    let common = config.common;
    let pool = common.database.pool_options.connect(&common.database.url).await?;
    let pool = Arc::new(pool);
    let region = common.scope.region.clone();
    let allowed_content_types = vec!["application/x-www-form-urlencoded".to_string()];
    let gsk = GetSigningKeyFromDatabase::new(pool, &common.scope.partition, &common.scope.region, "sts");
    // let service_impl = StsService {};
    // let error_mapper = XmlErrorMapper::new(STS_XML_NS);

    let app =
        Router::new().route("/", get(serve_request)).route("/", post(serve_request)).route("/", put(serve_request));
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
