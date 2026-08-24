//! The Scratchstack server.
//!
//! Runs every service the binary was built with -- see the crate's `iam` and `sts` features --
//! from a single process, driven by one configuration file. Each service listens on its own port
//! so that clients address them exactly as they would separate deployments, while services
//! configured against the same database share one connection pool.
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

#[cfg(not(any(feature = "iam", feature = "sts")))]
compile_error!("At least one service feature must be enabled; available features: iam, sts");

use {
    clap::Parser,
    futures::future::{BoxFuture, try_join_all},
    log::{debug, error, info},
    scratchstack_config::ScratchstackConfig,
    scratchstack_service_common::{KNOWN_SERVICES, ServiceDescriptor, serve},
    sqlx::postgres::PgPool,
    std::{
        collections::HashMap,
        path::PathBuf,
        process::{ExitCode, exit},
        sync::Arc,
    },
    tokio::runtime::Builder as RuntimeBuilder,
    tower::BoxError,
};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg.toml";

/// Connection pools opened so far, keyed by the configuration's database name.
///
/// Services naming the same database share a pool, so this is keyed on the database name rather
/// than on the service.
type Pools = HashMap<String, Arc<PgPool>>;

/// The servers to run, one per configured service.
type Servers = Vec<BoxFuture<'static, Result<(), BoxError>>>;

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
    let config = match ScratchstackConfig::read_file(&config_filename) {
        Ok(c) => c,
        Err(e) => {
            error!("Unable to read configuration file {}: {}", config_filename.display(), e);
            exit(2);
        }
    };
    info!("Configuration read from {}", config_filename.display());

    // Service sections are validated against every service the project implements, not just the
    // ones this binary was built with, so a slimmed binary still accepts a deployment-wide file.
    if let Err(e) = config.validate_service_names(KNOWN_SERVICES) {
        error!("Invalid configuration in {}: {}", config_filename.display(), e);
        exit(2);
    }

    let runtime_config = match config.resolve_runtime() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to resolve runtime configuration: {e}");
            exit(2);
        }
    };

    let runtime = match RuntimeBuilder::new_multi_thread()
        .worker_threads(runtime_config.threads)
        .thread_name("scratchstack")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to create runtime: {e}");
            exit(1);
        }
    };

    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Server error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run every configured service until one of them fails.
async fn run(config: ScratchstackConfig) -> Result<(), BoxError> {
    let mut pools = Pools::new();
    let mut servers = Servers::new();

    #[cfg(feature = "iam")]
    prepare_service::<scratchstack_service_iam::IamService>(&config, &mut pools, &mut servers).await?;

    #[cfg(feature = "sts")]
    prepare_service::<scratchstack_service_sts::StsService>(&config, &mut pools, &mut servers).await?;

    if servers.is_empty() {
        return Err("No services are configured to run; check the service sections in the configuration".into());
    }

    // try_join_all resolves when every server has finished, or as soon as one of them fails.
    // A server only returns once its listener stops, so in practice this runs until shutdown.
    try_join_all(servers).await?;
    Ok(())
}

/// Prepare the service `D` for running, if the configuration has a section for it.
///
/// Connects the service's database unless another service already opened a pool for it, and
/// appends the resulting server to `servers`. A service with no configuration section is skipped
/// rather than treated as an error, so one file can describe more services than a deployment
/// chooses to run.
async fn prepare_service<D: ServiceDescriptor + 'static>(
    config: &ScratchstackConfig,
    pools: &mut Pools,
    servers: &mut Servers,
) -> Result<(), BoxError> {
    let Some(service_config) = config.resolve_service(D::SERVICE, D::DEFAULT_PORT)? else {
        info!("{}: no configuration section; not starting this service", D::SERVICE);
        return Ok(());
    };

    if !service_config.enabled {
        info!("{}: service is disabled in configuration; not starting this service", D::SERVICE);
        return Ok(());
    }

    let pool = match pools.get(&service_config.database_name) {
        Some(pool) => {
            debug!("{}: sharing the pool already open for database {}", D::SERVICE, service_config.database_name);
            pool.clone()
        }
        None => {
            debug!(
                "{}: connecting to database {} at {}",
                D::SERVICE,
                service_config.database_name,
                service_config.database.url
            );
            let pool = service_config.database.pool_options.clone().connect(&service_config.database.url).await?;
            let pool = Arc::new(pool);
            pools.insert(service_config.database_name.clone(), pool.clone());
            pool
        }
    };

    servers.push(Box::pin(serve::<D>(service_config, pool)));
    Ok(())
}
