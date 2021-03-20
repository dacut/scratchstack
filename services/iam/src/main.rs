use std::{
    env,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    io::{self, Error as IOError, Write},
    process::exit,
    sync::Arc,
};

use env_logger;
use getopts::Options;
use hyper::{
    server::{conn::Http, Builder as HyperBuilder, Server as HyperServer},
    service::{make_service_fn, service_fn},
    Body, Error as HyperError, Response,
};
use log::{debug, error, info};
use tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder};
use tokio_rustls::TlsAcceptor;

mod config;
use crate::config::{Config, ResolvedConfig};
mod tls;
use crate::tls::TlsIncoming;

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg";
// const CONTENT_LENGTH_LIMIT: u64 = 10 << 20;

#[derive(Debug)]
enum ServerError {
    Hyper(HyperError),
    IO(IOError),
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(e) => Some(e),
            Self::IO(e) => Some(e),
        }
    }
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Hyper(e) => write!(f, "Hyper error: {}", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl From<HyperError> for ServerError {
    fn from(e: HyperError) -> Self {
        Self::Hyper(e)
    }
}

impl From<IOError> for ServerError {
    fn from(e: IOError) -> Self {
        Self::IO(e)
    }
}

#[allow(unused_must_use)]
fn print_usage(stream: &mut dyn Write, program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    write!(stream, "{}", opts.usage(&brief));
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "configuration file", "FILENAME");
    opts.optflag("h", "help", "print this usage information");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            error!("{}", f);
            exit(2);
        }
    };

    if matches.opt_present("h") {
        print_usage(&mut io::stdout(), &program, opts);
        return;
    }

    let config_filename = match matches.opt_str("c") {
        Some(filename) => filename.to_string(),
        None => DEFAULT_CONFIG_FILENAME.to_string(),
    };

    // Shouldn't have any other arguments on the command line.
    if !matches.free.is_empty() {
        print_usage(&mut io::stderr(), &program, opts);
        exit(0);
    }

    // Parse the configuration.
    info!("Reading configuration from {}", config_filename);
    let config = match Config::read_file(&config_filename) {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Unable to read configuration file {}: {}",
                config_filename, e
            );
            exit(2);
        }
    };
    info!("Configuration read from {}", config_filename);
    debug!("Configuration: {:?}", config);

    // Resolve the configuration -- this may uncover additional errors such as missing TLS certificate files, etc.
    info!("Resolving configuration");
    let config = match config.resolve() {
        Ok(c) => c,
        Err(e) => {
            error!("Error in configuration file {}: {}", config_filename, e);
            exit(2);
        }
    };
    info!("Configuration resolved");
    debug!("Resolved configuration: {:?}", config);

    info!("Creating runtime");
    let runtime = match RuntimeBuilder::new_multi_thread()
        .worker_threads(config.threads)
        .thread_name("IAM")
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to create runtime: {}", e);
            exit(1);
        }
    };

    println!("{:#?}", runtime.block_on(run_server_from_config(config)));
}

async fn run_server_from_config(
    config: ResolvedConfig,
) -> Result<(), ServerError> {
    match config.tls {
        Some(t) => {
            let make_service = make_service_fn(|_| async {
                Ok::<_, HyperError>(service_fn(|_req| async {
                    Ok::<_, HyperError>(Response::new(Body::from(
                        "Hello world",
                    )))
                }))
            });

            info!(
                "TLS configuration detected; creating acceptor and listener"
            );
            let acceptor = TlsAcceptor::from(Arc::new(t));
            let tcp_listener = TcpListener::bind(&config.address).await?;
            let incoming = TlsIncoming::new(tcp_listener, acceptor);
            let http = Http::new();
            info!("Starting Hyper");
            Ok(HyperBuilder::new(incoming, http)
                .serve(make_service)
                .await?)
        }
        None => {
            let make_service = make_service_fn(|_| async {
                Ok::<_, HyperError>(service_fn(|_req| async {
                    Ok::<_, HyperError>(Response::new(Body::from(
                        "Hello world",
                    )))
                }))
            });

            info!("Non-TLS configuration detected; starting Hyper");
            Ok(HyperServer::bind(&config.address)
                .serve(make_service)
                .await?)
        }
    }
}
