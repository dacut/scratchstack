use std::{
    env,
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    future::Future,
    io::{self, Error as IOError, Write},
    net::{SocketAddr},
    pin::Pin,
    process::exit,
    sync::Arc,
    task::{Context, Poll},
};

use aws_sig_verify::{Principal, SignatureError, SigningKeyKind};
use env_logger;
use getopts::Options;
use http::{
    header::HeaderValue,
    StatusCode,
};
use hyper::{
    server::{
        Builder as HyperBuilder, Server as HyperServer,
        conn::{AddrStream, Http},
    },
    service::{Service, HttpService, make_service_fn, service_fn},
    Body, Error as HyperError, Request, Response,
};
use hyper_aws_sig_verify::AwsSigV4VerifierService;
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
    SignatureError(SignatureError),
}

impl Error for ServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(e) => Some(e),
            Self::IO(e) => Some(e),
            Self::SignatureError(e) => Some(e),
        }
    }
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Hyper(e) => write!(f, "Hyper error: {}", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
            Self::SignatureError(e) => write!(f, "Signature error: {}", e),
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

impl From<SignatureError> for ServerError {
    fn from(e: SignatureError) -> Self {
        Self::SignatureError(e)
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
            info!(
                "TLS configuration detected; creating acceptor and listener"
            );
            let acceptor = TlsAcceptor::from(Arc::new(t));
            let tcp_listener = TcpListener::bind(&config.address).await?;
            let incoming = TlsIncoming::new(tcp_listener, acceptor);
            let http = Http::new();
            info!("Starting Hyper");
            let hs = HyperServer::bind(&config.address);
            Ok(())
        }
        None => {
            let service_maker = IAMServiceMaker{};
            info!("Non-TLS configuration detected; starting Hyper");
            let hs = HyperServer::bind(&config.address).serve(service_maker).await?;
            Ok(())
        }
    }
}

#[derive(Debug)]
enum ServiceError {
    Hyper(HyperError),
    Signature(SignatureError),
    IO(IOError),
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(e) => Some(e),
            Self::Signature(e) => Some(e),
            Self::IO(e) => Some(e)
        }
    }
}

impl From<HyperError> for ServiceError {
    fn from(e: HyperError) -> Self {
        Self::Hyper(e)
    }
}

impl From<SignatureError> for ServiceError {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}

impl From<IOError> for ServiceError {
    fn from(e: IOError) -> Self {
        Self::IO(e)
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug)]
struct IAMServiceMaker {}

impl Service<&'_ AddrStream> for IAMServiceMaker {
    type Response = AwsSigV4VerifierService<IAMService>;
    type Error = ServiceError;
    type Future = Pin<Box<dyn Future<Output=Result<Self::Response, Self::Error>> + Send + Sync + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: &'_ AddrStream) -> Self::Future {
        Box::pin(async {
            Ok(AwsSigV4VerifierService::new("local", "iam", IAMService{}))
        })
    }
}

#[derive(Clone, Debug)]
struct IAMService {
}

impl HttpService<Body> for IAMService {
    type ResBody = Body;
    type Error = Box<dyn Error + Send + Sync + 'static>;
    type Future = Pin<Box<dyn Future<Output=Result<Response<Body>, Box<dyn Error + Send + Sync + 'static>>> + Send + Sync + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        Box::pin(async {
            Ok(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", HeaderValue::from_static("text/plain"))
                    .body(Body::from("Hello IAM"))
                    .unwrap()
            )
        })
    }
}
