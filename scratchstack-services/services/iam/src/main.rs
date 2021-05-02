use std::{
    env,
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    future::Future,
    io::{self, Error as IOError, Write},
    iter::Iterator,
    pin::Pin,
    process::exit,
    sync::Arc,
    task::{Context, Poll},
};

use diesel::{
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool},
};
use env_logger;
use getopts::Options;
use http::{header::HeaderValue, StatusCode};
use hyper::{
    server::{conn::AddrStream, Server as HyperServer},
    service::Service,
    Body, Error as HyperError, Request, Response,
};
use log::{debug, error, info};
use scratchstack_aws_signature::SignatureError;
use scratchstack_aws_signature_hyper::AwsSigV4VerifierService;
use scratchstack_get_signing_key_direct::GetSigningKeyFromDatabase;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Builder as RuntimeBuilder,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tower::BoxError;

mod config;
mod tls;
use crate::config::{Config, ResolvedConfig};
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
            error!("Unable to read configuration file {}: {}", config_filename, e);
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

async fn run_server_from_config(config: ResolvedConfig) -> Result<(), ServerError> {
    let pool = Arc::new(config.pool);

    match config.tls {
        Some(t) => {
            info!("TLS configuration detected; creating acceptor and listener");
            let acceptor = TlsAcceptor::from(Arc::new(t));
            let tcp_listener = TcpListener::bind(&config.address).await?;
            let incoming = TlsIncoming::new(tcp_listener, acceptor);
            info!("Starting Hyper");
            let service_maker = IAMServiceMaker {
                pool: pool,
                partition: config.partition,
                region: config.region,
            };
            HyperServer::builder(incoming).serve(service_maker).await?;
            Ok(())
        }
        None => {
            let service_maker = IAMServiceMaker {
                pool: pool,
                partition: config.partition,
                region: config.region,
            };
            info!("Non-TLS configuration detected; starting Hyper");
            HyperServer::bind(&config.address).serve(service_maker).await?;
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum ServiceError {
    Hyper(HyperError),
    Signature(SignatureError),
    IO(IOError),
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(e) => Some(e),
            Self::Signature(e) => Some(e),
            Self::IO(e) => Some(e),
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

#[derive(Clone)]
pub struct IAMServiceMaker {
    pool: Arc<Pool<ConnectionManager<PgConnection>>>,
    partition: String,
    region: String,
}

type Verifier = AwsSigV4VerifierService<GetSigningKeyFromDatabase<PgConnection>, IAMService>;

impl Service<&AddrStream> for IAMServiceMaker {
    type Response = Verifier;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &AddrStream) -> Self::Future {
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let region = self.region.clone();

        Box::pin(async move {
            Ok(AwsSigV4VerifierService::new(
                "local",
                "iam",
                GetSigningKeyFromDatabase::new(pool, partition, region, "iam"),
                IAMService {},
            ))
        })
    }
}

impl Service<&TlsStream<TcpStream>> for IAMServiceMaker {
    type Response = Verifier;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: &TlsStream<TcpStream>) -> Self::Future {
        let pool = self.pool.clone();
        let partition = self.partition.clone();
        let region = self.region.clone();

        Box::pin(async move {
            Ok(AwsSigV4VerifierService::new(
                "local",
                "iam",
                GetSigningKeyFromDatabase::new(pool, partition, region, "iam"),
                IAMService {},
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct IAMService {}

impl Service<Request<Body>> for IAMService {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", HeaderValue::from_static("text/plain"))
                .body(Body::from("Hello IAM"))
                .unwrap())
        })
    }
}

// #[derive(Clone)]
// pub struct GetSigningKeyFromDatabase {
//     pool: Arc<Pool<ConnectionManager<PgConnection>>>,
//     partition: String,
//     region: String,
//     service: String,
// }

// impl Service<GetSigningKeyRequest> for GetSigningKeyFromDatabase {
//     type Response = (Principal, SigningKey);
//     type Error = BoxError;
//     type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

//     fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }

//     fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
//         let pool = self.pool.clone();
//         let region = self.region.clone();
//         let service = self.region.clone();

//         Box::pin(async move {
//             // Access keys are 20 characters (at least) in length.
//             if req.access_key.len() < 20 {
//                 return Err(SignatureError::UnknownAccessKey { access_key: req.access_key }.into())
//             }

//             let db = pool.get()?;

//             // The prefix tells us what kind of key it is.
//             let access_prefix = &req.access_key[..4];
//             match access_prefix {
//                 "AKIA" => {
//                     use scratchstack_schema::schema::iam::iam_user_credential;
//                     use scratchstack_schema::schema::iam::iam_user;

//                     let results = iam_user_credential::table
//                         .filter(iam_user_credential::columns::access_key_id.eq(&req.access_key[4..]))
//                         .filter(iam_user_credential::columns::active.eq(true))
//                         .inner_join(
//                             iam_user::table.on(
//                                 iam_user::columns::user_id.eq(iam_user_credential::columns::user_id)))
//                         .select((iam_user::columns::user_id, iam_user::columns::account_id, iam_user::columns::path,
//                                  iam_user::columns::user_name_cased, iam_user_credential::columns::secret_key))
//                         .load::<(String, String, String, String, String)>(&db)?;

//                     if results.len() == 0 {
//                         Err(SignatureError::UnknownAccessKey { access_key: req.access_key }.into())
//                     } else {
//                         let (user_id, account_id, path, user_name, secret_key) = &results[0];
//                         let sk = SigningKey { kind: SigningKeyKind::KSecret, key: secret_key.as_bytes().to_vec() };
//                         let sk = sk.derive(req.signing_key_kind, &req.request_date, &region, &service);
//                         Ok((Principal::user("aws", account_id, path, user_name, user_id)?, sk))
//                     }
//                 }

//                 _ => Err(SignatureError::UnknownAccessKey { access_key: req.access_key }.into()),
//             }
//         })
//     }
// }
