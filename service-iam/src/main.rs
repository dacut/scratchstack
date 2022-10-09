mod error;
mod service;

use {
    crate::{
        error::ServiceError,
        service::{IamService, IAM_XML_NS},
    },
    getopts::Options,
    http::method::Method,
    hyper::server::Server as HyperServer,
    log::{debug, error, info},
    scratchstack_config::{service::ResolvedIam, Config},
    scratchstack_http_framework::{GetSigningKeyFromDatabase, SpawnService, TlsIncoming, XmlErrorMapper},
    std::{
        env,
        io::{self, Write},
        iter::Iterator,
        process::exit,
        sync::Arc,
    },
    tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder},
    tokio_rustls::TlsAcceptor,
};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg";
// const CONTENT_LENGTH_LIMIT: u64 = 10 << 20;

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
        Some(filename) => filename,
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

    let service_config = match &config.service {
        Some(s) => s,
        None => {
            error!("No service configuration found in configuration file {}", config_filename);
            exit(2);
        }
    };

    let iam_config = match &service_config.iam {
        None => {
            error!("No configuration for service 'iam'");
            exit(2);
        }
        Some(c) => c,
    };

    // Resolve the configuration -- this may uncover additional errors such as missing TLS certificate files, etc.
    info!("Resolving configuration");
    let config = match iam_config.resolve() {
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
        .worker_threads(config.service.threads)
        .thread_name("iam")
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

async fn run_server_from_config(config: ResolvedIam) -> Result<(), ServiceError> {
    let pool = config.database.pool_options.connect(&config.database.url).await?;
    let pool = Arc::new(pool);
    let region = config.service.region.clone();
    let allowed_request_methods = vec![Method::GET, Method::POST, Method::PUT];
    let allowed_content_types = vec!["application/x-www-form-urlencoded".to_string()];
    let gsk = GetSigningKeyFromDatabase::new(pool, &config.service.partition, &config.service.region, "iam");
    let service_impl = IamService {};
    let error_mapper = XmlErrorMapper::new(IAM_XML_NS);

    match config.service.tls {
        Some(t) => {
            info!("TLS configuration detected; creating acceptor and listener");
            let acceptor = TlsAcceptor::from(Arc::new(t));
            let tcp_listener = TcpListener::bind(&config.service.address).await?;
            let incoming = TlsIncoming::new(tcp_listener, acceptor);

            let service_maker: SpawnService<GetSigningKeyFromDatabase, IamService, XmlErrorMapper> =
                SpawnService::builder()
                    .region(region)
                    .service("iam")
                    .allowed_request_methods(allowed_request_methods)
                    .allowed_content_types(allowed_content_types)
                    .get_signing_key(gsk)
                    .implementation(service_impl)
                    .error_mapper(error_mapper)
                    .build()
                    .expect("Unable to create service maker");

            info!("Starting Hyper");

            HyperServer::builder(incoming).serve(service_maker).await?;
            Ok(())
        }
        None => {
            info!("Non-TLS configuration detected");
            let service_maker: SpawnService<GetSigningKeyFromDatabase, IamService, XmlErrorMapper> =
                SpawnService::builder()
                    .region(region)
                    .service("iam")
                    .allowed_request_methods(allowed_request_methods)
                    .allowed_content_types(allowed_content_types)
                    .get_signing_key(gsk)
                    .implementation(service_impl)
                    .error_mapper(error_mapper)
                    .build()
                    .expect("Unable to create service maker");

            info!("Starting Hyper");
            HyperServer::bind(&config.service.address).serve(service_maker).await?;
            Ok(())
        }
    }
}
