use std::env;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

use diesel::pg::PgConnection;
use getopts::Options;
use gotham;
use gotham::handler::{Handler, HandlerFuture, IntoHandlerError, NewHandler};
use gotham::router::Router;
use gotham::router::builder::{build_router, DefineSingleRoute, DrawRoutes};
use gotham::pipeline::new_pipeline;
use gotham::pipeline::single::single_pipeline;
use gotham::state::State;
// use gotham_middleware_aws_sig_verify::{
//     AWSSigV4Verifier, ErrorKind as SignatureErrorKind, SignatureError,
//     SigningKeyKind};
use gotham_middleware_diesel::{DieselMiddleware, Repo};
use hyper::StatusCode;
use rustls::{ServerConfig as TlsServerConfig};

mod config;
use crate::config::{Config, ConfigError, ConfigErrorKind};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg";

pub struct IAM {
    pub config: Config,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub tls_config: Option<TlsServerConfig>,
    pub repo: Option<Repo<PgConnection>>,
}

impl IAM {
    pub fn from_config_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let config = Config::read_file(path)?;

        let tls_config = match &config.tls {
            None => None,
            Some(tls) => Some(tls.to_server_config()?),
        };

        let server_address: IpAddr = match &config.address {
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(addr) => IpAddr::from_str(addr)?,
        };

        let server_port = match config.port {
            None => 8080,
            Some(port) if port > 0 => port,
            _ => return Err(ConfigError{kind: ConfigErrorKind::InvalidPort}),
        };

        let url = config.database.get_postgres_url()?;
        let pb = config.database.get_pool_builder()?;
        let repo = Repo::from_pool_builder(&url, pb);

        Ok(Self {
            config: config,
            server_address: server_address,
            server_port: server_port,
            tls_config: tls_config,
            repo: Some(repo),
        })
    }

    pub fn run(&mut self) {
        let n_threads = match self.config.threads {
            None | Some(0) => 1,
            Some(n) => n
        };
        
        let dm = DieselMiddleware::new(self.repo.take().unwrap());

        let (chain, pipelines) = single_pipeline(
            new_pipeline().add(dm).build());

        let router = build_router(chain, pipelines, |route| {
            route.get("/").to(dummy_handler);
        });

        match self.tls_config {
            Some(ref tls_config) =>
                gotham::tls::start_with_num_threads(
                    (self.server_address, self.server_port), router,
                    tls_config.clone(), n_threads),
            None => gotham::plain::start_with_num_threads(
                (self.server_address, self.server_port), router,
                n_threads),
        }
    }
}

const HELLO_WORLD: &str = "Hello world";

fn dummy_handler(state: State) -> (State, &'static str) {
    (state, HELLO_WORLD)
}

#[allow(unused_must_use)]
fn print_usage(stream: &mut dyn Write, program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    write!(stream, "{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "configuration file", "FILENAME");
    opts.optflag("h", "help", "print this usage information");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&mut io::stdout(), &program, opts);
        return;
    }

    let config_filename = match matches.opt_str("c") {
        Some(filename) => filename.to_string(),
        None => DEFAULT_CONFIG_FILENAME.to_string(),
    };

    if !matches.free.is_empty() {
        print_usage(&mut io::stderr(), &program, opts);
        return;
    }

    let mut service = match IAM::from_config_file(&config_filename) {
        Ok(ls) => ls,
        Err(e) => {
            eprint!("Unable to open {}: {}\n", config_filename, e);
            return;
        }
    };

    service.run()
}