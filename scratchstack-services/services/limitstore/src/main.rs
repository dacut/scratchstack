// use std::collections::HashMap;
// use std::panic::RefUnwindSafe;
// use std::sync::Arc;

// use futures::future;
// use gotham::handler::{Handler, HandlerFuture, NewHandler};
// use gotham::helpers::http::response::create_empty_response;
// use gotham::state::{FromState, State};
// use hyper::header::{HeaderMap, HOST};
// use hyper::StatusCode;
use std::env;
use std::io;
use std::io::Write;
use std::path::Path;

use getopts::Options;
use gotham;
use gotham::router::Router;
use gotham::router::builder::{build_router, DefineSingleRoute, DrawRoutes};
use gotham::pipeline::{new_pipeline, single_middleware};
use rustls::{ServerConfig as TlsServerConfig};

mod config;
use crate::config::{Config, ConfigError, ConnectionManager};

const DEFAULT_CONFIG_FILENAME: &str = "scratchstack.cfg";

pub struct LimitStore {
    pub config: Config,
    pub connection_manager: ConnectionManager,
    pub tls_config: Option<TlsServerConfig>,
}

impl LimitStore {
    pub fn from_config_file<P: AsRef<Path>>(path: P) -> Result<LimitStore, ConfigError> {
        let config = Config::read_file(path)?;
        let connection_manager = config.database.to_connection_manager()?;
        let tls_config = match &config.tls {
            None => None,
            Some(tls) => Some(tls.to_server_config()?),
        };

        Ok(LimitStore {
            config: config,
            connection_manager: connection_manager,
            tls_config: tls_config,
        })
    }

    pub fn run(&self) {
        let n_threads = match self.config.threads {
            None | Some(0) => 1,
            Some(n) => n
        };

        let address = match self.config.address {
            None => "127.0.0.1",
            Some(addr) => &addr,
        };

        let port = match self.config.port {
            None => 8080,
            Some(port) => port
        };

        // match self.tls_config {
        //     Some(tls_config) => gotham::tls::start_with_num_threads(
        //         (address, port), handler, tls_config, n_threads),
        //     None => gotham::plain::start_with_num_threads(
        //         (address, port), handler, n_threads),
        // }
    }
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

    let limit_store = match LimitStore::from_config_file(&config_filename) {
        Ok(ls) => ls,
        Err(e) => {
            eprint!("Unable to open {}: {}\n", config_filename, e);
            return;
        }
    };

}