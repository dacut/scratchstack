#![feature(backtrace)]

extern crate chrono;
extern crate hex;
extern crate lazy_static;
extern crate regex;
extern crate ring;

pub mod signature;
mod chronoutil;
pub use crate::signature::{
    AWSSigV4, ErrorKind, Request, SignatureError
};

#[cfg(test)]
mod unittest;
