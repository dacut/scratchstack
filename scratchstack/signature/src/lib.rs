#![feature(backtrace)]

extern crate chrono;
extern crate hex;
extern crate lazy_static;
extern crate regex;
extern crate ring;

pub mod signature;
pub use crate::signature::{AWSSigV4, Request, SignatureError};

#[cfg(test)]
mod unittest;
