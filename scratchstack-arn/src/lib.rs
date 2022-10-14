#![warn(clippy::all)]
mod arn;
mod error;
mod pattern;
pub mod utils;

pub use {
    arn::{Arn, ArnPattern},
    error::ArnError,
    pattern::GlobPattern,
};

pub type ArnSegmentPattern = GlobPattern;
