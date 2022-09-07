#![warn(clippy::all)]
mod arn;
mod error;
pub mod utils;

pub use {
    arn::{Arn, ArnPattern, ArnSegmentPattern},
    error::ArnError,
};
