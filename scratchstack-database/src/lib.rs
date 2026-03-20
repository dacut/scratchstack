//! Scratchstack database schema and models

mod constants;
mod core;
pub use core::*;

#[cfg(feature = "gsk-direct")]
mod gsk_direct;
#[cfg(feature = "gsk-direct")]
pub use gsk_direct::*;

/// Database schema and models.
pub mod model;
