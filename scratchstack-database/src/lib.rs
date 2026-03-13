//! Scratchstack database schema and models

mod constants;
mod core;
mod gsk_direct;
/// Database schema and models.
pub mod model;
pub use {core::*, gsk_direct::*};
