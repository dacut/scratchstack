//! Clap command line parsing utilities
use std::{fmt::Display, str::FromStr};

/// Parses a string into a list of values for Clap.
pub fn parse_list<T>(value_str: &str) -> Result<Vec<T>, String>
where
    T: FromStr,
    T::Err: Display,
{
    value_str
        .split(',')
        .map(|s| s.trim().parse::<T>().map_err(|e| format!("Failed to parse list item '{s}': {e}")))
        .collect()
}
