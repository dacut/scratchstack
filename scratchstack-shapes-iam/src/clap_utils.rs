//! Clap command line parsing utilities

use std::{fmt::Display, str::FromStr};

/// Parses a string into an optional boolean for Clap.
pub fn parse_opt_bool(value_str: &str) -> Result<Option<bool>, String> {
    let value: bool = value_str.parse().map_err(|e| format!("Value must be a boolean: {e}"))?;
    Ok(Some(value))
}

/// Parses a string into an optional i8 for Clap.
pub fn parse_opt_i8(value_str: &str) -> Result<Option<i8>, String> {
    let value: i8 = value_str.parse().map_err(|e| format!("Value must be an 8-bit integer: {e}"))?;
    Ok(Some(value))
}

/// Parses a string into an optional i16 for Clap.
pub fn parse_opt_i16(value_str: &str) -> Result<Option<i16>, String> {
    let value: i16 = value_str.parse().map_err(|e| format!("Value must be a 16-bit integer: {e}"))?;
    Ok(Some(value))
}

/// Parses a string into an optional i32 for Clap.
pub fn parse_opt_i32(value_str: &str) -> Result<Option<i32>, String> {
    let value: i32 = value_str.parse().map_err(|e| format!("Value must be an integer: {e}"))?;
    Ok(Some(value))
}

/// Parses a string into an optional i64 for Clap.
pub fn parse_opt_i64(value_str: &str) -> Result<Option<i64>, String> {
    let value: i64 = value_str.parse().map_err(|e| format!("Value must be a 64-bit integer: {e}"))?;
    Ok(Some(value))
}

/// Parses a string into an optional string for Clap.
pub fn parse_opt_string(value_str: &str) -> Result<Option<String>, String> {
    Ok(Some(value_str.to_string()))
}

/// Parses a string into a string for Clap.
#[inline(always)]
pub fn parse_string(value_str: &str) -> Result<String, String> {
    Ok(value_str.to_string())
}

/// Parses a string into an optional list of values for Clap.
pub fn parse_opt_list<T>(value_str: &str) -> Result<Option<Vec<T>>, String>
where
    T: FromStr,
    T::Err: Display,
{
    let list = parse_list(value_str)?;
    Ok(Some(list))
}

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
