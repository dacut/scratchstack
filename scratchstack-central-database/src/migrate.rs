//! Database migration utilities.
use sqlx::{migrate, migrate::Migrator};

/// Migrations for the Scratchstack IAM database
pub static MIGRATOR: Migrator = migrate!("./migrations/iam");
