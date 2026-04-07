//! Database operations for the Scratchstack IAM database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.

mod create_account;
mod create_user;
mod get_current_partition;
mod list_accounts;
mod set_current_partition;

pub use {create_account::*, get_current_partition::*, list_accounts::*, set_current_partition::*};
