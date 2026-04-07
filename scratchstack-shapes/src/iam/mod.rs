//! Identity and Access Management (IAM) API shapes.

mod account_id;
mod path;
mod policy;
mod tag;
mod user;

pub use {account_id::*, path::*, policy::*, tag::*, user::*};
