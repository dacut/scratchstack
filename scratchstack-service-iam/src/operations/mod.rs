//! The IAM operations this service implements.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`]. What they share is gathered here: the ARN an operation
//! names the user it acts on by, which both the authorization check and the error responses are
//! built around.

mod create_user;
mod delete_user;
mod get_user;
mod list_users;

pub(crate) use {create_user::create_user, delete_user::delete_user, get_user::get_user, list_users::list_users};

use {
    crate::{constants::*, service::internal_failure},
    scratchstack_arn::Arn,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::partition::get_current_partition_or_fail,
    sqlx::postgres::PgTransaction,
};

/// Build the ARN naming the IAM user `user_name` under `path` in `account_id`.
///
/// The path is part of a user's ARN, so a policy can be scoped to a path prefix; an operation
/// therefore cannot name the user it acts on without knowing the path. An operation acting on an
/// existing user reads the path from that user, while one creating a user takes it from the
/// request.
///
/// The partition is read from the database inside `tx`, so this must be called within the same
/// transaction as the operation it authorizes.
///
/// Returns the ready-to-send error response if the partition could not be read or the resulting
/// ARN is not well-formed; neither is something the caller can act on.
pub(crate) async fn user_arn(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    path: &str,
    user_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    let partition = match get_current_partition_or_fail(tx, request_id).await {
        Ok(partition) => partition,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // A user's ARN spells its path between the resource type and the name, with the surrounding
    // slashes collapsed: the root path "/" yields "user/Name" rather than "user//Name".
    let resource_path = path.trim_matches('/');
    let resource = if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_USER}/{user_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_USER}/{resource_path}/{user_name}")
    };

    Arn::builder().partition(partition).service(SERVICE_IAM).account_id(account_id).resource(resource).build().map_err(
        |e| {
            log::error!("{request_id}: Could not construct ARN for user {user_name}: {e}");
            Box::new(internal_failure(request_id))
        },
    )
}
