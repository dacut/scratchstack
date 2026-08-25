//! The IAM operations this service implements.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`]. What they share is gathered here: the ARN an operation
//! names the user it acts on by, which both the authorization check and the error responses are
//! built around.

mod attach_user_policy;
mod create_user;
mod delete_user;
mod delete_user_permissions_boundary;
mod delete_user_policy;
mod detach_user_policy;
mod get_user;
mod get_user_policy;
mod list_attached_user_policies;
mod list_user_policies;
mod list_user_tags;
mod list_users;
mod put_user_permissions_boundary;
mod put_user_policy;
mod tag_user;
mod untag_user;

pub(crate) use {
    attach_user_policy::attach_user_policy, create_user::create_user, delete_user::delete_user,
    delete_user_permissions_boundary::delete_user_permissions_boundary, delete_user_policy::delete_user_policy,
    detach_user_policy::detach_user_policy, get_user::get_user, get_user_policy::get_user_policy,
    list_attached_user_policies::list_attached_user_policies, list_user_policies::list_user_policies,
    list_user_tags::list_user_tags, list_users::list_users,
    put_user_permissions_boundary::put_user_permissions_boundary, put_user_policy::put_user_policy, tag_user::tag_user,
    untag_user::untag_user,
};

use {
    crate::{constants::*, service::internal_failure},
    pct_str::{PctString, UriReserved},
    scratchstack_arn::Arn,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::{RequestExecutor as _, partition::get_current_partition_or_fail},
    scratchstack_shapes_iam::{error_meta::Error as IamError, operation::GetUserInternalRequest, types::Tag},
    sqlx::postgres::PgTransaction,
    std::str::FromStr as _,
};

/// Percent-encode a policy document for the response reporting it.
///
/// IAM does not report a policy document as the JSON it stores: it reports it percent-encoded,
/// leaving a client to URL-decode what it reads back. The encoding is RFC 3986's, escaping
/// everything outside the unreserved set, which is what [`UriReserved::Any`] describes.
///
/// This is asymmetric with the operations that take a policy document, which read it as plain
/// JSON once the query string itself has been decoded. The database stores and returns the
/// document as it was given, so the encoding belongs here, on the way out, and nowhere else.
pub(crate) fn encode_policy_document(policy_document: &str) -> String {
    PctString::encode(policy_document.chars(), UriReserved::Any).into_string()
}

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

/// Look up the user named `user_name` in `account_id` and describe it as the resource an
/// operation acts on: the ARN naming it, and the tags attached to it.
///
/// An operation acting on an existing user cannot name it without this lookup: the resource ARN
/// carries the user's path and the policy may be conditioned on the user's tags, and a request
/// naming the user supplies neither. The lookup runs inside `tx`, so what is authorized is what
/// the operation goes on to act on.
///
/// Authorization is still evaluated when no such user exists, so that a caller allowed the action
/// broadly is told the user does not exist while one allowed it only on specific users learns
/// nothing at all. There is no user to read a path or tags from in that case, so the root path is
/// assumed and no tags are reported; the operation itself then reports the missing user.
///
/// Returns the ready-to-send error response if the lookup failed for any reason other than the
/// user not existing.
pub(crate) async fn user_resource(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    user_name: &str,
) -> Result<(Arn, Vec<Tag>), Box<Response<Body>>> {
    let request =
        match GetUserInternalRequest::builder().account_id(account_id.to_string()).user_name(user_name).build() {
            Ok(request) => request,
            Err(mut e) => {
                e.request_id = Some(request_id.to_string());
                return Err(Box::new(e.respond()));
            }
        };

    let user = match request.execute(tx, request_id).await {
        Ok(response) => response.user,
        Err(IamError::NoSuchEntityException(_)) => {
            return Ok((user_arn(tx, request_id, account_id, "/", user_name).await?, Vec::new()));
        }
        Err(e) => return Err(Box::new(e.respond())),
    };

    match Arn::from_str(&user.arn) {
        Ok(arn) => Ok((arn, user.tags)),
        Err(e) => {
            log::error!("{request_id}: User {user_name} has an unparseable ARN {}: {e}", user.arn);
            Err(Box::new(internal_failure(request_id)))
        }
    }
}
