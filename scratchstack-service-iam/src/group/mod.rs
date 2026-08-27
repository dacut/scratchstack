//! IAM group operations.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`].

mod create_group;
mod delete_group;
mod get_group;
mod update_group;

pub(crate) use {
    create_group::create_group, delete_group::delete_group, get_group::get_group, update_group::update_group,
};

use {
    crate::{constants::*, service::internal_failure},
    scratchstack_arn::Arn,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::{group::get_group_path_and_name, partition::get_current_partition_or_fail},
    sqlx::postgres::PgTransaction,
};

/// Build the ARN naming the IAM group `group_name` under `path` in `account_id`.
///
/// The path is part of a group's ARN, so a policy can be scoped to a path prefix; an operation
/// therefore cannot name the group it acts on without knowing the path. An operation acting on an
/// existing group reads the path from that group, while one creating a group takes it from the
/// request.
///
/// The partition is read from the database inside `tx`, so this must be called within the same
/// transaction as the operation it authorizes.
///
/// Returns the ready-to-send error response if the partition could not be read or the resulting
/// ARN is not well-formed; neither is something the caller can act on.
pub(crate) async fn group_arn(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    path: &str,
    group_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    let partition = match get_current_partition_or_fail(tx, request_id).await {
        Ok(partition) => partition,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // A group's ARN spells its path between the resource type and the name, with the surrounding
    // slashes collapsed: the root path "/" yields "group/Name" rather than "group//Name".
    let resource_path = path.trim_matches('/');
    let resource = if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_GROUP}/{group_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_GROUP}/{resource_path}/{group_name}")
    };

    Arn::builder().partition(partition).service(SERVICE_IAM).account_id(account_id).resource(resource).build().map_err(
        |e| {
            log::error!("{request_id}: Could not construct ARN for group {group_name}: {e}");
            Box::new(internal_failure(request_id))
        },
    )
}

/// Look up the group named `group_name` in `account_id` and report the ARN naming it, which is
/// the resource an operation acting on it is authorized against.
///
/// An operation acting on an existing group cannot name it without this lookup: the resource ARN
/// carries the group's path, and a request naming the group by name alone does not supply it. The
/// lookup runs inside `tx`, so what is authorized is what the operation goes on to act on.
///
/// Unlike a user or a role, a group carries neither tags nor a permissions boundary -- IAM does
/// not support tagging groups, and a boundary may only be set on a user or a role -- so an ARN is
/// the whole of what a group contributes to an authorization decision. That is why this returns a
/// bare [`Arn`] rather than the [`crate::authz::EntityResource`] the user and role lookups
/// return, and why the operations on groups supply an empty request context.
///
/// Authorization is still evaluated when no such group exists, so that a caller allowed the
/// action broadly is told the group does not exist while one allowed it only on specific groups
/// learns nothing at all. There is no group to read a path from in that case, so the root path is
/// assumed and the name is taken as the request spelled it; the operation itself then reports the
/// missing group.
///
/// Returns the ready-to-send error response if the lookup failed for any reason other than the
/// group not existing.
pub(crate) async fn group_resource(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    group_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    // The lookup reads the group's path and stored name and nothing else. `GetGroup` would answer
    // the same question, but it reports the group's members as well, and an operation that only
    // needs to name the group would be paying for a membership listing it throws away.
    let (path, group_name) = match get_group_path_and_name(tx, account_id, group_name, request_id).await {
        Ok(Some(found)) => found,
        Ok(None) => ("/".to_string(), group_name.to_string()),
        Err(e) => return Err(Box::new(e.respond())),
    };

    group_arn(tx, request_id, account_id, &path, &group_name).await
}

/// Split the resource half of a group's ARN into the path and the group name it spells.
///
/// This is the inverse of what [`group_arn`] builds: a group's ARN carries its path between the
/// resource type and the name with the surrounding slashes collapsed, so `group/division/Admins`
/// names Admins under `/division/` and `group/Admins` names Admins under `/`.
///
/// `UpdateGroup` needs both halves back because a request may replace either one alone, and the
/// ARN the other half comes from is the one the group carries -- which is where the group's name
/// appears with the casing it was created under.
pub(crate) fn group_arn_path_and_name(resource: &str) -> (String, String) {
    let resource = resource.strip_prefix(ARN_RESOURCE_TYPE_GROUP).unwrap_or(resource).trim_matches('/');

    match resource.rsplit_once('/') {
        Some((path, group_name)) => (format!("/{path}/"), group_name.to_string()),
        None => ("/".to_string(), resource.to_string()),
    }
}
