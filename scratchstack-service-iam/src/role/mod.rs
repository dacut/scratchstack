//! IAM role operations.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`].

mod attach_role_policy;
mod create_role;
mod delete_role;
mod delete_role_permissions_boundary;
mod delete_role_policy;
mod detach_role_policy;
mod get_role;
mod list_attached_role_policies;
mod list_role_policies;
mod list_roles;
mod put_role_permissions_boundary;
mod put_role_policy;
mod tag_role;
mod untag_role;
mod update_role;
mod update_role_description;

pub(crate) use {
    attach_role_policy::attach_role_policy, create_role::create_role, delete_role::delete_role,
    delete_role_permissions_boundary::delete_role_permissions_boundary, delete_role_policy::delete_role_policy,
    detach_role_policy::detach_role_policy, get_role::get_role,
    list_attached_role_policies::list_attached_role_policies, list_role_policies::list_role_policies,
    list_roles::list_roles, put_role_permissions_boundary::put_role_permissions_boundary,
    put_role_policy::put_role_policy, tag_role::tag_role, untag_role::untag_role, update_role::update_role,
    update_role_description::update_role_description,
};

use {
    crate::{authz::EntityResource, constants::*, policy::encode_policy_document, service::internal_failure},
    scratchstack_arn::Arn,
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::{RequestExecutor as _, partition::get_current_partition_or_fail},
    scratchstack_shapes_iam::{error_meta::Error as IamError, operation::GetRoleInternalRequest, types::Role},
    sqlx::postgres::PgTransaction,
    std::str::FromStr as _,
};

/// Percent-encode the trust policy a role reports, for the response reporting the role.
///
/// A role's trust policy is a policy document, and IAM reports it the way it reports every other
/// one: percent-encoded, leaving a client to URL-decode what it reads back. The database stores
/// and returns it as it was given, so the encoding belongs here, on the way out.
///
/// This is asymmetric with `CreateRole`, which reads the document as plain JSON once the query
/// string itself has been decoded.
pub(crate) fn encode_trust_policy(role: &mut Role) {
    if let Some(document) = role.assume_role_policy_document.as_mut() {
        *document = encode_policy_document(document);
    }
}

/// Build the ARN naming the IAM role `role_name` under `path` in `account_id`.
///
/// The path is part of a role's ARN, so a policy can be scoped to a path prefix; an operation
/// therefore cannot name the role it acts on without knowing the path. An operation acting on an
/// existing role reads the path from that role, while one creating a role takes it from the
/// request.
///
/// The partition is read from the database inside `tx`, so this must be called within the same
/// transaction as the operation it authorizes.
///
/// Returns the ready-to-send error response if the partition could not be read or the resulting
/// ARN is not well-formed; neither is something the caller can act on.
pub(crate) async fn role_arn(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    path: &str,
    role_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    let partition = match get_current_partition_or_fail(tx, request_id).await {
        Ok(partition) => partition,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // A role's ARN spells its path between the resource type and the name, with the surrounding
    // slashes collapsed: the root path "/" yields "role/Name" rather than "role//Name".
    let resource_path = path.trim_matches('/');
    let resource = if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_ROLE}/{role_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_ROLE}/{resource_path}/{role_name}")
    };

    Arn::builder().partition(partition).service(SERVICE_IAM).account_id(account_id).resource(resource).build().map_err(
        |e| {
            log::error!("{request_id}: Could not construct ARN for role {role_name}: {e}");
            Box::new(internal_failure(request_id))
        },
    )
}

/// Look up the role named `role_name` in `account_id` and describe it as the resource an
/// operation acts on: the ARN naming it, the tags attached to it, and the permissions boundary
/// set on it.
///
/// An operation acting on an existing role cannot name it without this lookup: the resource ARN
/// carries the role's path and the policy may be conditioned on the role's tags or on the
/// boundary set on it, and a request naming the role supplies none of those. The lookup runs inside `tx`, so what is authorized is what
/// the operation goes on to act on.
///
/// Authorization is still evaluated when no such role exists, so that a caller allowed the action
/// broadly is told the role does not exist while one allowed it only on specific roles learns
/// nothing at all. There is no role to read any of that from in that case, so the root path is
/// assumed and neither tags nor a boundary are reported; the operation itself then reports the missing role.
///
/// Returns the ready-to-send error response if the lookup failed for any reason other than the
/// role not existing.
pub(crate) async fn role_resource(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    role_name: &str,
) -> Result<EntityResource, Box<Response<Body>>> {
    let request =
        match GetRoleInternalRequest::builder().account_id(account_id.to_string()).role_name(role_name).build() {
            Ok(request) => request,
            Err(mut e) => {
                e.request_id = Some(request_id.to_string());
                return Err(Box::new(e.respond()));
            }
        };

    let role = match request.execute(tx, request_id).await {
        Ok(response) => response.role,
        Err(IamError::NoSuchEntityException(_)) => {
            return Ok(EntityResource {
                arn: role_arn(tx, request_id, account_id, "/", role_name).await?,
                permissions_boundary: None,
                tags: Vec::new(),
            });
        }
        Err(e) => return Err(Box::new(e.respond())),
    };

    match Arn::from_str(&role.arn) {
        Ok(arn) => Ok(EntityResource {
            arn,
            // A boundary is stored as the managed policy serving as it, so what the entity
            // reports is an attachment wrapping that policy's ARN; an entity under no boundary
            // reports no attachment at all.
            permissions_boundary: role.permissions_boundary.and_then(|boundary| boundary.permissions_boundary_arn),
            tags: role.tags,
        }),
        Err(e) => {
            log::error!("{request_id}: Role {role_name} has an unparseable ARN {}: {e}", role.arn);
            Err(Box::new(internal_failure(request_id)))
        }
    }
}
