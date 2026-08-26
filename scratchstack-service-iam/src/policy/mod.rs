//! IAM managed policy operations.
//!
//! Each operation lives in its own module and is dispatched to by
//! [`crate::service::serve_request`].

mod create_policy;
mod delete_policy;
mod get_policy;
mod list_policies;

pub(crate) use {
    create_policy::create_policy, delete_policy::delete_policy, get_policy::get_policy, list_policies::list_policies,
};

use {
    crate::{constants::*, service::internal_failure},
    pct_str::{PctString, UriReserved},
    scratchstack_arn::{Arn, IamResourceArn},
    scratchstack_core::{
        RequestId,
        axum::{body::Body, response::Response},
        response::Responder as _,
    },
    scratchstack_iam_database::{
        partition::get_current_partition_or_fail,
        policy::{get_policy as read_policy, validate_policy_name},
    },
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::{
            Tag,
            error::{NoSuchEntityException, ValidationError},
        },
    },
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

/// Generate the `NoSuchEntity` error response reporting that `policy_arn` names no policy.
///
/// The database reports a policy it cannot find in these words; an operation that decides on its
/// own that a policy is out of the caller's reach reports it in the same ones, so that the two
/// cases are indistinguishable to a caller -- which is the point of reporting the second that
/// way at all.
pub(crate) fn no_such_policy(request_id: RequestId, policy_arn: &str) -> Response<Body> {
    NoSuchEntityException::builder()
        .message(format!("Policy {policy_arn} was not found."))
        .request_id(request_id)
        .build()
        .respond()
}

/// Build the ARN naming the managed policy `policy_name` under `path` in `account_id`.
///
/// The path is part of a policy's ARN, so a policy can be scoped to a path prefix; an operation
/// therefore cannot name the policy it acts on without knowing the path. An operation acting on
/// an existing policy reads the path from that policy, while one creating a policy takes it from
/// the request.
///
/// The partition is read from the database inside `tx`, so this must be called within the same
/// transaction as the operation it authorizes.
///
/// Returns the ready-to-send error response if the partition could not be read or the resulting
/// ARN is not well-formed; neither is something the caller can act on.
pub(crate) async fn policy_arn(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    path: &str,
    policy_name: &str,
) -> Result<Arn, Box<Response<Body>>> {
    let partition = match get_current_partition_or_fail(tx, request_id).await {
        Ok(partition) => partition,
        Err(e) => return Err(Box::new(e.respond())),
    };

    // A policy's ARN spells its path between the resource type and the name, with the surrounding
    // slashes collapsed: the root path "/" yields "policy/Name" rather than "policy//Name".
    let resource_path = path.trim_matches('/');
    let resource = if resource_path.is_empty() {
        format!("{ARN_RESOURCE_TYPE_POLICY}/{policy_name}")
    } else {
        format!("{ARN_RESOURCE_TYPE_POLICY}/{resource_path}/{policy_name}")
    };

    Arn::builder().partition(partition).service(SERVICE_IAM).account_id(account_id).resource(resource).build().map_err(
        |e| {
            log::error!("{request_id}: Could not construct ARN for policy {policy_name}: {e}");
            Box::new(internal_failure(request_id))
        },
    )
}

/// Parse the policy ARN a request names into the resource an operation acts on.
///
/// An operation naming a managed policy by ARN needs that ARN as an [`Arn`] before it can do
/// anything else: it is the resource the request is authorized against, and it is what says which
/// account the policy belongs to. The checks here are the ones
/// [`scratchstack_iam_database::policy`] makes of the same ARN, repeated so that an operation
/// that never reaches the database -- because the ARN names a policy outside the caller's reach
/// -- rejects a malformed one in the same words as one that does.
///
/// Returns the ready-to-send error response when the request named something that is not a policy
/// ARN.
pub(crate) fn policy_resource_arn(request_id: RequestId, policy_arn: &str) -> Result<Arn, Box<Response<Body>>> {
    let validation_error =
        |message: &str| Box::new(ValidationError::builder().message(message).request_id(request_id).build().respond());

    let arn = Arn::from_str(policy_arn).map_err(|e| {
        log::debug!("{request_id}: Could not parse policy ARN {policy_arn}: {e}");
        validation_error(MSG_INVALID_POLICY_ARN)
    })?;

    // An IAM resource ARN is what splits the resource into a type, a path, and a name; anything
    // naming another service is not a policy ARN at all.
    let iam_arn = IamResourceArn::try_from(arn.clone()).map_err(|e| {
        log::debug!("{request_id}: Policy ARN {policy_arn} is not an IAM resource ARN: {e}");
        validation_error(MSG_INVALID_POLICY_ARN)
    })?;

    if !iam_arn.region().is_empty() {
        return Err(validation_error(MSG_POLICY_ARN_REGION));
    }

    if iam_arn.resource_type() != ARN_RESOURCE_TYPE_POLICY {
        return Err(validation_error(MSG_POLICY_ARN_RESOURCE));
    }

    if let Err(e) = validate_policy_name(iam_arn.resource_name(), request_id) {
        return Err(Box::new(e.respond()));
    }

    Ok(arn)
}

/// Whether a caller in `account_id` may read the policy `policy_arn` names.
///
/// A caller reaches the policies of its own account and the AWS-managed policies, which every
/// account shares and none owns. Nothing else is visible: managed policies are not shared across
/// customer accounts, and a lookup by ARN alone would otherwise report another account's policy
/// to any caller holding a grant written against `Resource: "*"`.
pub(crate) fn policy_is_visible(account_id: &str, policy_arn: &Arn) -> bool {
    policy_is_owned(account_id, policy_arn)
        || policy_arn.account_id() == AWS_ACCOUNT_ID
        || policy_arn.account_id() == AWS_ACCOUNT_ID_NUMERIC
}

/// Whether the policy `policy_arn` names belongs to `account_id`, and so may be modified by a
/// caller in it.
///
/// This is stricter than [`policy_is_visible`] by the AWS-managed policies: those are readable by
/// every account, and modifiable by none, since one account changing a policy every account
/// shares would change it for all of them.
pub(crate) fn policy_is_owned(account_id: &str, policy_arn: &Arn) -> bool {
    policy_arn.account_id() == account_id
}

/// Look up the managed policy `policy_arn` names and describe it as the resource an operation
/// acts on: the ARN naming it, and the tags attached to it.
///
/// An operation acting on an existing policy cannot name it without this lookup: the resource ARN
/// carries the policy's path and the stored spelling of its name, and the policy governing the
/// caller may be conditioned on the policy's tags. The lookup runs inside `tx`, so what is
/// authorized is what the operation goes on to act on.
///
/// `account_id` is the caller's account, which is the account the attachment counts the lookup
/// reports are counted within; nothing here reads those counts, but the lookup answers them.
///
/// Authorization is still evaluated when no such policy exists, so that a caller allowed the
/// action broadly is told the policy does not exist while one allowed it only on specific
/// policies learns nothing at all. There is nothing to read tags from in that case, so the ARN
/// the request named is reported as it stands and no tags are reported; the operation itself then
/// reports the missing policy.
///
/// Returns the ready-to-send error response if the lookup failed for any reason other than the
/// policy not existing.
pub(crate) async fn policy_resource(
    tx: &mut PgTransaction<'_>,
    request_id: RequestId,
    account_id: &str,
    policy_arn: &Arn,
) -> Result<(Arn, Vec<Tag>), Box<Response<Body>>> {
    let policy = match read_policy(tx, account_id, &policy_arn.to_string(), request_id).await {
        Ok(response) => response.policy,
        Err(IamError::NoSuchEntityException(_)) => return Ok((policy_arn.clone(), Vec::new())),
        Err(e) => return Err(Box::new(e.respond())),
    };

    // The database reports the policy it found, and the ARN naming it; a response missing either
    // is a database-layer invariant violation rather than anything the caller did.
    let Some(arn) = policy.as_ref().and_then(|policy| policy.arn.as_deref()) else {
        log::error!("{request_id}: Lookup of policy {policy_arn} reported no policy ARN");
        return Err(Box::new(internal_failure(request_id)));
    };

    match Arn::from_str(arn) {
        Ok(resource_arn) => Ok((resource_arn, policy.expect("the ARN came from the policy").tags)),
        Err(e) => {
            log::error!("{request_id}: Policy {policy_arn} has an unparseable ARN {arn}: {e}");
            Err(Box::new(internal_failure(request_id)))
        }
    }
}
