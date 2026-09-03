//! GetGroup database operation
use {
    crate::{
        RequestExecutor,
        account::validate_account_id,
        constants::*,
        constrain_max_items, decrypt_pagination_token,
        group::{group_arn_resource, validate_group_name},
        internal_failure, make_iam_paginator,
        partition::get_current_partition_or_fail,
        policy::build_policy_arn,
        user::user_arn_resource,
    },
    chrono::{DateTime, Utc},
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{GetGroupInternalRequest, GetGroupResponse},
        types::{
            AttachedPermissionsBoundary, Group, PermissionsBoundaryAttachmentType, User, error::NoSuchEntityException,
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for GetGroupInternalRequest {
    type Response = GetGroupResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>, request_id: RequestId) -> Result<Self::Response, Self::Error> {
        get_group(tx, &self.account_id, &self.group_name, self.marker.as_deref(), self.max_items, request_id).await
    }
}

/// The marker innards for a GetGroup operation. GetGroup pages through the group's members, so
/// the marker names the next user rather than the next group.
#[derive(Deserialize, Serialize)]
struct GetGroupMarker {
    next_user_name: String,
}

/// The rows returned by the GetGroup membership query. The `pb_*` columns come from a LEFT JOIN
/// against iam.managed_policies on permissions_boundary_managed_policy_id, so the join keeps the
/// row even when a member has no PB and the projection avoids the N+1 lookup per member.
#[derive(FromRow)]
struct GetGroupMemberRow {
    user_id: String,
    user_account_id: String,
    user_name_lower: String,
    user_name_cased: String,
    path: String,
    permissions_boundary_managed_policy_id: Option<String>,
    created_at: DateTime<Utc>,
    pb_account_id: Option<String>,
    pb_path: Option<String>,
    pb_name_cased: Option<String>,
}

/// Look up the path and stored name of a group, without reading anything else about it.
///
/// [`get_group`] reports the group's members too, which means paging through
/// `iam.group_memberships` and joining `iam.users`. A caller that only needs to name the group --
/// to build the ARN an operation is authorized against, say -- would pay for a membership listing
/// it then throws away, so that lookup is available on its own here.
///
/// The name comes back with the casing the group was created under rather than the casing the
/// caller spelled, since that is the casing the group's ARN carries; group names themselves are
/// matched case-insensitively.
///
/// Returns `Ok(None)` when no such group exists. That is not an error at this level: a caller
/// looking a group up in order to authorize against it still has to authorize a request naming a
/// group that does not exist, and decides for itself what to name in that case.
pub async fn get_group_path_and_name(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    request_id: RequestId,
) -> Result<Option<(String, String)>, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;

    let row = query(indoc! {"
            SELECT path, group_name_cased
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(group_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to fetch group from database: {e}"))?;

    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// Get a group and the users belonging to it from the database. Returns NoSuchEntity if the group
/// does not exist.
///
/// The membership listing is paginated the way every other listing here is: `max_items` bounds a
/// page and `marker` continues from where the previous page stopped. The group itself is reported
/// in full on every page, since it is the group being read rather than an element of the listing.
pub async fn get_group(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    group_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    request_id: RequestId,
) -> Result<GetGroupResponse, IamError> {
    validate_account_id(account_id, request_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_group_name(group_name, request_id)?;
    let group_name_lower = group_name.to_lowercase();
    let max_items = constrain_max_items(max_items, request_id)?;

    let partition = get_current_partition_or_fail(tx, request_id).await?;

    let row = query(indoc! {"
            SELECT group_id, group_name_cased, path, created_at
            FROM iam.groups
            WHERE account_id = $1 AND group_name_lower = $2
        "})
    .bind(account_id)
    .bind(&group_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to fetch group from database: {e}"))?;

    let row = row.ok_or_else(|| {
        NoSuchEntityException::builder()
            .message(format!("The group with name {group_name} cannot be found."))
            .request_id(request_id)
            .build()
    })?;

    let group_id: String = row.get(0);
    let group_name_cased: String = row.get(1);
    let path: String = row.get(2);
    let created_at: DateTime<Utc> = row.get(3);

    let arn = Arn::builder()
        .partition(partition.clone())
        .service(SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(group_arn_resource(&path, &group_name_cased))
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to construct ARN for group: {e}"))?;

    let group = Group::builder()
        .arn(arn.to_string())
        .create_date(created_at)
        .path(path)
        .group_id(format!("{}{}", IamResourceType::Group.as_str(), group_id))
        .group_name(group_name_cased)
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to construct group object: {e}"))?;

    let paginator = make_iam_paginator(&partition, OP_GET_GROUP, request_id)?;

    // The membership rows are keyed on the group id, which is unique across accounts, so the
    // members are reached through it rather than through the account the group belongs to. Each
    // member's ARN is then built from the account that member belongs to rather than from the
    // group's, so a member is named by the account that actually owns it.
    let mut sql = QueryBuilder::new(
        r#"
        SELECT u.user_id, u.account_id AS user_account_id, u.user_name_lower, u.user_name_cased, u.path,
            u.permissions_boundary_managed_policy_id, u.created_at,
            pb.account_id AS pb_account_id, pb.path AS pb_path,
            pb.managed_policy_name_cased AS pb_name_cased
        FROM iam.users u
        INNER JOIN iam.group_memberships gm ON gm.user_id = u.user_id
        LEFT JOIN iam.managed_policies pb
            ON pb.managed_policy_id = u.permissions_boundary_managed_policy_id
        WHERE gm.group_id =
    "#,
    );
    sql.push_bind(&group_id);

    if let Some(marker) = marker {
        let info: GetGroupMarker = decrypt_pagination_token(&paginator, marker, OP_GET_GROUP, request_id).await?;
        sql.push(" AND u.user_name_lower >= ");
        sql.push_bind(info.next_user_name);
    }

    // Request one more than max_items so we can determine if there are more results.
    sql.push(" ORDER BY u.user_name_lower ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql
        .build_query_as::<GetGroupMemberRow>()
        .fetch_all(tx.as_mut())
        .await
        .map_err(|e| internal_failure!(request_id; "Failed to fetch group members from database: {e}"))?;
    let mut users = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if users.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&GetGroupMarker {
                        next_user_name: row.user_name_lower,
                    })
                    .await
                    .map_err(
                        |e| internal_failure!(request_id; "Failed to encrypt pagination token for GetGroup: {e}"),
                    )?,
            );
            break;
        }

        let user_arn = Arn::builder()
            .partition(partition.clone())
            .service(SERVICE_KEY_IAM)
            .account_id(&row.user_account_id)
            .resource(user_arn_resource(&row.path, &row.user_name_cased))
            .build()
            .map_err(|e| internal_failure!(request_id; "Failed to construct ARN for group member: {e}"))?;

        let permissions_boundary = if let Some(pb_id) = row.permissions_boundary_managed_policy_id.as_deref() {
            // The FK on permissions_boundary_managed_policy_id guarantees the joined row exists,
            // so a missing pb_account_id/pb_path/pb_name_cased here indicates DB corruption.
            let (pb_account_id, pb_path, pb_name_cased) = match (
                row.pb_account_id.as_deref(),
                row.pb_path.as_deref(),
                row.pb_name_cased.as_deref(),
            ) {
                (Some(pb_account_id), Some(pb_path), Some(pb_name_cased)) => (pb_account_id, pb_path, pb_name_cased),
                _ => {
                    return Err(internal_failure!(request_id; "Group member references missing permissions boundary managed policy ID: {pb_id}").into());
                }
            };

            // The boundary is named by the account owning the policy, not by the account owning
            // the user: an AWS-managed policy serving as a boundary belongs to the AWS account.
            let pb_arn = build_policy_arn(&partition, pb_account_id, pb_path, pb_name_cased, request_id)?;

            Some(
                AttachedPermissionsBoundary::builder()
                    .permissions_boundary_arn(pb_arn.to_string())
                    .permissions_boundary_type(PermissionsBoundaryAttachmentType::Policy)
                    .build()
                    .map_err(|e| {
                        internal_failure!(request_id; "Failed to construct permissions boundary for group member: {e}")
                    })?,
            )
        } else {
            None
        };

        users.push(
            User::builder()
                .arn(user_arn.to_string())
                .create_date(row.created_at)
                .path(row.path)
                .user_id(format!("{}{}", IamResourceType::User.as_str(), row.user_id))
                .user_name(row.user_name_cased)
                .set_permissions_boundary(permissions_boundary)
                .build()
                .map_err(|e| internal_failure!(request_id; "Failed to construct group member object: {e}"))?,
        );
    }

    let mut builder = GetGroupResponse::builder().group(group);
    builder = builder.set_users(users);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(true).marker(next_marker);
    }

    builder.build().map_err(|e| internal_failure!(request_id; "Failed to build GetGroupResponse: {e}").into())
}
