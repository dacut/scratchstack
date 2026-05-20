//! Role database level operations.
use {
    crate::{
        constants::iam::*,
        ops::{
            RequestExecutor,
            iam::{
                build_policy_arn, constrain_max_items, get_current_partition_or_fail, make_paginator, parse_policy_arn,
                validate_account_id, validate_path_prefix, validate_role_name,
            },
        },
    },
    indoc::indoc,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachRolePolicyInternalRequest, DetachRolePolicyInternalRequest, ListAttachedRolePoliciesInternalRequest,
            ListAttachedRolePoliciesResponse,
        },
        types::{
            AttachedPolicy,
            error::{InternalFailure, NoSuchEntityException},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
};

impl RequestExecutor for AttachRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        attach_role_policy(tx, &self.account_id, &self.role_name, &self.policy_arn).await
    }
}

/// Attach a managed policy to a role in the database.
pub async fn attach_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id != account_id && parts.account_id != AWS_ACCOUNT_ID_NUMERIC {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} was not found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // Look up the role_id.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if let Err(e) = query(indoc! {"
            INSERT INTO iam.role_attached_policies(role_id, managed_policy_id)
            VALUES($1, $2)
            ON CONFLICT (role_id, managed_policy_id) DO NOTHING
        "})
    .bind(&role_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        log::error!("Failed to attach policy to role in database: {e}");
        return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
    }

    Ok(())
}

impl RequestExecutor for DetachRolePolicyInternalRequest {
    type Response = ();
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        detach_role_policy(tx, &self.account_id, &self.role_name, &self.policy_arn).await
    }
}

/// Detach a managed policy from a role in the database.
pub async fn detach_role_policy(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    policy_arn: &str,
) -> Result<(), IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;

    let parts = parse_policy_arn(policy_arn)?;
    if parts.account_id != account_id && parts.account_id != AWS_ACCOUNT_ID_NUMERIC {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found."))
            .build()
            .into());
    }

    // Look up the managed_policy_id.
    let managed_policy_id: String = match query(indoc! {"
            SELECT managed_policy_id
            FROM iam.managed_policies
            WHERE account_id = $1 AND path = $2 AND managed_policy_name_lower = $3
        "})
    .bind(&parts.account_id)
    .bind(&parts.policy_path)
    .bind(&parts.policy_name_lower)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("Policy {policy_arn} was not found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up managed policy in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    // Look up the role_id.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let result = match query(indoc! {"
            DELETE FROM iam.role_attached_policies
            WHERE role_id = $1 AND managed_policy_id = $2
        "})
    .bind(&role_id)
    .bind(&managed_policy_id)
    .execute(tx.as_mut())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to detach policy from role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    if result.rows_affected() == 0 {
        return Err(NoSuchEntityException::builder()
            .message(format!("Policy {policy_arn} was not found attached to role {role_name}."))
            .build()
            .into());
    }

    Ok(())
}

impl RequestExecutor for ListAttachedRolePoliciesInternalRequest {
    type Response = ListAttachedRolePoliciesResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_attached_role_policies(
            tx,
            &self.account_id,
            &self.role_name,
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
        )
        .await
    }
}

/// The marker innards for a ListAttachedRolePolicies operation.
#[derive(Deserialize, Serialize)]
struct ListAttachedRolePoliciesMarker {
    next_policy_name_lower: String,
    next_managed_policy_id: String,
}

/// The rows returned by the ListAttachedRolePolicies query.
#[derive(FromRow)]
struct ListAttachedRolePolicyRow {
    managed_policy_id: String,
    account_id: String,
    managed_policy_name_cased: String,
    managed_policy_name_lower: String,
    path: String,
}

/// List managed policies attached to a role in the database.
pub async fn list_attached_role_policies(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_name: &str,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
) -> Result<ListAttachedRolePoliciesResponse, IamError> {
    validate_account_id(account_id)?;
    let account_id = match account_id {
        AWS_ACCOUNT_ID => AWS_ACCOUNT_ID_NUMERIC,
        account_id => account_id,
    };
    validate_role_name(role_name)?;
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;

    // Look up the role_id, returning NoSuchEntity if the role doesn't exist.
    let role_id: String = match query(indoc! {"
            SELECT role_id
            FROM iam.roles
            WHERE account_id = $1 AND role_name_lower = $2
        "})
    .bind(account_id)
    .bind(role_name.to_lowercase())
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(row)) => row.get(0),
        Ok(None) => {
            return Err(NoSuchEntityException::builder()
                .message(format!("The role with name {role_name} cannot be found."))
                .build()
                .into());
        }
        Err(e) => {
            log::error!("Failed to look up role in database: {e}");
            return Err(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build().into());
        }
    };

    let paginator = make_paginator(&partition, OP_LIST_ATTACHED_ROLE_POLICIES)?;

    let mut sql = QueryBuilder::new(
        r#"
        SELECT mp.managed_policy_id, mp.account_id, mp.managed_policy_name_cased,
            mp.managed_policy_name_lower, mp.path
        FROM iam.role_attached_policies rap
        INNER JOIN iam.managed_policies mp ON rap.managed_policy_id = mp.managed_policy_id
        WHERE rap.role_id =
    "#,
    );
    sql.push_bind(&role_id);

    if let Some(path_prefix) = path_prefix {
        sql.push(" AND mp.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(marker) = marker {
        let info: ListAttachedRolePoliciesMarker = paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListAttachedRolePolicies: {e}");
            IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })?;
        sql.push(" AND (mp.managed_policy_name_lower, mp.managed_policy_id) >= (");
        sql.push_bind(info.next_policy_name_lower);
        sql.push(", ");
        sql.push_bind(info.next_managed_policy_id);
        sql.push(")");
    }

    sql.push(" ORDER BY mp.managed_policy_name_lower ASC, mp.managed_policy_id ASC LIMIT ");
    sql.push_bind(max_items as i32 + 1);

    let rows = sql.build_query_as::<ListAttachedRolePolicyRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch attached role policies from database: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })?;

    let mut results: Vec<AttachedPolicy> = Vec::with_capacity(rows.len().min(max_items));
    let mut next_marker = None;

    for row in rows.into_iter() {
        if results.len() == max_items {
            next_marker = Some(
                paginator
                    .encrypt_token(&ListAttachedRolePoliciesMarker {
                        next_policy_name_lower: row.managed_policy_name_lower,
                        next_managed_policy_id: row.managed_policy_id,
                    })
                    .await
                    .map_err(|e| {
                        log::error!("Failed to encrypt pagination token for ListAttachedRolePolicies: {e}");
                        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                    })?,
            );
            break;
        }

        let arn = build_policy_arn(&partition, &row.account_id, &row.path, &row.managed_policy_name_cased)?;
        results.push(
            AttachedPolicy::builder()
                .policy_arn(Some(arn.to_string()))
                .policy_name(Some(row.managed_policy_name_cased))
                .build()
                .map_err(|e| {
                    log::error!("Failed to construct AttachedPolicy: {e}");
                    IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
                })?,
        );
    }

    let mut builder = ListAttachedRolePoliciesResponse::builder();
    builder = builder.attached_policies(results);
    if let Some(next_marker) = next_marker {
        builder = builder.is_truncated(Some(true)).marker(Some(next_marker));
    }

    builder.build().map_err(|e| {
        log::error!("Failed to build ListAttachedRolePoliciesResponse: {e}");
        IamError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
    })
}
