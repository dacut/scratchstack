//! Authorization support: gathering the policies that apply to a principal.
use {
    crate::{
        group::group_arn_resource, internal_failure, partition::get_current_partition_or_fail,
        policy::build_policy_arn, role::role_arn_resource, user::user_arn_resource,
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::{Policy, PolicySet, PolicySource},
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::error_meta::Error as IamError,
    sqlx::{FromRow, postgres::PgTransaction, query_as},
    std::{collections::HashMap, str::FromStr as _},
};

/// A row returned by the policy gather queries. Which columns are populated depends on the
/// `source` discriminator; [row_to_policy_source] enforces the expectations.
#[derive(FromRow)]
struct PrincipalPolicyRow {
    source: String,
    policy_name: Option<String>,
    policy_document: String,
    group_account_id: Option<String>,
    group_id: Option<String>,
    group_name: Option<String>,
    group_path: Option<String>,
    managed_policy_account_id: Option<String>,
    managed_policy_id: Option<String>,
    managed_policy_name: Option<String>,
    managed_policy_path: Option<String>,
    managed_policy_version: Option<i64>,
}

/// Fetch the policy documents for the given prefixed ("ANPA…") managed policy ids, resolving
/// each id to its current default version.
///
/// This reconstructs the session-policy gate for temporary credentials: `sts:AssumeRole` records
/// managed session policies by id in the session token, and the documents are resolved when a
/// request is authorized rather than when the session is created.
///
/// Returns `Ok(None)` if any id does not carry the managed-policy prefix or no longer resolves
/// (e.g. the policy was deleted after the session was created). The session gate cannot be
/// reconstructed in that case, so callers must fail closed and deny the request.
pub async fn get_policies_by_ids(
    tx: &mut PgTransaction<'_>,
    prefixed_policy_ids: &[String],
    request_id: RequestId,
) -> Result<Option<Vec<Policy>>, IamError> {
    let mut policy_ids = Vec::with_capacity(prefixed_policy_ids.len());
    for prefixed_policy_id in prefixed_policy_ids {
        let Some(policy_id) = prefixed_policy_id.strip_prefix(IamResourceType::ManagedPolicy.as_str()) else {
            log::warn!("Policy id {prefixed_policy_id} is not a prefixed managed policy id");
            return Ok(None);
        };
        policy_ids.push(policy_id.to_string());
    }

    #[derive(FromRow)]
    struct PolicyDocumentRow {
        managed_policy_id: String,
        policy_document: String,
    }

    let rows: Vec<PolicyDocumentRow> = query_as(indoc! {"
            SELECT mp.managed_policy_id, mpv.policy_document
            FROM iam.managed_policies mp
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE mp.managed_policy_id = ANY($1)
        "})
    .bind(&policy_ids)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to fetch policy documents by id: {e}"))?;

    let documents: HashMap<String, String> =
        rows.into_iter().map(|row| (row.managed_policy_id, row.policy_document)).collect();

    let mut policies = Vec::with_capacity(policy_ids.len());
    for policy_id in &policy_ids {
        let Some(document) = documents.get(policy_id) else {
            // The policy was deleted (or lost its default version) after the id was recorded.
            log::warn!("Managed policy id {policy_id} not found while fetching policy documents");
            return Ok(None);
        };

        // Policy documents were validated when they were stored, so a parse failure here means
        // the stored document is corrupt. Fail closed rather than skip: skipping a document
        // could silently drop an explicit deny.
        let policy = Policy::from_str(document).map_err(|e| {
            internal_failure!(request_id; "Failed to parse stored policy document for managed policy id {policy_id}: {e}")
        })?;
        policies.push(policy);
    }

    Ok(Some(policies))
}

/// Gather the identity-based policies that govern an IAM role: the role's inline policies, the
/// default versions of managed policies attached to the role, and the role's permissions
/// boundary (if any). Roles cannot belong to groups, so no group policies apply. Session
/// policies supplied to `sts:AssumeRole` travel in the session token rather than the database
/// and are not gathered here.
///
/// `role_id` is the internal, unprefixed role id (i.e. the `aws:userid` session value minus its
/// leading `AROA` prefix and trailing `:role-session-name`). If the role row does not exist in
/// `account_id`, an empty [PolicySet] is returned; evaluating it will produce a default deny.
pub async fn get_policies_for_role(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    role_id: &str,
    request_id: RequestId,
) -> Result<PolicySet, IamError> {
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    // Fetch the caller's role row; this also supplies the components of the role's ARN.
    #[derive(FromRow)]
    struct RoleRow {
        role_name_cased: String,
        path: String,
    }

    let role_row: Option<RoleRow> = query_as(indoc! {"
            SELECT role_name_cased, path
            FROM iam.roles
            WHERE role_id = $1 AND account_id = $2
        "})
    .bind(role_id)
    .bind(account_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to look up role for authorization: {e}"))?;

    let Some(role_row) = role_row else {
        // The role was deleted (or moved accounts) between the session's creation and now.
        log::warn!("{request_id}: Role id {role_id} not found in account {account_id} while gathering policies");
        return Ok(PolicySet::new());
    };

    let role_arn = build_iam_arn(
        &partition,
        account_id,
        role_arn_resource(&role_row.path, &role_row.role_name_cased),
        request_id,
    )?;
    let prefixed_role_id = format!("{}{role_id}", IamResourceType::Role.as_str());

    // Gather every policy document that applies to the role in a single round trip. Managed
    // policies resolve to their default version; a managed policy with no default version (which
    // cannot happen for an attachable policy) drops out of the inner join.
    let rows: Vec<PrincipalPolicyRow> = query_as(indoc! {"
            SELECT
                'entity_inline' AS source,
                rip.policy_name_cased AS policy_name,
                rip.policy_document AS policy_document,
                NULL::VARCHAR AS group_account_id,
                NULL::VARCHAR AS group_id,
                NULL::VARCHAR AS group_name,
                NULL::VARCHAR AS group_path,
                NULL::VARCHAR AS managed_policy_account_id,
                NULL::VARCHAR AS managed_policy_id,
                NULL::VARCHAR AS managed_policy_name,
                NULL::VARCHAR AS managed_policy_path,
                NULL::BIGINT AS managed_policy_version
            FROM iam.role_inline_policies rip
            WHERE rip.role_id = $1

            UNION ALL

            SELECT
                'entity_attached',
                NULL::VARCHAR,
                mpv.policy_document,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                mp.account_id,
                mp.managed_policy_id,
                mp.managed_policy_name_cased,
                mp.path,
                mp.default_version
            FROM iam.role_attached_policies rap
            INNER JOIN iam.managed_policies mp ON mp.managed_policy_id = rap.managed_policy_id
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE rap.role_id = $1

            UNION ALL

            SELECT
                'boundary',
                NULL::VARCHAR,
                mpv.policy_document,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                mp.account_id,
                mp.managed_policy_id,
                mp.managed_policy_name_cased,
                mp.path,
                mp.default_version
            FROM iam.roles r
            INNER JOIN iam.managed_policies mp
                ON mp.managed_policy_id = r.permissions_boundary_managed_policy_id
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE r.role_id = $1 AND r.account_id = $2
        "})
    .bind(role_id)
    .bind(account_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to gather policies for role: {e}"))?;

    let mut policy_set = PolicySet::new();
    for row in rows.into_iter() {
        // Policy documents were validated when they were stored, so a parse failure here means
        // the stored document is corrupt. Fail closed rather than skip: skipping a document
        // could silently drop an explicit deny.
        let policy = Policy::from_str(&row.policy_document).map_err(|e| {
            internal_failure!(request_id; "Failed to parse stored policy document ({}) for role id {role_id}: {e}", row.source)
        })?;

        let source = row_to_policy_source(&partition, &role_arn, &prefixed_role_id, row, request_id)?;
        policy_set.add_policy(source, policy);
    }

    Ok(policy_set)
}

/// Gather the identity-based policies that govern an IAM user: the user's inline policies, the
/// default versions of managed policies attached to the user, inline and attached policies of
/// every group the user belongs to, and the user's permissions boundary (if any).
///
/// `user_id` is the internal, unprefixed user id (i.e. the `aws:userid` session value minus its
/// leading `AIDA` prefix). If the user row does not exist in `account_id`, an empty [PolicySet]
/// is returned; evaluating it will produce a default deny.
pub async fn get_policies_for_user(
    tx: &mut PgTransaction<'_>,
    account_id: &str,
    user_id: &str,
    request_id: RequestId,
) -> Result<PolicySet, IamError> {
    let partition = get_current_partition_or_fail(tx, request_id).await?;

    // Fetch the caller's user row; this also supplies the components of the user's ARN.
    #[derive(FromRow)]
    struct UserRow {
        user_name_cased: String,
        path: String,
    }

    let user_row: Option<UserRow> = query_as(indoc! {"
            SELECT user_name_cased, path
            FROM iam.users
            WHERE user_id = $1 AND account_id = $2
        "})
    .bind(user_id)
    .bind(account_id)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to look up user for authorization: {e}"))?;

    let Some(user_row) = user_row else {
        // The user was deleted (or moved accounts) between signature verification and now.
        log::warn!("{request_id}: User id {user_id} not found in account {account_id} while gathering policies");
        return Ok(PolicySet::new());
    };

    let user_arn = build_iam_arn(
        &partition,
        account_id,
        user_arn_resource(&user_row.path, &user_row.user_name_cased),
        request_id,
    )?;
    let prefixed_user_id = format!("{}{user_id}", IamResourceType::User.as_str());

    // Gather every policy document that applies to the user in a single round trip. Managed
    // policies resolve to their default version; a managed policy with no default version (which
    // cannot happen for an attachable policy) drops out of the inner join.
    let rows: Vec<PrincipalPolicyRow> = query_as(indoc! {"
            SELECT
                'entity_inline' AS source,
                uip.policy_name_cased AS policy_name,
                uip.policy_document AS policy_document,
                NULL::VARCHAR AS group_account_id,
                NULL::VARCHAR AS group_id,
                NULL::VARCHAR AS group_name,
                NULL::VARCHAR AS group_path,
                NULL::VARCHAR AS managed_policy_account_id,
                NULL::VARCHAR AS managed_policy_id,
                NULL::VARCHAR AS managed_policy_name,
                NULL::VARCHAR AS managed_policy_path,
                NULL::BIGINT AS managed_policy_version
            FROM iam.user_inline_policies uip
            WHERE uip.user_id = $1

            UNION ALL

            SELECT
                'entity_attached',
                NULL::VARCHAR,
                mpv.policy_document,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                mp.account_id,
                mp.managed_policy_id,
                mp.managed_policy_name_cased,
                mp.path,
                mp.default_version
            FROM iam.user_attached_policies uap
            INNER JOIN iam.managed_policies mp ON mp.managed_policy_id = uap.managed_policy_id
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE uap.user_id = $1

            UNION ALL

            SELECT
                'group_inline',
                gip.policy_name_cased,
                gip.policy_document,
                g.account_id,
                g.group_id,
                g.group_name_cased,
                g.path,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::BIGINT
            FROM iam.group_memberships gm
            INNER JOIN iam.groups g ON g.group_id = gm.group_id
            INNER JOIN iam.group_inline_policies gip ON gip.group_id = gm.group_id
            WHERE gm.user_id = $1

            UNION ALL

            SELECT
                'group_attached',
                NULL::VARCHAR,
                mpv.policy_document,
                g.account_id,
                g.group_id,
                g.group_name_cased,
                g.path,
                mp.account_id,
                mp.managed_policy_id,
                mp.managed_policy_name_cased,
                mp.path,
                mp.default_version
            FROM iam.group_memberships gm
            INNER JOIN iam.groups g ON g.group_id = gm.group_id
            INNER JOIN iam.group_attached_policies gap ON gap.group_id = gm.group_id
            INNER JOIN iam.managed_policies mp ON mp.managed_policy_id = gap.managed_policy_id
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE gm.user_id = $1

            UNION ALL

            SELECT
                'boundary',
                NULL::VARCHAR,
                mpv.policy_document,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                mp.account_id,
                mp.managed_policy_id,
                mp.managed_policy_name_cased,
                mp.path,
                mp.default_version
            FROM iam.users u
            INNER JOIN iam.managed_policies mp
                ON mp.managed_policy_id = u.permissions_boundary_managed_policy_id
            INNER JOIN iam.managed_policy_versions mpv
                ON mpv.managed_policy_id = mp.managed_policy_id
                AND mpv.managed_policy_version = mp.default_version
            WHERE u.user_id = $1 AND u.account_id = $2
        "})
    .bind(user_id)
    .bind(account_id)
    .fetch_all(tx.as_mut())
    .await
    .map_err(|e| internal_failure!(request_id; "Failed to gather policies for user: {e}"))?;

    let mut policy_set = PolicySet::new();
    for row in rows.into_iter() {
        // Policy documents were validated when they were stored, so a parse failure here means
        // the stored document is corrupt. Fail closed rather than skip: skipping a document
        // could silently drop an explicit deny.
        let policy = Policy::from_str(&row.policy_document).map_err(|e| {
            internal_failure!(request_id; "Failed to parse stored policy document ({}) for user id {user_id}: {e}", row.source)
        })?;

        let source = row_to_policy_source(&partition, &user_arn, &prefixed_user_id, row, request_id)?;
        policy_set.add_policy(source, policy);
    }

    Ok(policy_set)
}

/// Construct an IAM ARN (no region) from its components.
fn build_iam_arn(partition: &str, account_id: &str, resource: String, request_id: RequestId) -> Result<Arn, IamError> {
    Arn::builder()
        .partition(partition)
        .service(crate::constants::SERVICE_KEY_IAM)
        .account_id(account_id)
        .resource(resource)
        .build()
        .map_err(|e| internal_failure!(request_id; "Failed to construct IAM ARN: {e}").into())
}

/// Convert a gather-query row into the corresponding [PolicySource]. Missing columns that the
/// row's `source` discriminator requires indicate a database integrity error and produce an
/// internal failure.
fn row_to_policy_source(
    partition: &str,
    entity_arn: &Arn,
    prefixed_entity_id: &str,
    row: PrincipalPolicyRow,
    request_id: RequestId,
) -> Result<PolicySource, IamError> {
    /// Unwrap a column that the source discriminator requires.
    macro_rules! required {
        ($field:ident) => {
            row.$field.ok_or_else(|| {
                IamError::from(internal_failure!(request_id; concat!("Gather query returned a {} row without ", stringify!($field)), row.source))
            })?
        };
    }

    match row.source.as_str() {
        "entity_inline" => {
            Ok(PolicySource::new_entity_inline(entity_arn.to_string(), prefixed_entity_id, required!(policy_name)))
        }
        source @ ("entity_attached" | "group_attached" | "boundary") => {
            let policy_arn = build_policy_arn(
                partition,
                &required!(managed_policy_account_id),
                &required!(managed_policy_path),
                &required!(managed_policy_name),
                request_id,
            )?;
            let policy_id = format!("{}{}", IamResourceType::ManagedPolicy.as_str(), required!(managed_policy_id));
            let version = format!("v{}", required!(managed_policy_version));

            match source {
                "entity_attached" => {
                    Ok(PolicySource::new_entity_attached_policy(policy_arn.to_string(), policy_id, version))
                }
                "group_attached" => {
                    let group_arn = build_iam_arn(
                        partition,
                        &required!(group_account_id),
                        group_arn_resource(&required!(group_path), &required!(group_name)),
                        request_id,
                    )?;
                    let group_id = format!("{}{}", IamResourceType::Group.as_str(), required!(group_id));
                    Ok(PolicySource::new_group_attached_policy(
                        group_arn.to_string(),
                        group_id,
                        policy_arn.to_string(),
                        policy_id,
                        version,
                    ))
                }
                _ => Ok(PolicySource::new_permission_boundary(policy_arn.to_string(), policy_id, version)),
            }
        }
        "group_inline" => {
            let group_arn = build_iam_arn(
                partition,
                &required!(group_account_id),
                group_arn_resource(&required!(group_path), &required!(group_name)),
                request_id,
            )?;
            let group_id = format!("{}{}", IamResourceType::Group.as_str(), required!(group_id));
            Ok(PolicySource::new_group_inline(group_arn.to_string(), group_id, required!(policy_name)))
        }
        source => {
            Err(internal_failure!(request_id; "Gather query returned an unknown source discriminator: {source}").into())
        }
    }
}
