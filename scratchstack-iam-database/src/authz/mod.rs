//! Authorization support: gathering the policies that apply to a principal.
use {
    crate::{
        group::group_arn_resource, internal_failure, partition::get_current_partition_or_fail,
        policy::build_policy_arn, user::user_arn_resource,
    },
    indoc::indoc,
    scratchstack_arn::Arn,
    scratchstack_aspen::{Policy, PolicySet, PolicySource},
    scratchstack_aws_principal::IamResourceType,
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::error_meta::Error as IamError,
    sqlx::{FromRow, postgres::PgTransaction, query_as},
    std::str::FromStr as _,
};

/// A row returned by the policies-for-user gather query. Which columns are populated depends on
/// the `source` discriminator; [row_to_policy_source] enforces the expectations.
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
    .map_err(|e| {
        log::error!("Failed to look up user for authorization: {e}");
        internal_failure(request_id)
    })?;

    let Some(user_row) = user_row else {
        // The user was deleted (or moved accounts) between signature verification and now.
        log::warn!("User id {user_id} not found in account {account_id} while gathering policies");
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
                'user_inline' AS source,
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
                'user_attached',
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
    .map_err(|e| {
        log::error!("Failed to gather policies for user: {e}");
        internal_failure(request_id)
    })?;

    let mut policy_set = PolicySet::new();
    for row in rows.into_iter() {
        // Policy documents were validated when they were stored, so a parse failure here means
        // the stored document is corrupt. Fail closed rather than skip: skipping a document
        // could silently drop an explicit deny.
        let policy = Policy::from_str(&row.policy_document).map_err(|e| {
            log::error!("Failed to parse stored policy document ({}) for user id {user_id}: {e}", row.source);
            internal_failure(request_id)
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
        .map_err(|e| {
            log::error!("Failed to construct IAM ARN: {e}");
            internal_failure(request_id).into()
        })
}

/// Convert a gather-query row into the corresponding [PolicySource]. Missing columns that the
/// row's `source` discriminator requires indicate a database integrity error and produce an
/// internal failure.
fn row_to_policy_source(
    partition: &str,
    user_arn: &Arn,
    prefixed_user_id: &str,
    row: PrincipalPolicyRow,
    request_id: RequestId,
) -> Result<PolicySource, IamError> {
    /// Unwrap a column that the source discriminator requires.
    macro_rules! required {
        ($field:ident) => {
            row.$field.ok_or_else(|| {
                log::error!(concat!("Gather query returned a {} row without ", stringify!($field)), row.source);
                IamError::from(internal_failure(request_id))
            })?
        };
    }

    match row.source.as_str() {
        "user_inline" => {
            Ok(PolicySource::new_entity_inline(user_arn.to_string(), prefixed_user_id, required!(policy_name)))
        }
        source @ ("user_attached" | "group_attached" | "boundary") => {
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
                "user_attached" => {
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
            log::error!("Gather query returned an unknown source discriminator: {source}");
            Err(internal_failure(request_id).into())
        }
    }
}
