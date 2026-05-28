//! ListEntitiesForPolicy database operation
use {
    crate::{
        RequestExecutor,
        constants::iam::*,
        iam::{
            constrain_max_items, get_current_partition_or_fail, internal_failure, make_paginator, parse_policy_arn,
            validate_path_prefix,
        },
    },
    indoc::{formatdoc, indoc},
    scratchstack_aws_principal::IamResourceType,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{ListEntitiesForPolicyRequest, ListEntitiesForPolicyResponse},
        types::{
            EntityType, PolicyGroup, PolicyRole, PolicyUsageType, PolicyUser,
            error::{NoSuchEntityException, ValidationError},
        },
    },
    serde::{Deserialize, Serialize},
    sqlx::{FromRow, QueryBuilder, Row as _, postgres::PgTransaction, query},
    std::fmt::{Display, Formatter, Result as FmtResult},
};

impl RequestExecutor for ListEntitiesForPolicyRequest {
    type Response = ListEntitiesForPolicyResponse;
    type Error = IamError;

    async fn execute(&self, tx: &mut PgTransaction<'_>) -> Result<Self::Response, Self::Error> {
        list_entities_for_policy(
            tx,
            &self.policy_arn,
            self.entity_filter.as_ref(),
            self.marker.as_deref(),
            self.max_items,
            self.path_prefix.as_deref(),
            self.policy_usage_filter.as_ref(),
        )
        .await
    }
}

/// The marker innards for a ListEntitiesForPolicy operation.
#[derive(Deserialize, Serialize)]
struct ListEntitiesForPolicyMarker {
    /// Which section to resume in.
    section: EntitySection,

    /// The next entity id to resume after within the section.
    next_entity_id: String,
}

/// A single attached-entity row, used uniformly across the group/role/user sections.
#[derive(FromRow)]
struct EntityRow {
    entity_id: String,
    entity_name_cased: String,
}

/// Which section we're in for ListEntitiesForPolicyMarker
#[derive(Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum EntitySection {
    #[default]
    Group,
    Role,
    User,
}

impl Display for EntitySection {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            EntitySection::Group => f.write_str("Group"),
            EntitySection::Role => f.write_str("Role"),
            EntitySection::User => f.write_str("User"),
        }
    }
}

/// List the IAM entities (users, groups, roles) that a managed policy is attached to (or, when
/// `policy_usage_filter == PermissionsBoundary`, that use the policy as a permissions boundary).
#[allow(clippy::too_many_arguments)]
pub async fn list_entities_for_policy(
    tx: &mut PgTransaction<'_>,
    policy_arn: &str,
    entity_filter: Option<&EntityType>,
    marker: Option<&str>,
    max_items: Option<i32>,
    path_prefix: Option<&str>,
    policy_usage_filter: Option<&PolicyUsageType>,
) -> Result<ListEntitiesForPolicyResponse, IamError> {
    if let Some(path_prefix) = path_prefix {
        validate_path_prefix(path_prefix)?;
    }
    let max_items = constrain_max_items(max_items)?;
    let partition = get_current_partition_or_fail(tx).await?;
    let parts = parse_policy_arn(policy_arn)?;

    // Which entity sections to scan, in display order.
    let sections_to_query: &[EntitySection] = match entity_filter {
        None => &[EntitySection::Group, EntitySection::Role, EntitySection::User],
        Some(EntityType::Group) => &[EntitySection::Group],
        Some(EntityType::Role) => &[EntitySection::Role],
        Some(EntityType::User) => &[EntitySection::User],
        Some(other) => {
            return Err(ValidationError::builder()
                .message(format!("Unsupported EntityFilter value for ListEntitiesForPolicy: {other}"))
                .build()
                .into());
        }
    };

    // PermissionsPolicy (default) lists attachments; PermissionsBoundary lists permissions-boundary
    // usages (users/roles only — groups can't have a permissions boundary).
    let is_pb_filter = match policy_usage_filter {
        None | Some(PolicyUsageType::PermissionsPolicy) => false,
        Some(PolicyUsageType::PermissionsBoundary) => true,
        Some(other) => {
            return Err(ValidationError::builder()
                .message(format!("Unsupported PolicyUsageFilter value: {other}"))
                .build()
                .into());
        }
    };

    let paginator = make_paginator(&partition, OP_LIST_ENTITIES_FOR_POLICY)?;

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
            return Err(internal_failure().into());
        }
    };

    let resume: Option<ListEntitiesForPolicyMarker> = if let Some(marker) = marker {
        Some(paginator.decrypt_token(marker).await.map_err(|e| {
            log::error!("Failed to decrypt pagination token for ListEntitiesForPolicy: {e}");
            internal_failure()
        })?)
    } else {
        None
    };
    let resume_section = resume.as_ref().map(|r| r.section).unwrap_or_default();

    let mut groups: Vec<PolicyGroup> = Vec::new();
    let mut roles: Vec<PolicyRole> = Vec::new();
    let mut users: Vec<PolicyUser> = Vec::new();
    let mut next_marker: Option<String> = None;

    for &section in sections_to_query {
        if next_marker.is_some() {
            break;
        }

        // Skip sections that come before the marker's section.
        if section < resume_section {
            continue;
        }

        // Groups don't have a permissions boundary, so always empty under that filter.
        if is_pb_filter && section == EntitySection::Group {
            continue;
        }

        // If this is the section we're resuming from, set the resuming entity id; otherwise, start
        // from the beginning of the section.
        let resume_entity_id = if resume_section == section
            && let Some(r) = resume.as_ref()
        {
            Some(r.next_entity_id.as_str())
        } else {
            None
        };

        let already_collected = groups.len() + roles.len() + users.len();
        // Request one more than we need so we can detect overflow → marker.
        let limit = (max_items - already_collected) as i32 + 1;

        let rows =
            fetch_section_rows(tx, section, &managed_policy_id, is_pb_filter, path_prefix, resume_entity_id, limit)
                .await?;

        for row in rows {
            let collected = groups.len() + roles.len() + users.len();
            if collected == max_items {
                next_marker = Some(
                    paginator
                        .encrypt_token(&ListEntitiesForPolicyMarker {
                            section,
                            next_entity_id: row.entity_id,
                        })
                        .await
                        .map_err(|e| {
                            log::error!("Failed to encrypt pagination token for ListEntitiesForPolicy: {e}");
                            internal_failure()
                        })?,
                );
                break;
            }
            match section {
                EntitySection::Group => groups.push(
                    PolicyGroup::builder()
                        .group_id(Some(format!("{}{}", IamResourceType::Group.as_str(), row.entity_id)))
                        .group_name(Some(row.entity_name_cased))
                        .build()
                        .map_err(|e| {
                            log::error!("Failed to construct PolicyGroup: {e}");
                            internal_failure()
                        })?,
                ),
                EntitySection::Role => roles.push(
                    PolicyRole::builder()
                        .role_id(Some(format!("{}{}", IamResourceType::Role.as_str(), row.entity_id)))
                        .role_name(Some(row.entity_name_cased))
                        .build()
                        .map_err(|e| {
                            log::error!("Failed to construct PolicyRole: {e}");
                            internal_failure()
                        })?,
                ),
                EntitySection::User => users.push(
                    PolicyUser::builder()
                        .user_id(Some(format!("{}{}", IamResourceType::User.as_str(), row.entity_id)))
                        .user_name(Some(row.entity_name_cased))
                        .build()
                        .map_err(|e| {
                            log::error!("Failed to construct PolicyUser: {e}");
                            internal_failure()
                        })?,
                ),
            }
        }
    }

    Ok(ListEntitiesForPolicyResponse {
        policy_groups: groups,
        policy_roles: roles,
        policy_users: users,
        is_truncated: Some(next_marker.is_some()),
        marker: next_marker,
    })
}

/// Fetch rows from the requested section (groups/roles/users) attached to or boundaried by a
/// managed policy. The rows are returned in `entity_id` order.
#[allow(clippy::too_many_arguments)]
async fn fetch_section_rows(
    tx: &mut PgTransaction<'_>,
    section: EntitySection,
    managed_policy_id: &str,
    is_pb_filter: bool,
    path_prefix: Option<&str>,
    resume_entity_id: Option<&str>,
    limit: i32,
) -> Result<Vec<EntityRow>, IamError> {
    let mut sql = QueryBuilder::new("");

    let entity_type_name = match section {
        EntitySection::Group => "group",
        EntitySection::Role => "role",
        EntitySection::User => "user",
    };

    if is_pb_filter {
        sql.push(formatdoc! {"
            SELECT
                e.{entity_type_name}_id AS entity_id,
                e.{entity_type_name}_name_lower AS entity_name_lower,
                e.{entity_type_name}_name_cased AS entity_name_cased
            FROM iam.{entity_type_name}s e
            WHERE e.permissions_boundary_managed_policy_id = 
        "});
        sql.push_bind(managed_policy_id);
    } else {
        sql.push(formatdoc! {"
            SELECT
                e.{entity_type_name}_id AS entity_id,
                e.{entity_type_name}_name_lower AS entity_name_lower,
                e.{entity_type_name}_name_cased AS entity_name_cased
            FROM iam.{entity_type_name}s e
            INNER JOIN iam.{entity_type_name}_attached_policies ep
            ON ep.{entity_type_name}_id = e.{entity_type_name}_id
            WHERE ep.managed_policy_id = 
        "});
        sql.push_bind(managed_policy_id);
    }

    if let Some(path_prefix) = path_prefix {
        sql.push("\nAND e.path LIKE ");
        sql.push_bind(format!("{}%", path_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    }

    if let Some(resume_entity_id) = resume_entity_id {
        sql.push(format!("\nAND e.{entity_type_name}_id >= "));
        sql.push_bind(resume_entity_id);
    }

    sql.push(format!("\nORDER BY e.{entity_type_name}_id ASC LIMIT "));
    sql.push_bind(limit);

    sql.build_query_as::<EntityRow>().fetch_all(tx.as_mut()).await.map_err(|e| {
        log::error!("Failed to fetch attached entities for ListEntitiesForPolicy ({section}): {e}");
        internal_failure().into()
    })
}
