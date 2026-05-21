//! Role test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateRoleInternalRequest, DeleteRoleInternalRequest, DeleteRolePermissionsBoundaryInternalRequest,
            GetRoleInternalRequest, ListRoleTagsInternalRequest, ListRolesInternalRequest, TagRoleInternalRequest,
            UntagRoleInternalRequest, UpdateRoleDescriptionInternalRequest, UpdateRoleInternalRequest,
        },
        types::{PermissionsBoundaryAttachmentType, Tag},
    },
};

/// Simple trust policy that allows Lambda to assume the role.
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Create a role with only the required fields — all other fields take defaults.
pub async fn test_create_role_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create role");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "LambdaExecutor");
    assert_eq!(role.path, "/");
    assert!(role.role_id.starts_with("AROA"), "Role ID must start with AROA prefix");
    assert!(role.arn.ends_with(":role/LambdaExecutor"), "ARN must end with :role/LambdaExecutor, got {}", role.arn);
    assert!(role.permissions_boundary.is_none());
    assert!(role.tags.is_empty());
    assert_eq!(role.assume_role_policy_document.as_deref(), Some(TRUST_POLICY));
    assert!(role.description.is_none());
    assert!(role.max_session_duration.is_none());
}

/// Create a role at a non-default path.
pub async fn test_create_role_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("DeployRole".to_string())
        .path(Some("/service-roles/".to_string()))
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create role with path");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "DeployRole");
    assert_eq!(role.path, "/service-roles/");
    assert!(
        role.arn.ends_with(":role/service-roles/DeployRole"),
        "ARN must end with :role/service-roles/DeployRole, got {}",
        role.arn
    );
}

/// Create a role with a description and max session duration.
pub async fn test_create_role_with_description_and_duration(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("LongSessionRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .description(Some("Role for long-running batch jobs.".to_string()))
        .max_session_duration(Some(14400))
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create role with description and duration");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "LongSessionRole");
    assert_eq!(role.description.as_deref(), Some("Role for long-running batch jobs."));
    assert_eq!(role.max_session_duration, Some(14400));
}

/// Create a role with tags attached.
pub async fn test_create_role_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("TaggedRole".to_string())
        .account_id("210987654321".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build Environment tag"),
            Tag::builder()
                .key("Team".to_string())
                .value("Platform".to_string())
                .build()
                .expect("Failed to build Team tag"),
        ])
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create role with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "TaggedRole");
    assert_eq!(role.tags.len(), 2);
    assert_eq!(role.tags[0].key, "Environment");
    assert_eq!(role.tags[0].value, "Production");
    assert_eq!(role.tags[1].key, "Team");
    assert_eq!(role.tags[1].value, "Platform");
}

/// Create a role with an existing managed policy as the permissions boundary.
///
/// Rolled back rather than committed because downstream `policy_query` tests assert that no role
/// uses `Example-Managed-Policy-1` as a permissions boundary; we still get to verify the response.
pub async fn test_create_role_with_permissions_boundary(pool: &sqlx::PgPool) {
    // The test data has "Example-Managed-Policy-1" in account 123456789012 at path "/".
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("BoundedRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1".to_string()))
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create role with permissions boundary");
    tx.rollback().await.expect("Failed to rollback transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "BoundedRole");
    let pb = role.permissions_boundary.expect("Role should have a permissions boundary");
    let pb_arn = pb.permissions_boundary_arn.expect("Permissions boundary should include an ARN");
    assert_eq!(pb_arn, "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1");
}

/// Attempting to create a role whose (lowercased) name already exists in the account must fail.
pub async fn test_create_role_duplicate_name(pool: &sqlx::PgPool) {
    // "LambdaExecutor" was committed by test_create_role_simple; re-inserting it must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate role name must fail");
}

/// Building a request with an invalid role name must fail before touching the database.
pub fn test_create_role_invalid_name() {
    // Spaces and `!` are not in the allowed character set.
    let result = CreateRoleInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Building a request with a max_session_duration outside the allowed range must fail.
pub fn test_create_role_invalid_max_session_duration() {
    // 60 seconds is well below the 3600 minimum.
    let result = CreateRoleInternalRequest::builder()
        .role_name("ShortSessionRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .max_session_duration(Some(60))
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration below 3600 must fail");

    // 100000 seconds is well above the 43200 maximum.
    let result = CreateRoleInternalRequest::builder()
        .role_name("VeryLongSessionRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .max_session_duration(Some(100000))
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration above 43200 must fail");
}

/// Creating a role in an account that does not exist must fail with a FK violation.
pub async fn test_create_role_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateRoleInternalRequest::builder()
        .role_name("OrphanRole".to_string())
        .account_id("999999999999".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a role in a nonexistent account must fail");
}

/// Specifying a permissions boundary that references a policy that does not exist must fail.
pub async fn test_create_role_nonexistent_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateRoleInternalRequest::builder()
        .role_name("MissingBoundaryRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/NonExistentPolicy".to_string()))
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a role with a nonexistent permissions boundary must fail");
}

/// Delete a role that has no attached or inline policies — success path.
pub async fn test_delete_role_simple(pool: &sqlx::PgPool) {
    // Create a fresh role so this test is self-contained.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeRole");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeRole");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same role must fail with NoSuchEntity.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting DeleteMeRole must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Verify that DeleteRole cascades to role_tags so a tagged role can be deleted cleanly once its
/// attachments and inline policies are removed.
pub async fn test_delete_role_cascades_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeTaggedRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Dev".to_string())
                .build()
                .expect("Failed to build Environment tag"),
        ])
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeTaggedRole");
    tx.commit().await.expect("Failed to commit transaction");

    // Capture the raw role_id (without AROA prefix) so we can confirm cascade on role_tags.
    let role_id: String =
        sqlx::query_scalar("SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2")
            .bind("123456789012")
            .bind("deletemetaggedrole")
            .fetch_one(pool)
            .await
            .expect("Failed to fetch role_id");

    let pre_tags: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam.role_tags WHERE role_id = $1")
        .bind(&role_id)
        .fetch_one(pool)
        .await
        .expect("Failed to count role tags before delete");
    assert_eq!(pre_tags, 1, "Expected exactly one tag before delete");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeTaggedRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeTaggedRole");
    tx.commit().await.expect("Failed to commit transaction");

    let post_tags: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam.role_tags WHERE role_id = $1")
        .bind(&role_id)
        .fetch_one(pool)
        .await
        .expect("Failed to count role tags after delete");
    assert_eq!(post_tags, 0, "role_tags rows must cascade-delete with the role");
}

/// A role with an attached managed policy (and nothing else) must not be deletable. Build a fresh
/// role and attach an existing seeded managed policy directly via SQL so the only blocking
/// condition is the attachment.
pub async fn test_delete_role_attached_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeAttachedRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeAttachedRole");
    let role_id: String =
        sqlx::query_scalar("SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeattachedrole")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeAttachedRole role_id");
    // AAAABBBBCCCCDDDD is the seeded Example-Managed-Policy-1.
    sqlx::query("INSERT INTO iam.role_attached_policies(role_id, managed_policy_id) VALUES ($1, $2)")
        .bind(&role_id)
        .bind("AAAABBBBCCCCDDDD")
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach Example-Managed-Policy-1 to DeleteMeAttachedRole");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeAttachedRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a role with an attached managed policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: detach the policy, confirm DeleteRole now succeeds. This also exercises the
    // success path with cascaded role_attached_policies removal being unnecessary (we already
    // cleared the row).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.role_attached_policies WHERE role_id = $1")
        .bind(&role_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to detach managed policy");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeAttachedRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeAttachedRole after detaching policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A role with inline policies must not be deletable. Build a fresh role and write an inline
/// policy directly via SQL so this test does not depend on the seed role's mixed state.
pub async fn test_delete_role_inline_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeInlineRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeInlineRole");
    let role_id: String =
        sqlx::query_scalar("SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeinlinerole")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeInlineRole role_id");
    sqlx::query(
        "INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES ($1, $2, $3, $4)",
    )
    .bind(&role_id)
    .bind("inline-blocker")
    .bind("inline-blocker")
    .bind(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#)
    .execute(tx.as_mut())
    .await
    .expect("Failed to insert inline policy for DeleteMeInlineRole");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeInlineRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a role with an inline policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: remove the inline policy and confirm DeleteRole then succeeds.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.role_inline_policies WHERE role_id = $1")
        .bind(&role_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to remove inline policy");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeInlineRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeInlineRole after removing inline policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting a role that does not exist must fail with NoSuchEntity.
pub async fn test_delete_role_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("NoSuchDeleteRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a request with an invalid role name must fail before touching the database.
pub fn test_delete_role_invalid_name() {
    let result = DeleteRoleInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a delete request with an invalid role name must fail");
}

/// Clear a permissions boundary that is set on a role. The role exists and has a PB; afterwards
/// the column must be NULL.
pub async fn test_delete_role_permissions_boundary_simple(pool: &sqlx::PgPool) {
    // Set up: create a role with no PB, then attach a PB directly via SQL (the create_role API
    // verifies the PB exists by name, but we just need any seeded managed_policy_id here).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMePbRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMePbRole");
    let role_id: String =
        sqlx::query_scalar("SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2")
            .bind("123456789012")
            .bind("deletemepbrole")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMePbRole role_id");
    let managed_policy_id: String = sqlx::query_scalar(
        "SELECT managed_policy_id FROM iam.managed_policies WHERE account_id = $1 AND managed_policy_name_lower = $2",
    )
    .bind("123456789012")
    .bind("example-managed-policy-1")
    .fetch_one(tx.as_mut())
    .await
    .expect("Failed to fetch Example-Managed-Policy-1 managed_policy_id");
    sqlx::query("UPDATE iam.roles SET permissions_boundary_managed_policy_id = $1 WHERE role_id = $2")
        .bind(managed_policy_id)
        .bind(&role_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to set DeleteMePbRole permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("DeleteMePbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMePbRole permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let pb: Option<String> =
        sqlx::query_scalar("SELECT permissions_boundary_managed_policy_id FROM iam.roles WHERE role_id = $1")
            .bind(&role_id)
            .fetch_one(pool)
            .await
            .expect("Failed to fetch DeleteMePbRole permissions boundary after delete");
    assert!(pb.is_none(), "permissions_boundary_managed_policy_id must be NULL after delete");

    // Clean up.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMePbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMePbRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteRolePermissionsBoundary on a role that has no PB must succeed (idempotent).
pub async fn test_delete_role_permissions_boundary_no_boundary(pool: &sqlx::PgPool) {
    // LambdaExecutor was committed earlier in test_create_role_simple with no PB.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("DeleteRolePermissionsBoundary on a role with no PB must succeed");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteRolePermissionsBoundary on a nonexistent role must fail with NoSuchEntity.
pub async fn test_delete_role_permissions_boundary_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("NoSuchPbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Clearing PB on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteRolePermissionsBoundary request with an invalid role name must fail before
/// touching the database.
pub fn test_delete_role_permissions_boundary_invalid_name() {
    let result = DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Get a role created earlier in the suite with no PB, tags, or extras. Validates the basic
/// projection (ARN, role_id prefix, path, trust policy).
pub async fn test_get_role_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor");
    tx.rollback().await.expect("Failed to rollback transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "LambdaExecutor");
    assert_eq!(role.path, "/");
    assert!(role.arn.ends_with(":role/LambdaExecutor"), "Unexpected ARN: {}", role.arn);
    assert!(role.role_id.starts_with("AROA"), "RoleId must start with AROA, got {}", role.role_id);
    assert_eq!(role.assume_role_policy_document.as_deref(), Some(TRUST_POLICY));
    assert!(role.permissions_boundary.is_none());
    assert!(role.tags.is_empty());
    assert!(role.description.is_none());
    assert!(role.max_session_duration.is_none());
}

/// Get a role created with a non-default path; the projected ARN must include the path.
pub async fn test_get_role_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("DeployRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get DeployRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "DeployRole");
    assert_eq!(role.path, "/service-roles/");
    assert!(role.arn.ends_with(":role/service-roles/DeployRole"), "Unexpected ARN: {}", role.arn);
}

/// Get a role committed earlier with tags. Tags must come back ordered by lowercased key.
pub async fn test_get_role_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("TaggedRole".to_string())
        .account_id("210987654321".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TaggedRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "TaggedRole");
    assert_eq!(role.tags.len(), 2);
    assert_eq!(role.tags[0].key, "Environment");
    assert_eq!(role.tags[0].value, "Production");
    assert_eq!(role.tags[1].key, "Team");
    assert_eq!(role.tags[1].value, "Platform");
}

/// Get a role that has a permissions boundary set. Builds the role through the normal API path
/// (CreateRoleInternalRequest with the PB ARN), then asserts the get_role response surfaces the
/// PB with the policy's true ARN (name+path resolved from the managed_policy_id).
///
/// Safe to commit this role with `Example-Managed-Policy-1` as its PB because the
/// `policy_query::test_list_policies_usage_filter_pb` assertions ran much earlier in the suite;
/// the role is removed before the test returns.
pub async fn test_get_role_with_permissions_boundary(pool: &sqlx::PgPool) {
    let pb_arn = "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("GetMePbRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary(Some(pb_arn.to_string()))
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create GetMePbRole with permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("GetMePbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get GetMePbRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pb = resp.role.permissions_boundary.expect("Role should have a permissions boundary");
    assert_eq!(pb.permissions_boundary_type, Some(PermissionsBoundaryAttachmentType::Policy));
    assert_eq!(pb.permissions_boundary_arn.as_deref(), Some(pb_arn));

    // Clean up through the API.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("GetMePbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to clear GetMePbRole PB");
    DeleteRoleInternalRequest::builder()
        .role_name("GetMePbRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete GetMePbRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Getting a nonexistent role must fail with NoSuchEntity.
pub async fn test_get_role_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetRoleInternalRequest::builder()
        .role_name("NoSuchGetRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Getting a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a GetRole request with an invalid role name must fail before touching the database.
pub fn test_get_role_invalid_name() {
    let result = GetRoleInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// List all roles in 123456789012. At this point in the suite the account holds Example-Role-1
/// (seed) plus LambdaExecutor, DeployRole (under /service-roles/), and LongSessionRole — all
/// committed by earlier create_role tests.
pub async fn test_list_roles(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list roles");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<&str> = resp.roles.iter().map(|r| r.role_name.as_str()).collect();
    assert!(names.contains(&"Example-Role-1"), "Expected Example-Role-1 in list, got {names:?}");
    assert!(names.contains(&"LambdaExecutor"), "Expected LambdaExecutor in list, got {names:?}");
    assert!(names.contains(&"DeployRole"), "Expected DeployRole in list, got {names:?}");
    assert!(names.contains(&"LongSessionRole"), "Expected LongSessionRole in list, got {names:?}");

    // Ordering must be ascending by lowercased role name.
    let lowercased: Vec<String> = resp.roles.iter().map(|r| r.role_name.to_lowercase()).collect();
    let mut sorted = lowercased.clone();
    sorted.sort();
    assert_eq!(lowercased, sorted, "Roles must be ordered by lowercased name");

    // Each Role payload must include the trust policy and an AROA-prefixed RoleId.
    for role in &resp.roles {
        assert!(role.role_id.starts_with("AROA"), "RoleId must start with AROA, got {}", role.role_id);
        assert!(
            role.assume_role_policy_document.is_some(),
            "AssumeRolePolicyDocument must be present for {}",
            role.role_name
        );
    }

    // The truncation/marker fields must be unset when everything fits in one page.
    assert!(resp.is_truncated != Some(true), "Expected no truncation, got {:?}", resp.is_truncated);
    assert!(resp.marker.is_none(), "Expected no marker, got {:?}", resp.marker);
}

/// List roles filtered to a specific path prefix.
pub async fn test_list_roles_with_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("/service-roles/".to_string()))
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list roles with path prefix");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.roles.len(), 1, "Expected exactly 1 role under /service-roles/");
    let role = &resp.roles[0];
    assert_eq!(role.role_name, "DeployRole");
    assert_eq!(role.path, "/service-roles/");
}

/// A path prefix that doesn't match any role must return an empty list (not an error).
pub async fn test_list_roles_path_prefix_no_match(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("/no-such-prefix/".to_string()))
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list roles with no-match path prefix");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.roles.is_empty(), "Expected empty role list, got {} roles", resp.roles.len());
}

/// Listing roles in an account that has none must succeed and return an empty list.
pub async fn test_list_roles_empty_account(pool: &sqlx::PgPool) {
    // 876543210000 is one of the bulk accounts created by test_create_350_accounts and has no
    // roles attached.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolesInternalRequest::builder()
        .account_id("876543210000".to_string())
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list roles in empty account");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.roles.is_empty(), "Expected empty role list, got {} roles", resp.roles.len());
}

/// Walk pagination: create 5 roles under a fresh path, page through them with max_items=2, then
/// roll back so subsequent tests aren't affected.
pub async fn test_list_roles_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    for i in 0..5 {
        CreateRoleInternalRequest::builder()
            .role_name(format!("PaginationRole{i}"))
            .path(Some("/pagination/".to_string()))
            .account_id("123456789012".to_string())
            .assume_role_policy_document(TRUST_POLICY.to_string())
            .build()
            .expect("Failed to build CreateRoleInternalRequest")
            .execute(&mut tx)
            .await
            .unwrap_or_else(|e| panic!("Failed to create PaginationRole{i}: {e:?}"));
    }

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListRolesResponse {
        let mut builder = ListRolesInternalRequest::builder()
            .account_id("123456789012".to_string())
            .path_prefix(Some("/pagination/".to_string()))
            .max_items(Some(2));
        if let Some(marker) = marker {
            builder = builder.marker(Some(marker));
        }
        builder
            .build()
            .expect("Failed to build ListRolesInternalRequest")
            .execute(tx)
            .await
            .expect("Failed to list roles page")
    };

    let page1 = list_page(&mut tx, None).await;
    assert_eq!(page1.roles.len(), 2, "page 1 should have max_items=2 entries");
    assert_eq!(page1.is_truncated, Some(true), "page 1 should be truncated");
    let marker1 = page1.marker.clone().expect("page 1 should have a marker");

    let page2 = list_page(&mut tx, Some(marker1)).await;
    assert_eq!(page2.roles.len(), 2, "page 2 should have max_items=2 entries");
    assert_eq!(page2.is_truncated, Some(true), "page 2 should be truncated");
    let marker2 = page2.marker.clone().expect("page 2 should have a marker");

    let page3 = list_page(&mut tx, Some(marker2)).await;
    assert_eq!(page3.roles.len(), 1, "page 3 should have the remaining 1 entry");
    assert!(page3.is_truncated != Some(true), "page 3 should not be truncated");
    assert!(page3.marker.is_none(), "page 3 should have no marker");

    let mut all_names: Vec<String> =
        page1.roles.iter().chain(page2.roles.iter()).chain(page3.roles.iter()).map(|r| r.role_name.clone()).collect();
    let unique: std::collections::HashSet<&String> = all_names.iter().collect();
    assert_eq!(unique.len(), all_names.len(), "Pages must not contain duplicate role names: {all_names:?}");

    all_names.sort();
    let expected: Vec<String> = (0..5).map(|i| format!("PaginationRole{i}")).collect();
    assert_eq!(all_names, expected, "Union of pages should cover all 5 roles");

    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Building a ListRoles request with a path prefix that lacks a leading slash must fail at the
/// Smithy shape regex (^/...) before reaching the database.
pub fn test_list_roles_invalid_path_prefix() {
    let result = ListRolesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("no-leading-slash/".to_string()))
        .build();
    assert!(result.is_err(), "Building a request with an invalid path prefix must fail");
}

/// List tags on `TaggedRole`, which was created earlier in the suite with two tags. Both must
/// come back ordered by lowercased key.
pub async fn test_list_role_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("TaggedRole".to_string())
        .account_id("210987654321".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list tags for TaggedRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2);
    assert_eq!(resp.tags[0].key, "Environment");
    assert_eq!(resp.tags[0].value, "Production");
    assert_eq!(resp.tags[1].key, "Team");
    assert_eq!(resp.tags[1].value, "Platform");
    assert!(resp.is_truncated != Some(true), "Expected no truncation, got {:?}", resp.is_truncated);
    assert!(resp.marker.is_none(), "Expected no marker, got {:?}", resp.marker);
}

/// Listing tags for a role with no tags must succeed and return an empty list.
pub async fn test_list_role_tags_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list tags for LambdaExecutor");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.tags.is_empty(), "Expected empty tag list, got {} tags", resp.tags.len());
}

/// Walk pagination: create a role with 5 tags, page through them with max_items=2.
pub async fn test_list_role_tags_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let tags: Vec<Tag> = (0..5)
        .map(|i| {
            Tag::builder()
                .key(format!("Key{i}"))
                .value(format!("Value{i}"))
                .build()
                .expect("Failed to build pagination tag")
        })
        .collect();
    CreateRoleInternalRequest::builder()
        .role_name("PaginationTagsRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .tags(tags)
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create PaginationTagsRole");

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListRoleTagsResponse {
        let mut builder = ListRoleTagsInternalRequest::builder()
            .role_name("PaginationTagsRole".to_string())
            .account_id("123456789012".to_string())
            .max_items(Some(2));
        if let Some(marker) = marker {
            builder = builder.marker(Some(marker));
        }
        builder
            .build()
            .expect("Failed to build ListRoleTagsInternalRequest")
            .execute(tx)
            .await
            .expect("Failed to list role tags page")
    };

    let page1 = list_page(&mut tx, None).await;
    assert_eq!(page1.tags.len(), 2, "page 1 should have max_items=2 entries");
    assert_eq!(page1.is_truncated, Some(true), "page 1 should be truncated");
    let marker1 = page1.marker.clone().expect("page 1 should have a marker");

    let page2 = list_page(&mut tx, Some(marker1)).await;
    assert_eq!(page2.tags.len(), 2, "page 2 should have max_items=2 entries");
    assert_eq!(page2.is_truncated, Some(true), "page 2 should be truncated");
    let marker2 = page2.marker.clone().expect("page 2 should have a marker");

    let page3 = list_page(&mut tx, Some(marker2)).await;
    assert_eq!(page3.tags.len(), 1, "page 3 should have the remaining 1 entry");
    assert!(page3.is_truncated != Some(true), "page 3 should not be truncated");
    assert!(page3.marker.is_none(), "page 3 should have no marker");

    let mut all_keys: Vec<String> =
        page1.tags.iter().chain(page2.tags.iter()).chain(page3.tags.iter()).map(|t| t.key.clone()).collect();
    let unique: std::collections::HashSet<&String> = all_keys.iter().collect();
    assert_eq!(unique.len(), all_keys.len(), "Pages must not contain duplicate tag keys: {all_keys:?}");

    all_keys.sort();
    let expected: Vec<String> = (0..5).map(|i| format!("Key{i}")).collect();
    assert_eq!(all_keys, expected, "Union of pages should cover all 5 tags");

    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Listing tags for a nonexistent role must fail with NoSuchEntity.
pub async fn test_list_role_tags_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListRoleTagsInternalRequest::builder()
        .role_name("NoSuchTagsRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Listing tags for a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListRoleTags request with an invalid role name must fail before touching the
/// database.
pub fn test_list_role_tags_invalid_name() {
    let result = ListRoleTagsInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Tag an existing role and verify the tags appear in ListRoleTags.
pub async fn test_tag_role(pool: &sqlx::PgPool) {
    // LambdaExecutor was created in account 123456789012 by test_create_role_simple with no tags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder()
                .key("Dept".to_string())
                .value("Engineering".to_string())
                .build()
                .expect("Failed to build tag"),
            Tag::builder()
                .key("CostCenter".to_string())
                .value("1234".to_string())
                .build()
                .expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify tags via ListRoleTags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list role tags");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on LambdaExecutor");
    // Tags are returned sorted by key_lower.
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Engineering");
}

/// Tagging with an existing key should update the value (upsert).
pub async fn test_tag_role_upsert(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Dept".to_string()).value("Finance".to_string()).build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag on role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the value was updated and the other tag is still present.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list role tags after upsert");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on LambdaExecutor after upsert");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Finance");
}

/// Tagging a nonexistent role must fail with NoSuchEntityException.
pub async fn test_tag_role_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = TagRoleInternalRequest::builder()
        .role_name("NoSuchTagRole".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Key".to_string()).value("Value".to_string()).build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Tagging a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Tagging with an empty tag list must fail.
pub async fn test_tag_role_empty_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging with an empty tag list must fail");
}

/// Untag an existing role and verify the tag is removed.
pub async fn test_untag_role(pool: &sqlx::PgPool) {
    // LambdaExecutor currently has CostCenter and Dept tags from the tag/upsert tests.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Dept".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify only CostCenter remains.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list role tags after untag");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 1, "Expected 1 tag on LambdaExecutor after removing Dept");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
}

/// Untagging a key that does not exist on the role should succeed silently.
pub async fn test_untag_role_nonexistent_key(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["NoSuchTag".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Untagging a nonexistent key should succeed silently");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Untagging with an empty tag key list must fail.
pub async fn test_untag_role_empty_keys(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec![])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging with an empty tag key list must fail");
}

/// Untagging a nonexistent role must fail with NoSuchEntityException.
pub async fn test_untag_role_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagRoleInternalRequest::builder()
        .role_name("NoSuchUntagRole".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Key".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Untagging a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// UpdateRole with only the description: column is changed, max_session_duration is left as-is.
pub async fn test_update_role_description_only(pool: &sqlx::PgPool) {
    // LambdaExecutor was committed earlier with no description and no max_session_duration.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .description(Some("Description set via UpdateRole.".to_string()))
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update LambdaExecutor description");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor after UpdateRole");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.role.description.as_deref(), Some("Description set via UpdateRole."));
    assert!(resp.role.max_session_duration.is_none(), "max_session_duration must remain NULL");
}

/// UpdateRole with only the max_session_duration: column is changed, description is left as-is.
pub async fn test_update_role_max_session_duration_only(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .max_session_duration(Some(7200))
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update LambdaExecutor max_session_duration");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor after UpdateRole");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.role.max_session_duration, Some(7200));
    // The description set in the previous test must be preserved.
    assert_eq!(resp.role.description.as_deref(), Some("Description set via UpdateRole."));
}

/// UpdateRole with both fields specified.
pub async fn test_update_role_both_fields(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .description(Some("Updated again.".to_string()))
        .max_session_duration(Some(10800))
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update both fields on LambdaExecutor");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor after UpdateRole");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.role.description.as_deref(), Some("Updated again."));
    assert_eq!(resp.role.max_session_duration, Some(10800));
}

/// UpdateRole with neither field specified must still succeed when the role exists (no-op).
pub async fn test_update_role_no_fields(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("UpdateRole with no fields on an existing role must succeed");
    tx.commit().await.expect("Failed to commit transaction");

    // Confirm the previous values are still in place.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor after no-op UpdateRole");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.role.description.as_deref(), Some("Updated again."));
    assert_eq!(resp.role.max_session_duration, Some(10800));
}

/// UpdateRole on a nonexistent role must fail with NoSuchEntity.
pub async fn test_update_role_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateRoleInternalRequest::builder()
        .role_name("NoSuchUpdateRole".to_string())
        .account_id("123456789012".to_string())
        .description(Some("Will not be applied.".to_string()))
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateRole on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building an UpdateRole request with a max_session_duration outside the allowed range must
/// fail at the Smithy builder before reaching the database.
pub fn test_update_role_invalid_max_session_duration() {
    let result = UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .max_session_duration(Some(60))
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration below 3600 must fail");

    let result = UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .max_session_duration(Some(100000))
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration above 43200 must fail");
}

/// Building an UpdateRole request with an invalid role name must fail before touching the database.
pub fn test_update_role_invalid_name() {
    let result = UpdateRoleInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// UpdateRoleDescription replaces the description and returns the updated role.
pub async fn test_update_role_description_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .description("Description set via UpdateRoleDescription.".to_string())
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update LambdaExecutor description");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role.expect("UpdateRoleDescriptionResponse should include the role");
    assert_eq!(role.role_name, "LambdaExecutor");
    assert_eq!(role.description.as_deref(), Some("Description set via UpdateRoleDescription."));
    // max_session_duration set earlier in test_update_role_both_fields must be preserved.
    assert_eq!(role.max_session_duration, Some(10800));

    // Double-check via GetRole that the change persisted.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let get_resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LambdaExecutor after UpdateRoleDescription");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(get_resp.role.description.as_deref(), Some("Description set via UpdateRoleDescription."));
}

/// UpdateRoleDescription with an empty string replaces the description with an empty string.
pub async fn test_update_role_description_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("LambdaExecutor".to_string())
        .account_id("123456789012".to_string())
        .description(String::new())
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update LambdaExecutor description to empty");
    tx.commit().await.expect("Failed to commit transaction");

    let role = resp.role.expect("UpdateRoleDescriptionResponse should include the role");
    assert_eq!(role.description.as_deref(), Some(""));
}

/// UpdateRoleDescription on a nonexistent role must fail with NoSuchEntity.
pub async fn test_update_role_description_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("NoSuchUpdateDescRole".to_string())
        .account_id("123456789012".to_string())
        .description("anything".to_string())
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateRoleDescription on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building an UpdateRoleDescription request with an invalid role name must fail before touching
/// the database.
pub fn test_update_role_description_invalid_name() {
    let result = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("bad role!".to_string())
        .account_id("123456789012".to_string())
        .description("ok".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}
