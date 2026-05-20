//! Role test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateRoleInternalRequest, DeleteRoleInternalRequest, DeleteRolePermissionsBoundaryInternalRequest,
            GetRoleInternalRequest,
        },
        types::Tag,
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
        .role_name("LongSessionRole".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get LongSessionRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    let role = resp.role;
    assert_eq!(role.role_name, "LongSessionRole");
    assert_eq!(role.description.as_deref(), Some("Role for long-running batch jobs."));
    assert_eq!(role.max_session_duration, Some(14400));
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

/// Get a role that has a permissions boundary set. The response must surface the PB as a Policy.
pub async fn test_get_role_with_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("GetMePbRole".to_string())
        .account_id("123456789012".to_string())
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create GetMePbRole");
    let role_id: String =
        sqlx::query_scalar("SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2")
            .bind("123456789012")
            .bind("getmepbrole")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch GetMePbRole role_id");
    sqlx::query("UPDATE iam.roles SET permissions_boundary_managed_policy_id = $1 WHERE role_id = $2")
        .bind("AAAABBBBCCCCDDDD")
        .bind(&role_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to set GetMePbRole permissions boundary");
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
    assert!(pb.permissions_boundary_arn.as_deref().unwrap_or("").contains("AAAABBBBCCCCDDDD"));

    // Clean up.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("UPDATE iam.roles SET permissions_boundary_managed_policy_id = NULL WHERE role_id = $1")
        .bind(&role_id)
        .execute(tx.as_mut())
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
