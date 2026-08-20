//! Role test suite.
use {
    base64::{Engine as _, engine::general_purpose::URL_SAFE},
    chrono::Utc,
    pretty_assertions::assert_eq,
    scratchstack_aws_signature::{
        DefaultSessionTokenExtractor, SessionTokenEncryptionAlgorithm as SigSessionTokenEncryptionAlgorithm,
        SessionTokenEncryptionKeyInfo, StaticKeyService,
    },
    scratchstack_core::RequestId,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateRoleInternalRequest, CreateSessionTokenEncryptionKeyRequest, DeleteRoleInternalRequest,
            DeleteRolePermissionsBoundaryInternalRequest, DeleteRolePolicyInternalRequest, GetRoleInternalRequest,
            GetRolePolicyInternalRequest, ListRolePoliciesInternalRequest, ListRoleTagsInternalRequest,
            ListRolesInternalRequest, PutRolePermissionsBoundaryInternalRequest, PutRolePolicyInternalRequest,
            TagRoleInternalRequest, UntagRoleInternalRequest, UpdateRoleDescriptionInternalRequest,
            UpdateRoleInternalRequest,
        },
        types::{PermissionsBoundaryAttachmentType, Tag},
    },
    scratchstack_shapes_sts::{error_meta::Error as StsError, operation::AssumeRoleRequest},
    tower::{Service as _, ServiceExt as _},
    zeroize::Zeroizing,
};

/// Simple trust policy that allows Lambda to assume the role.
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// Create a role with only the required fields — all other fields take defaults.
pub async fn test_create_role_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeployRole")
        .path("/service-roles/")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LongSessionRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .description("Role for long-running batch jobs.")
        .max_session_duration(14400)
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("TaggedRole")
        .account_id("210987654321")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .set_tags(vec![
            Tag::builder().key("Environment").value("Production").build().expect("Failed to build Environment tag"),
            Tag::builder().key("Team").value("Platform").build().expect("Failed to build Team tag"),
        ])
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("BoundedRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate role name must fail");
}

/// Building a request with an invalid role name must fail before touching the database.
pub fn test_create_role_invalid_name() {
    // Spaces and `!` are not in the allowed character set.
    let result = CreateRoleInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Building a request with a max_session_duration outside the allowed range must fail.
pub fn test_create_role_invalid_max_session_duration() {
    // 60 seconds is well below the 3600 minimum.
    let result = CreateRoleInternalRequest::builder()
        .role_name("ShortSessionRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .max_session_duration(60)
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration below 3600 must fail");

    // 100000 seconds is well above the 43200 maximum.
    let result = CreateRoleInternalRequest::builder()
        .role_name("VeryLongSessionRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .max_session_duration(100000)
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration above 43200 must fail");
}

/// Creating a role in an account that does not exist must fail with a FK violation.
pub async fn test_create_role_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateRoleInternalRequest::builder()
        .role_name("OrphanRole")
        .account_id("999999999999")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a role in a nonexistent account must fail");
}

/// Specifying a permissions boundary that references a policy that does not exist must fail.
pub async fn test_create_role_nonexistent_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateRoleInternalRequest::builder()
        .role_name("MissingBoundaryRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary("arn:aws:iam::123456789012:policy/NonExistentPolicy")
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a role with a nonexistent permissions boundary must fail");
}

/// Delete a role that has no attached or inline policies — success path.
pub async fn test_delete_role_simple(pool: &sqlx::PgPool) {
    // Create a fresh role so this test is self-contained.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create DeleteMeRole");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete DeleteMeRole");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same role must fail with NoSuchEntity.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("DeleteMeRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeTaggedRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .set_tags(vec![
            Tag::builder().key("Environment").value("Dev").build().expect("Failed to build Environment tag"),
        ])
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeTaggedRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeAttachedRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeAttachedRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeAttachedRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete DeleteMeAttachedRole after detaching policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A role with inline policies must not be deletable. Build a fresh role and write an inline
/// policy directly via SQL so this test does not depend on the seed role's mixed state.
pub async fn test_delete_role_inline_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMeInlineRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeInlineRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMeInlineRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete DeleteMeInlineRole after removing inline policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting a role that does not exist must fail with NoSuchEntity.
pub async fn test_delete_role_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRoleInternalRequest::builder()
        .role_name("NoSuchDeleteRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Deleting a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a request with an invalid role name must fail before touching the database.
pub fn test_delete_role_invalid_name() {
    let result = DeleteRoleInternalRequest::builder().role_name("bad role!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a delete request with an invalid role name must fail");
}

/// Clear a permissions boundary that is set on a role. The role exists and has a PB; afterwards
/// the column must be NULL.
pub async fn test_delete_role_permissions_boundary_simple(pool: &sqlx::PgPool) {
    // Set up: create a role with no PB, then attach a PB directly via SQL (the create_role API
    // verifies the PB exists by name, but we just need any seeded managed_policy_id here).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("DeleteMePbRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeleteMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete DeleteMePbRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteRolePermissionsBoundary on a role that has no PB must succeed (idempotent).
pub async fn test_delete_role_permissions_boundary_no_boundary(pool: &sqlx::PgPool) {
    // LambdaExecutor was committed earlier in test_create_role_simple with no PB.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("DeleteRolePermissionsBoundary on a role with no PB must succeed");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteRolePermissionsBoundary on a nonexistent role must fail with NoSuchEntity.
pub async fn test_delete_role_permissions_boundary_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("NoSuchPbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Clearing PB on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteRolePermissionsBoundary request with an invalid role name must fail before
/// touching the database.
pub fn test_delete_role_permissions_boundary_invalid_name() {
    let result = DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Get a role created earlier in the suite with no PB, tags, or extras. Validates the basic
/// projection (ARN, role_id prefix, path, trust policy).
pub async fn test_get_role_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("DeployRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("TaggedRole")
        .account_id("210987654321")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("GetMePbRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create GetMePbRole with permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("GetMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get GetMePbRole");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pb = resp.role.permissions_boundary.expect("Role should have a permissions boundary");
    assert_eq!(pb.permissions_boundary_type, Some(PermissionsBoundaryAttachmentType::Policy));
    assert_eq!(pb.permissions_boundary_arn.as_deref(), Some(pb_arn));

    // Clean up through the API.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("GetMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to clear GetMePbRole PB");
    DeleteRoleInternalRequest::builder()
        .role_name("GetMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete GetMePbRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Getting a nonexistent role must fail with NoSuchEntity.
pub async fn test_get_role_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetRoleInternalRequest::builder()
        .role_name("NoSuchGetRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Getting a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a GetRole request with an invalid role name must fail before touching the database.
pub fn test_get_role_invalid_name() {
    let result = GetRoleInternalRequest::builder().role_name("bad role!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// List all roles in 123456789012. At this point in the suite the account holds Example-Role-1
/// (seed) plus LambdaExecutor, DeployRole (under /service-roles/), and LongSessionRole — all
/// committed by earlier create_role tests.
pub async fn test_list_roles(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolesInternalRequest::builder()
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .path_prefix("/service-roles/")
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .path_prefix("/no-such-prefix/")
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("876543210000")
        .build()
        .expect("Failed to build ListRolesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
            .path("/pagination/")
            .account_id("123456789012")
            .assume_role_policy_document(TRUST_POLICY.to_string())
            .build()
            .expect("Failed to build CreateRoleInternalRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .unwrap_or_else(|e| panic!("Failed to create PaginationRole{i}: {e:?}"));
    }

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListRolesResponse {
        let mut builder =
            ListRolesInternalRequest::builder().account_id("123456789012").path_prefix("/pagination/").max_items(2);
        if let Some(marker) = marker {
            builder = builder.marker(marker);
        }
        builder
            .build()
            .expect("Failed to build ListRolesInternalRequest")
            .execute(tx, RequestId::new())
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
    let result =
        ListRolesInternalRequest::builder().account_id("123456789012").path_prefix("no-leading-slash/").build();
    assert!(result.is_err(), "Building a request with an invalid path prefix must fail");
}

/// List tags on `TaggedRole`, which was created earlier in the suite with two tags. Both must
/// come back ordered by lowercased key.
pub async fn test_list_role_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("TaggedRole")
        .account_id("210987654321")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("PaginationTagsRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .set_tags(tags)
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create PaginationTagsRole");

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListRoleTagsResponse {
        let mut builder = ListRoleTagsInternalRequest::builder()
            .role_name("PaginationTagsRole")
            .account_id("123456789012")
            .max_items(2);
        if let Some(marker) = marker {
            builder = builder.marker(marker);
        }
        builder
            .build()
            .expect("Failed to build ListRoleTagsInternalRequest")
            .execute(tx, RequestId::new())
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
        .role_name("NoSuchTagsRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing tags for a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListRoleTags request with an invalid role name must fail before touching the
/// database.
pub fn test_list_role_tags_invalid_name() {
    let result = ListRoleTagsInternalRequest::builder().role_name("bad role!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// Tag an existing role and verify the tags appear in ListRoleTags.
pub async fn test_tag_role(pool: &sqlx::PgPool) {
    // LambdaExecutor was created in account 123456789012 by test_create_role_simple with no tags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tags(vec![
            Tag::builder().key("Dept").value("Engineering").build().expect("Failed to build tag"),
            Tag::builder().key("CostCenter").value("1234").build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to tag role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify tags via ListRoleTags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tags(vec![Tag::builder().key("Dept").value("Finance").build().expect("Failed to build tag")])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to upsert tag on role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the value was updated and the other tag is still present.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("NoSuchTagRole")
        .account_id("123456789012")
        .set_tags(vec![Tag::builder().key("Key").value("Value").build().expect("Failed to build tag")])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Tagging a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Tagging with an empty tag list must fail.
pub async fn test_tag_role_empty_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tags(vec![])
        .build()
        .expect("Failed to build TagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging with an empty tag list must fail");
}

/// Untag an existing role and verify the tag is removed.
pub async fn test_untag_role(pool: &sqlx::PgPool) {
    // LambdaExecutor currently has CostCenter and Dept tags from the tag/upsert tests.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tag_keys(vec!["Dept".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to untag role");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify only CostCenter remains.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRoleTagsInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRoleTagsInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tag_keys(vec!["NoSuchTag".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Untagging a nonexistent key should succeed silently");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Untagging with an empty tag key list must fail.
pub async fn test_untag_role_empty_keys(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .set_tag_keys(vec![])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging with an empty tag key list must fail");
}

/// Untagging a nonexistent role must fail with NoSuchEntityException.
pub async fn test_untag_role_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagRoleInternalRequest::builder()
        .role_name("NoSuchUntagRole")
        .account_id("123456789012")
        .set_tag_keys(vec!["Key".to_string()])
        .build()
        .expect("Failed to build UntagRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .description("Description set via UpdateRole.")
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to update LambdaExecutor description");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .max_session_duration(7200)
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to update LambdaExecutor max_session_duration");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .description("Updated again.")
        .max_session_duration(10800)
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to update both fields on LambdaExecutor");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("UpdateRole with no fields on an existing role must succeed");
    tx.commit().await.expect("Failed to commit transaction");

    // Confirm the previous values are still in place.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("NoSuchUpdateRole")
        .account_id("123456789012")
        .description("Will not be applied.")
        .build()
        .expect("Failed to build UpdateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("UpdateRole on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building an UpdateRole request with a max_session_duration outside the allowed range must
/// fail at the Smithy builder before reaching the database.
pub fn test_update_role_invalid_max_session_duration() {
    let result = UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .max_session_duration(60)
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration below 3600 must fail");

    let result = UpdateRoleInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .max_session_duration(100000)
        .build();
    assert!(result.is_err(), "Building a request with max_session_duration above 43200 must fail");
}

/// Building an UpdateRole request with an invalid role name must fail before touching the database.
pub fn test_update_role_invalid_name() {
    let result = UpdateRoleInternalRequest::builder().role_name("bad role!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// UpdateRoleDescription replaces the description and returns the updated role.
pub async fn test_update_role_description_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .description("Description set via UpdateRoleDescription.")
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get LambdaExecutor after UpdateRoleDescription");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(get_resp.role.description.as_deref(), Some("Description set via UpdateRoleDescription."));
}

/// UpdateRoleDescription with an empty string replaces the description with an empty string.
pub async fn test_update_role_description_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .description(String::new())
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .role_name("NoSuchUpdateDescRole")
        .account_id("123456789012")
        .description("anything")
        .build()
        .expect("Failed to build UpdateRoleDescriptionInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("UpdateRoleDescription on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building an UpdateRoleDescription request with an invalid role name must fail before touching
/// the database.
pub fn test_update_role_description_invalid_name() {
    let result = UpdateRoleDescriptionInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .description("ok")
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// PutRolePermissionsBoundary sets the boundary, and a second call replaces it (here using the
/// same policy, exercising the UPDATE path on a row that already has the column populated).
pub async fn test_put_role_permissions_boundary_simple(pool: &sqlx::PgPool) {
    let pb_arn = "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create PutMePbRole");
    PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build PutRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to set PutMePbRole permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRoleInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get PutMePbRole");
    tx.rollback().await.expect("Failed to rollback transaction");
    let pb = resp.role.permissions_boundary.expect("Role should have a permissions boundary");
    assert_eq!(pb.permissions_boundary_type, Some(PermissionsBoundaryAttachmentType::Policy));
    assert_eq!(pb.permissions_boundary_arn.as_deref(), Some(pb_arn));

    // Calling Put again on a role that already has a PB must succeed.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build PutRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Re-putting the same permissions boundary on PutMePbRole must succeed");
    tx.commit().await.expect("Failed to commit transaction");

    // Clean up.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePermissionsBoundaryInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to clear PutMePbRole PB");
    DeleteRoleInternalRequest::builder()
        .role_name("PutMePbRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete PutMePbRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// PutRolePermissionsBoundary on a nonexistent role must fail with NoSuchEntity.
pub async fn test_put_role_permissions_boundary_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("NoSuchPutPbRole")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build PutRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("PutRolePermissionsBoundary on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// PutRolePermissionsBoundary with a PB ARN that refers to a nonexistent policy must fail with
/// NoSuchEntity (raised by the permissions-boundary lookup helper).
pub async fn test_put_role_permissions_boundary_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/NoSuchPolicy")
        .build()
        .expect("Failed to build PutRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("PutRolePermissionsBoundary with a nonexistent PB policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// PutRolePermissionsBoundary with a malformed PB ARN must fail with ValidationError.
pub async fn test_put_role_permissions_boundary_invalid_arn(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        // Long enough to pass the shape's min-length check, but not a valid ARN.
        .permissions_boundary("not-an-arn-but-long-enough-to-pass")
        .build()
        .expect("Failed to build PutRolePermissionsBoundaryInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("PutRolePermissionsBoundary with an invalid ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// Building a PutRolePermissionsBoundary request with an invalid role name must fail before
/// touching the database.
pub fn test_put_role_permissions_boundary_invalid_name() {
    let result = PutRolePermissionsBoundaryInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

const INLINE_ROLE_POLICY_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
const INLINE_ROLE_POLICY_EC2: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
const INLINE_ROLE_POLICY_UNKNOWN_PRINCIPAL: &str = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

/// PutRolePolicy attaches an inline policy to an existing role.
pub async fn test_put_role_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .policy_document(INLINE_ROLE_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to put inline policy on LambdaExecutor");
    tx.commit().await.expect("Failed to commit transaction");

    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.role_inline_policies \
         WHERE role_id = (SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("lambdaexecutor")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch LambdaExecutor inline policy");
    assert_eq!(doc, INLINE_ROLE_POLICY_S3);
}

/// PutRolePolicy with the same policy name replaces the document on the same row.
pub async fn test_put_role_policy_replaces(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .policy_document(INLINE_ROLE_POLICY_EC2.to_string())
        .build()
        .expect("Failed to build PutRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to replace inline policy on LambdaExecutor");
    tx.commit().await.expect("Failed to commit transaction");

    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.role_inline_policies \
         WHERE role_id = (SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("lambdaexecutor")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch LambdaExecutor inline policy after replace");
    assert_eq!(doc, INLINE_ROLE_POLICY_EC2);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.role_inline_policies \
         WHERE role_id = (SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("lambdaexecutor")
    .fetch_one(pool)
    .await
    .expect("Failed to count LambdaExecutor inline policies");
    assert_eq!(count, 1, "Replacing must not create a new row");
}

/// A syntactically valid principal that references a non-existent account/user is still accepted.
pub async fn test_put_role_policy_invalid_principal_accepted(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineWithMissingPrincipal")
        .policy_document(INLINE_ROLE_POLICY_UNKNOWN_PRINCIPAL.to_string())
        .build()
        .expect("Failed to build PutRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Policies referring to non-existent principals must still be accepted");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A non-JSON / unparseable policy document must fail with MalformedPolicyDocument.
pub async fn test_put_role_policy_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineBroken")
        .policy_document("{ not valid aspen json }")
        .build()
        .expect("Failed to build PutRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("PutRolePolicy with malformed JSON must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(
        matches!(err, IamError::MalformedPolicyDocumentException(_)),
        "Expected MalformedPolicyDocumentException, got: {err:?}"
    );
}

/// PutRolePolicy on a nonexistent role must fail with NoSuchEntity.
pub async fn test_put_role_policy_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutRolePolicyInternalRequest::builder()
        .role_name("NoSuchPutPolicyRole")
        .account_id("123456789012")
        .policy_name("AnyName")
        .policy_document(INLINE_ROLE_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("PutRolePolicy on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a PutRolePolicy request with an invalid role name must fail before touching the
/// database.
pub fn test_put_role_policy_invalid_name() {
    let result = PutRolePolicyInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .policy_document(INLINE_ROLE_POLICY_S3.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// GetRolePolicy returns the policy document set via PutRolePolicy.
pub async fn test_get_role_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .build()
        .expect("Failed to build GetRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get inline policy on LambdaExecutor");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.role_name, "LambdaExecutor");
    assert_eq!(resp.policy_name, "InlineRead");
    assert_eq!(resp.policy_document, INLINE_ROLE_POLICY_EC2);
}

/// GetRolePolicy returns the document under the original case for the policy name even when
/// looked up using a different case.
pub async fn test_get_role_policy_case_insensitive_lookup(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetRolePolicyInternalRequest::builder()
        .role_name("lambdaexecutor")
        .account_id("123456789012")
        .policy_name("inlineread")
        .build()
        .expect("Failed to build GetRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get inline policy via case-insensitive lookup");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.role_name, "LambdaExecutor");
    assert_eq!(resp.policy_name, "InlineRead");
}

/// GetRolePolicy on a nonexistent inline policy must fail with NoSuchEntity.
pub async fn test_get_role_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("NotAttached")
        .build()
        .expect("Failed to build GetRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("GetRolePolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// GetRolePolicy on a nonexistent role must fail with NoSuchEntity.
pub async fn test_get_role_policy_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetRolePolicyInternalRequest::builder()
        .role_name("NoSuchGetPolicyRole")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build()
        .expect("Failed to build GetRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("GetRolePolicy on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a GetRolePolicy request with an invalid role name must fail before touching the
/// database.
pub fn test_get_role_policy_invalid_name() {
    let result = GetRolePolicyInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// ListRolePolicies returns the policy names attached to a role in sorted (case-insensitive)
/// order.
pub async fn test_list_role_policies_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListRolePoliciesInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list inline policies on LambdaExecutor");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.policy_names, vec!["InlineRead".to_string(), "InlineWithMissingPrincipal".to_string()]);
    assert_eq!(resp.is_truncated, None);
    assert_eq!(resp.marker, None);
}

/// ListRolePolicies returns an empty list when the role has no inline policies attached.
pub async fn test_list_role_policies_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateRoleInternalRequest::builder()
        .role_name("ListPoliciesEmptyRole")
        .account_id("123456789012")
        .assume_role_policy_document(TRUST_POLICY.to_string())
        .build()
        .expect("Failed to build CreateRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create ListPoliciesEmptyRole");
    let resp = ListRolePoliciesInternalRequest::builder()
        .role_name("ListPoliciesEmptyRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list inline policies on empty role");
    assert!(resp.policy_names.is_empty(), "Expected no inline policies, got: {:?}", resp.policy_names);
    assert_eq!(resp.is_truncated, None);

    DeleteRoleInternalRequest::builder()
        .role_name("ListPoliciesEmptyRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteRoleInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete ListPoliciesEmptyRole");
    tx.commit().await.expect("Failed to commit transaction");
}

/// ListRolePolicies honors `max_items` and emits a usable marker for the next page.
pub async fn test_list_role_policies_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListRolePoliciesInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .max_items(1)
        .build()
        .expect("Failed to build ListRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list inline policies on LambdaExecutor (page 1)");
    assert_eq!(page1.policy_names, vec!["InlineRead".to_string()]);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.clone().expect("Expected a pagination marker");

    let page2 = ListRolePoliciesInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .max_items(1)
        .marker(marker)
        .build()
        .expect("Failed to build ListRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list inline policies on LambdaExecutor (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.policy_names, vec!["InlineWithMissingPrincipal".to_string()]);
    assert_eq!(page2.is_truncated, None);
    assert_eq!(page2.marker, None);
}

/// ListRolePolicies on a nonexistent role must fail with NoSuchEntity.
pub async fn test_list_role_policies_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListRolePoliciesInternalRequest::builder()
        .role_name("NoSuchListPoliciesRole")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("ListRolePolicies on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListRolePolicies request with an invalid role name must fail before touching the
/// database.
pub fn test_list_role_policies_invalid_name() {
    let result = ListRolePoliciesInternalRequest::builder().role_name("bad role!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// DeleteRolePolicy removes an inline policy previously attached via PutRolePolicy.
pub async fn test_delete_role_policy_simple(pool: &sqlx::PgPool) {
    // The "InlineWithMissingPrincipal" inline policy was added in test_put_role_policy_invalid_principal_accepted.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("InlineWithMissingPrincipal")
        .build()
        .expect("Failed to build DeleteRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete inline policy on LambdaExecutor");
    tx.commit().await.expect("Failed to commit transaction");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.role_inline_policies \
         WHERE role_id = (SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("lambdaexecutor")
    .bind("inlinewithmissingprincipal")
    .fetch_one(pool)
    .await
    .expect("Failed to count LambdaExecutor inline policy after delete");
    assert_eq!(count, 0, "Deleted inline policy must be gone");

    // The other policy ("InlineRead") must still be present.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.role_inline_policies \
         WHERE role_id = (SELECT role_id FROM iam.roles WHERE account_id = $1 AND role_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("lambdaexecutor")
    .fetch_one(pool)
    .await
    .expect("Failed to count remaining LambdaExecutor inline policies");
    assert_eq!(remaining, 1, "Only the targeted inline policy must be removed");
}

/// DeleteRolePolicy with a policy name that is not attached must fail with NoSuchEntity.
pub async fn test_delete_role_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRolePolicyInternalRequest::builder()
        .role_name("LambdaExecutor")
        .account_id("123456789012")
        .policy_name("NotAttached")
        .build()
        .expect("Failed to build DeleteRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("DeleteRolePolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// DeleteRolePolicy on a nonexistent role must fail with NoSuchEntity.
pub async fn test_delete_role_policy_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteRolePolicyInternalRequest::builder()
        .role_name("NoSuchDeletePolicyRole")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build()
        .expect("Failed to build DeleteRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("DeleteRolePolicy on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteRolePolicy request with an invalid role name must fail before touching the
/// database.
pub fn test_delete_role_policy_invalid_name() {
    let result = DeleteRolePolicyInternalRequest::builder()
        .role_name("bad role!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build();
    assert!(result.is_err(), "Building a request with an invalid role name must fail");
}

/// AssumeRole returns credentials whose session token round-trips through the default session
/// token extractor.
pub async fn test_assume_role(pool: &sqlx::PgPool) {
    // Create a session token encryption key for AssumeRole to encrypt the session token with.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let stek = CreateSessionTokenEncryptionKeyRequest::builder()
        .issue_valid_from(Utc::now())
        .build()
        .expect("Failed to build CreateSessionTokenEncryptionKeyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create session token encryption key")
        .session_token_encryption_key;
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = AssumeRoleRequest::builder()
        .role_arn("arn:aws:iam::123456789012:role/example-role-1")
        .role_session_name("test-session")
        .source_identity("test-identity")
        .build()
        .expect("Failed to build AssumeRoleRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to assume role");
    tx.commit().await.expect("Failed to commit transaction");

    let assumed_role_user = resp.assumed_role_user.expect("AssumedRoleUser should be present");
    assert_eq!(assumed_role_user.arn, "arn:aws:sts::123456789012:assumed-role/example-role-1/test-session");
    assert_eq!(assumed_role_user.assumed_role_id, "AROAEXAMPLEROLEID123:test-session");
    assert_eq!(resp.source_identity.as_deref(), Some("test-identity"));

    let credentials = resp.credentials.expect("Credentials should be present");
    assert!(
        credentials.access_key_id.starts_with("ASIA"),
        "Access key ID must start with ASIA prefix, got {}",
        credentials.access_key_id
    );
    assert!(!credentials.secret_access_key.is_empty());
    assert!(credentials.expiration > Utc::now());

    // Decrypt the session token and verify that it matches the issued credentials.
    let key_info = SessionTokenEncryptionKeyInfo {
        session_token_encryption_key_id: stek.session_token_encryption_key_id.clone(),
        encryption_algorithm: SigSessionTokenEncryptionAlgorithm::Aes256Gcm,
        encryption_key: Zeroizing::new(URL_SAFE.decode(&stek.encryption_key).expect("Failed to decode encryption key")),
    };
    let mut key_service = StaticKeyService::new();
    key_service.0.insert(stek.session_token_encryption_key_id.clone(), key_info);
    let mut extractor = DefaultSessionTokenExtractor::new(key_service);
    let token_data = extractor
        .ready()
        .await
        .expect("Extractor should be ready")
        .call(credentials.session_token.clone())
        .await
        .expect("Failed to extract session token");

    assert_eq!(token_data.access_key_id, credentials.access_key_id);
    assert_eq!(token_data.secret_key.as_str(), credentials.secret_access_key);
    assert_eq!(token_data.role_id, "EXAMPLEROLEID123");
    assert_eq!(token_data.role_session_name, "test-session");
    assert_eq!(token_data.expires_at, credentials.expiration);
    assert!(token_data.inline_policy.is_none());
    assert!(token_data.managed_policy_ids.is_empty());
}

/// AssumeRole on a nonexistent role must fail with AccessDenied, not NoSuchEntity, to avoid
/// leaking role existence.
pub async fn test_assume_role_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = AssumeRoleRequest::builder()
        .role_arn("arn:aws:iam::123456789012:role/does-not-exist")
        .role_session_name("test-session")
        .build()
        .expect("Failed to build AssumeRoleRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("AssumeRole on a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, StsError::AccessDeniedException(_)), "Expected AccessDenied, got: {err:?}");
}

/// AssumeRole with a non-role ARN must fail with a validation error.
pub async fn test_assume_role_invalid_arn(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = AssumeRoleRequest::builder()
        .role_arn("arn:aws:iam::123456789012:user/example-user-1")
        .role_session_name("test-session")
        .build()
        .expect("Failed to build AssumeRoleRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("AssumeRole with a non-role ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, StsError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// AssumeRole with a malformed inline session policy must fail with MalformedPolicyDocument.
pub async fn test_assume_role_malformed_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = AssumeRoleRequest::builder()
        .role_arn("arn:aws:iam::123456789012:role/example-role-1")
        .role_session_name("test-session")
        .policy("not a policy document")
        .build()
        .expect("Failed to build AssumeRoleRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("AssumeRole with a malformed policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(
        matches!(err, StsError::MalformedPolicyDocumentException(_)),
        "Expected MalformedPolicyDocument, got: {err:?}"
    );
}
