//! Role test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{operation::CreateRoleInternalRequest, types::Tag},
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
