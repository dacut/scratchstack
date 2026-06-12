//! DeletePolicy test suite — covers the can/cannot-delete invariants
//! (attachments, permissions-boundary usage, non-default versions, ARN routing).
use {
    super::common::VALID_POLICY_DOCUMENT,
    pretty_assertions::assert_eq,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyVersionRequest, DeletePolicyRequest, DeletePolicyVersionRequest,
            GetPolicyRequest,
        },
        types::Tag,
    },
};

/// Helper: strip the "ANPA" prefix to get the raw managed_policy_id stored in the DB.
fn managed_policy_id_from(policy: &scratchstack_shapes_iam::types::Policy) -> String {
    policy.policy_id.as_deref().expect("policy_id").strip_prefix("ANPA").expect("policy_id has ANPA prefix").to_string()
}

/// Simple success path: create a fresh policy with only the default version and no attachments,
/// delete it, and confirm it's gone.
pub async fn test_delete_policy_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeSimple";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeSimple".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeSimple");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeSimple");
    tx.commit().await.expect("Failed to commit transaction");

    // GetPolicy should now fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteMeSimple should no longer exist");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");

    // Re-deleting the same policy should also fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting DeleteMeSimple should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Verify that DeletePolicy cascades to managed_policy_versions (the default version) and
/// managed_policy_tags. The migration adds ON DELETE CASCADE to managed_policy_versions; the
/// managed_policy_tags FK was already CASCADE.
pub async fn test_delete_policy_cascade_tags_and_default_version(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeCascade";

    let managed_policy_id = {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = CreatePolicyInternalRequest::builder()
            .policy_name("DeleteMeCascade".to_string())
            .policy_document(VALID_POLICY_DOCUMENT.to_string())
            .account_id("123456789012".to_string())
            .tags(vec![
                Tag::builder()
                    .key("Environment".to_string())
                    .value("Dev".to_string())
                    .build()
                    .expect("Failed to build tag"),
            ])
            .build()
            .expect("Failed to build CreatePolicyInternalRequest")
            .execute(&mut tx)
            .await
            .expect("Failed to create DeleteMeCascade");
        tx.commit().await.expect("Failed to commit transaction");
        managed_policy_id_from(resp.policy.as_ref().expect("Response should include created policy"))
    };

    // Sanity: a tag row and a version row exist before delete.
    let pre_versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM iam.managed_policy_versions WHERE managed_policy_id = $1")
            .bind(&managed_policy_id)
            .fetch_one(pool)
            .await
            .expect("Failed to count versions");
    assert_eq!(pre_versions, 1, "Expected exactly v1 to exist before delete");
    let pre_tags: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iam.managed_policy_tags WHERE managed_policy_id = $1")
        .bind(&managed_policy_id)
        .fetch_one(pool)
        .await
        .expect("Failed to count tags");
    assert_eq!(pre_tags, 1, "Expected exactly one tag to exist before delete");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeCascade");
    tx.commit().await.expect("Failed to commit transaction");

    let post_versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM iam.managed_policy_versions WHERE managed_policy_id = $1")
            .bind(&managed_policy_id)
            .fetch_one(pool)
            .await
            .expect("Failed to count versions after delete");
    assert_eq!(post_versions, 0, "managed_policy_versions rows should cascade-delete with the policy");
    let post_tags: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM iam.managed_policy_tags WHERE managed_policy_id = $1")
            .bind(&managed_policy_id)
            .fetch_one(pool)
            .await
            .expect("Failed to count tags after delete");
    assert_eq!(post_tags, 0, "managed_policy_tags rows should cascade-delete with the policy");
}

/// A policy attached to a user must not be deletable.
pub async fn test_delete_policy_attached_to_user_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeUserAttached";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeUserAttached".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeUserAttached");
    let managed_policy_id = managed_policy_id_from(resp.policy.as_ref().expect("Response should include policy"));
    sqlx::query("INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES ($1, $2)")
        .bind("EXAMPLEUSERID123")
        .bind(&managed_policy_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach DeleteMeUserAttached to a user");

    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a user-attached policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// A policy attached to a group must not be deletable.
pub async fn test_delete_policy_attached_to_group_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeGroupAttached";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeGroupAttached".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeGroupAttached");
    let managed_policy_id = managed_policy_id_from(resp.policy.as_ref().expect("Response should include policy"));
    sqlx::query("INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES ($1, $2)")
        .bind("EXAMPLEGROUPID123")
        .bind(&managed_policy_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach DeleteMeGroupAttached to a group");

    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a group-attached policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// A policy attached to a role must not be deletable.
pub async fn test_delete_policy_attached_to_role_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeRoleAttached";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeRoleAttached".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeRoleAttached");
    let managed_policy_id = managed_policy_id_from(resp.policy.as_ref().expect("Response should include policy"));
    sqlx::query("INSERT INTO iam.role_attached_policies(role_id, managed_policy_id) VALUES ($1, $2)")
        .bind("EXAMPLEROLEID123")
        .bind(&managed_policy_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach DeleteMeRoleAttached to a role");

    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a role-attached policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// A policy used as a user's permissions boundary must not be deletable.
pub async fn test_delete_policy_user_permissions_boundary_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeUserPB";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeUserPB".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeUserPB");
    let managed_policy_id = managed_policy_id_from(resp.policy.as_ref().expect("Response should include policy"));
    sqlx::query("UPDATE iam.users SET permissions_boundary_managed_policy_id = $1 WHERE user_id = $2")
        .bind(&managed_policy_id)
        .bind("EXAMPLEUSERID456")
        .execute(tx.as_mut())
        .await
        .expect("Failed to set user's permissions boundary");

    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a policy that is a user's permissions boundary must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// A policy used as a role's permissions boundary must not be deletable.
pub async fn test_delete_policy_role_permissions_boundary_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeRolePB";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeRolePB".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeRolePB");
    let managed_policy_id = managed_policy_id_from(resp.policy.as_ref().expect("Response should include policy"));
    sqlx::query("UPDATE iam.roles SET permissions_boundary_managed_policy_id = $1 WHERE role_id = $2")
        .bind(&managed_policy_id)
        .bind("EXAMPLEROLEID123")
        .execute(tx.as_mut())
        .await
        .expect("Failed to set role's permissions boundary");

    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a policy that is a role's permissions boundary must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// A policy with versions other than the default must not be deletable.
pub async fn test_delete_policy_with_non_default_versions_fails(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/DeleteMeMultiVersion";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("DeleteMeMultiVersion".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeMultiVersion");
    CreatePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#
                .to_string(),
        )
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2 of DeleteMeMultiVersion");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a policy with non-default versions must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Delete v2, then DeletePolicy should now succeed: this exercises the same code path again with
    // the only version being the default, and leaves the test database clean of DeleteMeMultiVersion.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v2");
    DeletePolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeMultiVersion after pruning v2");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting a policy that does not exist must fail with NoSuchEntity.
pub async fn test_delete_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchDeletePolicy".to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting a policy with a mismatched path must fail with NoSuchEntity.
pub async fn test_delete_policy_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("MismatchedDeleteMe".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create /engineering/MismatchedDeleteMe");
    tx.commit().await.expect("Failed to commit transaction");

    // ARN omits the /engineering/ path, so the policy must not be found.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/MismatchedDeleteMe".to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting with a mismatched path must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");

    // Clean up: delete it via the correct ARN.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/MismatchedDeleteMe".to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete /engineering/MismatchedDeleteMe");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting with an unparseable ARN must fail with ValidationError.
pub async fn test_delete_policy_invalid_arn(pool: &sqlx::PgPool) {
    let cases: &[(&str, &str)] = &[
        ("not-an-arn-but-long-enough-to-pass", "unparseable ARN"),
        ("arn:test-partition:s3:::policy/SomePolicy", "wrong service"),
        ("arn:test-partition:iam:us-east-1:123456789012:policy/SomePolicy", "non-empty region"),
        ("arn:test-partition:iam::123456789012:user/SomeUser", "non-policy resource"),
    ];

    for (arn, label) in cases {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let result = DeletePolicyRequest::builder()
            .policy_arn(arn.to_string())
            .build()
            .expect("Failed to build DeletePolicyRequest")
            .execute(&mut tx)
            .await;
        tx.rollback().await.expect("Failed to rollback transaction");
        let err = match result {
            Ok(_) => panic!("Expected error for {label} ({arn}), got Ok"),
            Err(e) => e,
        };
        assert!(
            matches!(err, IamError::ValidationError(_)),
            "Expected ValidationError for {label} ({arn}), got: {err:?}"
        );
    }
}

/// Deleting an AWS-owned policy must accept either the "aws" alias or the numeric account in the
/// ARN.
pub async fn test_delete_policy_aws_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("AwsOwnedDeleteMe".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("000000000000".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create AwsOwnedDeleteMe");
    tx.commit().await.expect("Failed to commit transaction");

    // Delete via the "aws" alias.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDeleteMe".to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete AwsOwnedDeleteMe via 'aws' account alias");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting via the numeric account must report NoSuchEntity (proves the alias hit the same
    // row).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::000000000000:policy/AwsOwnedDeleteMe".to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("AwsOwnedDeleteMe should already be gone");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}
