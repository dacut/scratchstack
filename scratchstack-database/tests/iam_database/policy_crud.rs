//! Policy create + version + tag + set-default test suite, plus the cross-cutting update_date
//! lifecycle test.
use {
    super::common::VALID_POLICY_DOCUMENT,
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, CreatePolicyVersionRequest, DeletePolicyVersionRequest, GetPolicyRequest,
            SetDefaultPolicyVersionRequest, TagPolicyRequest, UntagPolicyRequest,
        },
        types::Tag,
    },
};

// -- CreatePolicyInternalRequest tests ----------------------------------------

/// Create a simple managed policy with defaults.
pub async fn test_create_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("TestPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.policy_name.as_deref(), Some("TestPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/"));
    assert!(
        policy.policy_id.as_ref().unwrap().starts_with("ANPA"),
        "Policy ID must start with ANPA prefix, got {:?}",
        policy.policy_id
    );
    assert!(
        policy.arn.as_ref().unwrap().ends_with(":policy/TestPolicy"),
        "ARN must end with :policy/TestPolicy, got {:?}",
        policy.arn
    );
    assert_eq!(policy.default_version_id.as_deref(), Some("v1"));
    assert_eq!(policy.is_attachable, Some(true));
    assert_eq!(policy.attachment_count, Some(0));
    assert_eq!(policy.permissions_boundary_usage_count, Some(0));
    assert!(policy.description.is_none());
    assert!(policy.tags.is_empty());
}

/// Create a policy with a non-default path.
pub async fn test_create_policy_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("PathPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with path");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.path.as_deref(), Some("/engineering/"));
    assert!(
        policy.arn.as_ref().unwrap().ends_with(":policy/engineering/PathPolicy"),
        "ARN must end with :policy/engineering/PathPolicy, got {:?}",
        policy.arn
    );
}

/// Create a policy with a description.
pub async fn test_create_policy_with_description(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DescribedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .description(Some("Grants read access to S3 objects".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with description");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.description.as_deref(), Some("Grants read access to S3 objects"));
}

/// Create a policy with tags.
pub async fn test_create_policy_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("TaggedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build tag"),
            Tag::builder().key("Team".to_string()).value("Platform".to_string()).build().expect("Failed to build tag"),
        ])
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.tags.len(), 2, "Expected 2 tags on policy");
}

/// Creating a policy with a duplicate name must fail.
pub async fn test_create_policy_duplicate_name(pool: &sqlx::PgPool) {
    // "TestPolicy" was committed by test_create_policy_simple; re-inserting must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("TestPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate policy name must fail");
}

/// Creating a policy with an invalid policy document must fail.
pub async fn test_create_policy_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("BadDocPolicy".to_string())
        .policy_document("not valid json".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with an invalid document must fail");
}

/// Creating a policy with valid JSON that is not a valid Aspen policy must fail.
pub async fn test_create_policy_valid_json_invalid_aspen(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("ValidJsonBadAspen".to_string())
        .policy_document(r#"{"foo": "bar"}"#.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with valid JSON but invalid Aspen document must fail");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("ValidJsonBadAspen".to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Resource":"*"}]}"#.to_string(),
        )
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with valid JSON but invalid Aspen document must fail");
}

/// Creating a policy in an account that does not exist must fail.
pub async fn test_create_policy_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("OrphanPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy in a nonexistent account must fail");
}

// -- CreatePolicyVersionRequest tests -----------------------------------------

/// Create a new policy version with set_as_default = true (default behavior).
pub async fn test_create_policy_version_simple(pool: &sqlx::PgPool) {
    // First, create a policy to add versions to.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("VersionedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    // Now create a new version.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v2"));
    assert_eq!(pv.is_default_version, Some(true));
    assert_eq!(pv.document.as_deref(), Some(new_document));
    assert!(pv.create_date.is_some());
}

/// Create a policy version with set_as_default = true explicitly.
pub async fn test_create_policy_version_set_as_default(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version as default");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v3"));
    assert_eq!(pv.is_default_version, Some(true));
}

/// Create a policy version with set_as_default = false.
pub async fn test_create_policy_version_not_default(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version (not default)");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v4"));
    assert_eq!(pv.is_default_version, Some(false));
}

/// Exceeding 5 versions must fail with LimitExceededException.
pub async fn test_create_policy_version_limit_exceeded(pool: &sqlx::PgPool) {
    // v1 was created with the policy, v2-v4 above. Create v5.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let doc_v5 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(doc_v5.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version v5");
    tx.commit().await.expect("Failed to commit transaction");

    // Now attempt to create v6, which must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let doc_v6 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*"}]}"#;
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(doc_v6.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a 6th policy version must fail");
}

/// Creating a version for a nonexistent policy must fail.
pub async fn test_create_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version for a nonexistent policy must fail");
}

/// Creating a version with an ARN whose path does not match the policy path must fail.
pub async fn test_create_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("PathSensitivePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/wrong/PathSensitivePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version with a mismatched path must fail");
}

/// Creating a version with an invalid policy document must fail.
pub async fn test_create_policy_version_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document("not valid json".to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version with an invalid document must fail");
}

/// CreatePolicyVersion still has its own inline ARN parsing (separate from `parse_policy_arn`).
/// Both rejection branches should surface as ValidationError.
pub async fn test_create_policy_version_invalid_arn(pool: &sqlx::PgPool) {
    let cases: &[(&str, &str)] = &[
        // Unparseable but long enough to pass the Smithy 20-char minimum.
        ("not-an-arn-but-long-enough-to-pass", "unparseable ARN"),
        // Resource doesn't start with "policy/".
        ("arn:test-partition:iam::123456789012:user/SomeUser", "non-policy resource"),
    ];
    for (arn, label) in cases {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let result = CreatePolicyVersionRequest::builder()
            .policy_arn(arn.to_string())
            .policy_document(VALID_POLICY_DOCUMENT.to_string())
            .build()
            .expect("Failed to build CreatePolicyVersionRequest")
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

// -- DeletePolicyVersionRequest tests -----------------------------------------

/// Delete a non-default version of a managed policy. After the test_create_policy_version_*
/// tests, "VersionedPolicy" has versions v1..v5 with v3 as the default version. v1 is not the
/// default, so deleting it should succeed.
pub async fn test_delete_policy_version_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete policy version v1");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same version should fail with NoSuchEntity since the row is gone.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting v1 should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting the default version must fail with DeleteConflictException.
pub async fn test_delete_policy_version_default_fails(pool: &sqlx::PgPool) {
    // v3 is the default version of VersionedPolicy.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting the default version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Confirm v3 is still present by trying to delete it again (still must fail with DeleteConflict).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Default version still cannot be deleted on a retry");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// Deleting a version on a policy with a non-default path must work when the ARN's path matches.
pub async fn test_delete_policy_version_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("PathDelVersion".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy at /engineering/PathDelVersion");
    let doc_v2 = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathDelVersion".to_string())
        .policy_document(doc_v2.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2 of /engineering/PathDelVersion");
    tx.commit().await.expect("Failed to commit transaction");

    // v1 is no longer the default; delete it.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v1 of /engineering/PathDelVersion");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting a version using an ARN with the wrong path must fail with NoSuchEntity.
pub async fn test_delete_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    // PathDelVersion lives at /engineering/, not at /.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/PathDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting with a mismatched path must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting a version from a policy that does not exist must fail with NoSuchEntity.
pub async fn test_delete_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchPolicyEver".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a version of a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting a version that does not exist on an existing policy must fail with NoSuchEntity.
pub async fn test_delete_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a nonexistent version must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting with an unparseable ARN must fail with ValidationError.
pub async fn test_delete_policy_version_invalid_arn(pool: &sqlx::PgPool) {
    // Each case exercises a distinct rejection in parse_policy_arn.
    let cases: &[(&str, &str)] = &[
        // Unparseable string (passes the Smithy length check but not the ARN parser).
        ("not-an-arn-but-long-enough-to-pass", "unparseable ARN"),
        // Wrong service (s3 instead of iam).
        ("arn:test-partition:s3:::policy/SomePolicy", "wrong service"),
        // Region must be empty for IAM ARNs.
        ("arn:test-partition:iam:us-east-1:123456789012:policy/SomePolicy", "non-empty region"),
        // Resource doesn't start with "policy/".
        ("arn:test-partition:iam::123456789012:user/SomeUser", "non-policy resource"),
    ];

    for (arn, label) in cases {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let result = DeletePolicyVersionRequest::builder()
            .policy_arn(arn.to_string())
            .version_id("v1".to_string())
            .build()
            .expect("Failed to build DeletePolicyVersionRequest")
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

/// Deleting a version on an AWS-owned managed policy must accept an "aws" account in the ARN
/// (mapped to "000000000000").
pub async fn test_delete_policy_version_aws_account(pool: &sqlx::PgPool) {
    // CreatePolicy's Smithy regex requires a 12-digit account id, so create the AWS-owned policy
    // by addressing it with the literal "000000000000" account that bootstrap inserts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("AwsOwnedDelVersion".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("000000000000".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create AWS-owned policy");
    let doc_v2 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::000000000000:policy/AwsOwnedDelVersion".to_string())
        .policy_document(doc_v2.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2 of AwsOwnedDelVersion");
    tx.commit().await.expect("Failed to commit transaction");

    // Delete v2 using "aws" in the ARN.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v2 of AwsOwnedDelVersion via 'aws' account");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same version should fail with NoSuchEntity (proves it really was deleted
    // from the "000000000000" account row).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting v2 should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");

    // Also verify that the same ARN using "000000000000" addresses the same policy.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::000000000000:policy/AwsOwnedDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("v1 is the default and cannot be deleted");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

// -- SetDefaultPolicyVersion tests --------------------------------------------

/// VersionedPolicy currently has v3 as default. Set it to v4, verify, then back to v3.
pub async fn test_set_default_policy_version_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/VersionedPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v4".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set default to v4");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.policy.unwrap().default_version_id.as_deref(), Some("v4"));

    // Restore v3 as default so later list tests see a stable state.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to restore default to v3");
    tx.commit().await.expect("Failed to commit transaction");
}

pub async fn test_set_default_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default to nonexistent version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_set_default_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchSetDefaultPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_set_default_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default with mismatched path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// AwsOwnedDelVersion has only v1 in account 000000000000. Setting v1 as default through 'aws'
/// ARN should succeed (idempotent).
pub async fn test_set_default_policy_version_aws_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set default via 'aws' ARN");
    tx.commit().await.expect("Failed to commit transaction");
}

// -- TagPolicy / UntagPolicy tests --------------------------------------------

pub async fn test_tag_policy_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tags(vec![
            Tag::builder().key("Env".to_string()).value("Prod".to_string()).build().expect("Tag build failed"),
            Tag::builder().key("Owner".to_string()).value("Platform".to_string()).build().expect("Tag build failed"),
        ])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag TestPolicy");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy after tagging");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    let tag_pairs: Vec<(String, String)> = policy.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
    assert!(tag_pairs.contains(&("Env".to_string(), "Prod".to_string())));
    assert!(tag_pairs.contains(&("Owner".to_string(), "Platform".to_string())));
}

pub async fn test_tag_policy_upsert(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";

    // Update Env=Prod to Env=Staging.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tags(vec![
            Tag::builder().key("Env".to_string()).value("Staging".to_string()).build().expect("Tag build failed"),
        ])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let env_value = resp
        .policy
        .unwrap()
        .tags
        .iter()
        .find(|t| t.key == "Env")
        .map(|t| t.value.clone())
        .expect("Env tag should exist");
    assert_eq!(env_value, "Staging");
}

pub async fn test_tag_policy_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = TagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .tags(vec![])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Tagging with empty list should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

pub async fn test_tag_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = TagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchTagPolicy".to_string())
        .tags(vec![Tag::builder().key("X".to_string()).value("Y".to_string()).build().expect("Tag build failed")])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Tagging missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_untag_policy_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tag_keys(vec!["Owner".to_string()])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag Owner");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let keys: Vec<String> = resp.policy.unwrap().tags.iter().map(|t| t.key.clone()).collect();
    assert!(!keys.contains(&"Owner".to_string()), "Owner tag should have been removed");
    assert!(keys.contains(&"Env".to_string()), "Env tag should still be present");
}

pub async fn test_untag_policy_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .tag_keys(vec![])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Untagging with empty list should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

pub async fn test_untag_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchUntagPolicy".to_string())
        .tag_keys(vec!["X".to_string()])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Untagging missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- update_date denormalization tests ----------------------------------------

/// Exercise update_date semantics across CreatePolicy, CreatePolicyVersion, and
/// DeletePolicyVersion (both for non-latest and latest versions). update_date is supposed to
/// track the most recent version's created_at.
pub async fn test_policy_update_date_lifecycle(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/UpdateDatePolicy";

    // Create the policy. Initially the only version is v1, so update_date == v1.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let create = CreatePolicyInternalRequest::builder()
        .policy_name("UpdateDatePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create UpdateDatePolicy");
    tx.commit().await.expect("Failed to commit transaction");

    let initial_update_date = get_policy_update_date(pool, arn).await;
    // CreatePolicy doesn't return update_date directly, but it must equal the policy's create_date,
    // which is the version's created_at (they all come from the same CURRENT_TIMESTAMP in-tx).
    assert_eq!(initial_update_date, create.policy.as_ref().unwrap().create_date.unwrap());

    // Create v2 (non-default). update_date should advance to v2.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let v2 = CreatePolicyVersionRequest::builder()
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
        .expect("Failed to create v2");
    tx.commit().await.expect("Failed to commit transaction");

    let after_v2 = get_policy_update_date(pool, arn).await;
    assert_eq!(after_v2, v2.policy_version.as_ref().unwrap().create_date.unwrap());
    assert!(after_v2 > initial_update_date, "update_date should advance after CreatePolicyVersion");

    // Create v3 (non-default). update_date should advance to v3.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let v3 = CreatePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}"#
                .to_string(),
        )
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v3");
    tx.commit().await.expect("Failed to commit transaction");
    let v3_create_date = v3.policy_version.as_ref().unwrap().create_date.unwrap();
    assert_eq!(get_policy_update_date(pool, arn).await, v3_create_date);

    // Delete v2 (non-latest). update_date should be unchanged (still v3.create_date).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v2");
    tx.commit().await.expect("Failed to commit transaction");
    assert_eq!(
        get_policy_update_date(pool, arn).await,
        v3_create_date,
        "Deleting a non-latest version must not change update_date"
    );

    // Delete v3 (the latest). update_date should be recomputed to v1.create_date (only remaining).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v3");
    tx.commit().await.expect("Failed to commit transaction");
    assert_eq!(
        get_policy_update_date(pool, arn).await,
        initial_update_date,
        "Deleting the latest version must roll update_date back to the now-latest version's create_date"
    );
}

/// Fetch the `update_date` for a managed policy via GetPolicy.
async fn get_policy_update_date(pool: &sqlx::PgPool, arn: &str) -> chrono::DateTime<chrono::Utc> {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get policy");
    tx.rollback().await.expect("Failed to rollback transaction");
    resp.policy.unwrap().update_date.expect("Policy should have update_date")
}
