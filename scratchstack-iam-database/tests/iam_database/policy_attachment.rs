//! Policy attach/detach/list-attached test suite for users, groups, and roles.
use {
    super::common::VALID_POLICY_DOCUMENT,
    pretty_assertions::assert_eq,
    scratchstack_core::RequestId,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachGroupPolicyInternalRequest, AttachRolePolicyInternalRequest, AttachUserPolicyInternalRequest,
            CreatePolicyInternalRequest, CreateUserInternalRequest, DetachGroupPolicyInternalRequest,
            DetachRolePolicyInternalRequest, DetachUserPolicyInternalRequest, ListAttachedGroupPoliciesInternalRequest,
            ListAttachedRolePoliciesInternalRequest, ListAttachedUserPoliciesInternalRequest,
        },
    },
};

// -- AttachUserPolicyInternalRequest tests ------------------------------------

pub async fn test_attach_user_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to user");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_user_policy_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest");
    req.execute(&mut tx, RequestId::new()).await.expect("First attach must succeed");
    req.execute(&mut tx, RequestId::new()).await.expect("Second attach must succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_user_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a nonexistent policy must fail");
}

pub async fn test_attach_user_policy_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("nonexistent-user")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a policy to a nonexistent user must fail");
}

// -- AttachGroupPolicyInternalRequest tests -----------------------------------

pub async fn test_attach_group_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to group");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_group_policy_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest");
    req.execute(&mut tx, RequestId::new()).await.expect("First attach must succeed");
    req.execute(&mut tx, RequestId::new()).await.expect("Second attach must succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_group_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a nonexistent policy to a group must fail");
}

pub async fn test_attach_group_policy_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("NonexistentGroup")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a policy to a nonexistent group must fail");
}

// -- AttachRolePolicyInternalRequest tests ------------------------------------

pub async fn test_attach_role_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to role");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_role_policy_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest");
    req.execute(&mut tx, RequestId::new()).await.expect("First attach must succeed");
    req.execute(&mut tx, RequestId::new()).await.expect("Second attach must succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_attach_role_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a nonexistent policy to a role must fail");
}

pub async fn test_attach_role_policy_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("nonexistent-role")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Attaching a policy to a nonexistent role must fail");
}

// -- DetachUserPolicyInternalRequest tests ------------------------------------

pub async fn test_detach_user_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to user");
    DetachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to detach policy from user");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_detach_user_policy_not_attached(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching an unattached policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_user_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build DetachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_user_policy_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("nonexistent-user")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching from a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- DetachGroupPolicyInternalRequest tests -----------------------------------

pub async fn test_detach_group_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to group");
    DetachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to detach policy from group");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_detach_group_policy_not_attached(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    // Seed data has Example-Managed-Policy-1 attached to Example-Group-1, so detach it first
    // to set up the "not attached" state, then verify a second detach fails.
    DetachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to detach seed attachment");
    let err = DetachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching an unattached policy from group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_group_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching a nonexistent policy from group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_group_policy_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("NonexistentGroup")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching from a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- DetachRolePolicyInternalRequest tests ------------------------------------

pub async fn test_detach_role_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach policy to role");
    DetachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to detach policy from role");
    tx.rollback().await.expect("Failed to rollback transaction");
}

pub async fn test_detach_role_policy_not_attached(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    // Seed data has Example-Managed-Policy-1 attached to Example-Role-1, so detach it first
    // to set up the "not attached" state, then verify a second detach fails.
    DetachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to detach seed attachment");
    let err = DetachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching an unattached policy from role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_role_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::123456789012:policy/NonexistentPolicy")
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching a nonexistent policy from role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_detach_role_policy_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DetachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("nonexistent-role")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching from a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- cross-account attachment tests -------------------------------------------

/// Managed policies are not shared across accounts. Attaching one another account owns is reported
/// the way attaching one that does not exist is, whichever kind of entity is receiving it, and the
/// message names the policy rather than the entity -- the ARN is settled before anything looks the
/// entity up, so a caller cannot probe another account's policies through an entity of its own.
pub async fn test_attach_policy_cross_account_rejected(pool: &sqlx::PgPool) {
    // Owned by 123456789012; every attach below is made by 210987654321.
    const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let err = AttachUserPolicyInternalRequest::builder()
        .account_id("210987654321")
        .user_name("Example-User-2")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Attaching another account's policy to a user must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    // The group and role here do not exist in that account either; the policy is what the failure
    // names, which is what says the ARN was settled first.
    let err = AttachGroupPolicyInternalRequest::builder()
        .account_id("210987654321")
        .group_name("No-Such-Group")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Attaching another account's policy to a group must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    let err = AttachRolePolicyInternalRequest::builder()
        .account_id("210987654321")
        .role_name("No-Such-Role")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Attaching another account's policy to a role must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Detaching is confined the same way attaching is. The seed data carries a cross-account
/// attachment that predates the rule, so this also shows that state cannot be reached back into
/// through the API even where it exists.
pub async fn test_detach_policy_cross_account_rejected(pool: &sqlx::PgPool) {
    const FOREIGN_POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let err = DetachUserPolicyInternalRequest::builder()
        .account_id("210987654321")
        .user_name("Example-User-2")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build DetachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching another account's policy from a user must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    let err = DetachGroupPolicyInternalRequest::builder()
        .account_id("210987654321")
        .group_name("No-Such-Group")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build DetachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching another account's policy from a group must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    let err = DetachRolePolicyInternalRequest::builder()
        .account_id("210987654321")
        .role_name("No-Such-Role")
        .policy_arn(FOREIGN_POLICY_ARN)
        .build()
        .expect("Failed to build DetachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Detaching another account's policy from a role must fail");
    assert_cross_account_rejection(err, FOREIGN_POLICY_ARN);

    tx.rollback().await.expect("Failed to rollback transaction");
}

/// The one policy every account reaches is an AWS-managed one, and it can be named either through
/// the `aws` account alias IAM spells it with or through the numeric account it is stored under.
/// Both name the same policy, and every kind of entity accepts either spelling.
pub async fn test_attach_policy_aws_managed_either_spelling(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    CreatePolicyInternalRequest::builder()
        .account_id("000000000000")
        .policy_name("AwsManagedEitherSpelling")
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create AWS-managed policy");

    AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("Example-User-1")
        .policy_arn("arn:aws:iam::aws:policy/AwsManagedEitherSpelling")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Attaching an AWS-managed policy by its alias must succeed");

    AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .policy_arn("arn:aws:iam::000000000000:policy/AwsManagedEitherSpelling")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Attaching an AWS-managed policy by its numeric account must succeed");

    AttachRolePolicyInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .policy_arn("arn:aws:iam::000000000000:policy/AwsManagedEitherSpelling")
        .build()
        .expect("Failed to build AttachRolePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Attaching an AWS-managed policy by its numeric account must succeed");

    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Assert that `err` is the "no such policy" report a cross-account ARN earns, naming `policy_arn`.
fn assert_cross_account_rejection(err: IamError, policy_arn: &str) {
    let IamError::NoSuchEntityException(e) = err else {
        panic!("Expected NoSuchEntity, got: {err:?}");
    };
    assert_eq!(e.message.as_deref(), Some(format!("Policy {policy_arn} was not found.").as_str()));
}

// -- ListAttachedUserPoliciesInternalRequest tests ----------------------------

/// Seed data has Example-User-2 (account 210987654321) attached to Example-Managed-Policy-1.
pub async fn test_list_attached_user_policies_seed(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("210987654321")
        .user_name("Example-User-2")
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached user policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.attached_policies.len(), 1, "Expected exactly one attached policy");
    let policy = &resp.attached_policies[0];
    assert_eq!(policy.policy_name.as_deref(), Some("Example-Managed-Policy-1"));
    assert_eq!(
        policy.policy_arn.as_deref(),
        Some("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
    );
    assert!(!resp.is_truncated.unwrap_or(false), "Result should not be truncated");
}

/// alice was created earlier in the test sequence but has no attached policies.
pub async fn test_list_attached_user_policies_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .user_name("alice")
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached user policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.attached_policies.is_empty(), "Expected no attached policies, got: {:?}", resp.attached_policies);
}

pub async fn test_list_attached_user_policies_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .user_name("no-such-user")
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing attached policies for a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// A path_prefix that does not match the seed policy's path ("/") should filter it out.
pub async fn test_list_attached_user_policies_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("210987654321")
        .user_name("Example-User-2")
        .path_prefix("/nomatch/")
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached user policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.attached_policies.is_empty(), "Path-prefix filter should exclude the seed policy");
}

/// Attach two additional policies in the same transaction, then verify pagination with max_items=2.
pub async fn test_list_attached_user_policies_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    // Create three customer-managed policies and attach all three to attach-test-user-2.
    CreateUserInternalRequest::builder()
        .account_id("123456789012")
        .user_name("attach-test-user-2")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create attach-test-user-2");

    for name in ["Pagination-Policy-A", "Pagination-Policy-B", "Pagination-Policy-C"] {
        CreatePolicyInternalRequest::builder()
            .account_id("123456789012")
            .policy_name(name.to_string())
            .policy_document(VALID_POLICY_DOCUMENT.to_string())
            .build()
            .expect("Failed to build CreatePolicyInternalRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .unwrap_or_else(|e| panic!("Failed to create policy {name}: {e:?}"));
        AttachUserPolicyInternalRequest::builder()
            .account_id("123456789012")
            .user_name("attach-test-user-2")
            .policy_arn(format!("arn:aws:iam::123456789012:policy/{name}"))
            .build()
            .expect("Failed to build AttachUserPolicyInternalRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .unwrap_or_else(|e| panic!("Failed to attach policy {name}: {e:?}"));
    }

    // First page (max_items=2) should return exactly 2 policies and a continuation marker.
    let page1 = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .user_name("attach-test-user-2")
        .max_items(2)
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached user policies (page 1)");
    assert_eq!(page1.attached_policies.len(), 2, "Page 1 should contain 2 policies");
    assert_eq!(page1.is_truncated, Some(true), "Page 1 should be truncated");
    let marker = page1.marker.expect("Page 1 should provide a continuation marker");

    // Second page should return the remaining 1 policy and no marker.
    let page2 = ListAttachedUserPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .user_name("attach-test-user-2")
        .max_items(2)
        .marker(marker)
        .build()
        .expect("Failed to build ListAttachedUserPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached user policies (page 2)");
    assert_eq!(page2.attached_policies.len(), 1, "Page 2 should contain 1 policy");
    assert!(!page2.is_truncated.unwrap_or(false), "Page 2 should not be truncated");

    // Combined pages should hold all three policy names exactly once.
    let mut names: Vec<String> = page1
        .attached_policies
        .iter()
        .chain(page2.attached_policies.iter())
        .map(|p| p.policy_name.clone().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["Pagination-Policy-A", "Pagination-Policy-B", "Pagination-Policy-C"]);

    tx.rollback().await.expect("Failed to rollback transaction");
}

// -- ListAttachedGroupPoliciesInternalRequest tests ---------------------------

pub async fn test_list_attached_group_policies_seed(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAttachedGroupPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .group_name("Example-Group-1")
        .build()
        .expect("Failed to build ListAttachedGroupPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached group policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.attached_policies.len(), 1, "Expected exactly one attached policy");
    let policy = &resp.attached_policies[0];
    assert_eq!(policy.policy_name.as_deref(), Some("Example-Managed-Policy-1"));
    assert_eq!(
        policy.policy_arn.as_deref(),
        Some("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
    );
}

pub async fn test_list_attached_group_policies_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAttachedGroupPoliciesInternalRequest::builder()
        .account_id("123456789012")
        .group_name("NoSuchGroup")
        .build()
        .expect("Failed to build ListAttachedGroupPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing attached policies for a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- ListAttachedRolePoliciesInternalRequest tests ----------------------------

pub async fn test_list_attached_role_policies_seed(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAttachedRolePoliciesInternalRequest::builder()
        .account_id("123456789012")
        .role_name("Example-Role-1")
        .build()
        .expect("Failed to build ListAttachedRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list attached role policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.attached_policies.len(), 1, "Expected exactly one attached policy");
    let policy = &resp.attached_policies[0];
    assert_eq!(policy.policy_name.as_deref(), Some("Example-Managed-Policy-1"));
    assert_eq!(
        policy.policy_arn.as_deref(),
        Some("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
    );
}

pub async fn test_list_attached_role_policies_nonexistent_role(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAttachedRolePoliciesInternalRequest::builder()
        .account_id("123456789012")
        .role_name("no-such-role")
        .build()
        .expect("Failed to build ListAttachedRolePoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing attached policies for a nonexistent role must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}
