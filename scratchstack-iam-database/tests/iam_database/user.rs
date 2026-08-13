//! User test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateAccessKeyInternalRequest, CreateUserInternalRequest, DeleteAccessKeyInternalRequest,
            DeleteUserInternalRequest, DeleteUserPermissionsBoundaryInternalRequest, DeleteUserPolicyInternalRequest,
            GetUserInternalRequest, GetUserPolicyInternalRequest, ListAccessKeysInternalRequest,
            ListUserPoliciesInternalRequest, ListUserTagsInternalRequest, PutUserPermissionsBoundaryInternalRequest,
            PutUserPolicyInternalRequest, TagUserInternalRequest, UntagUserInternalRequest,
            UpdateAccessKeyInternalRequest,
        },
        types::{StatusType, Tag},
    },
};

/// Create a user with only a name and account — all other fields take defaults.
pub async fn test_create_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "alice");
    assert_eq!(user.path, "/");
    assert!(user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert!(user.arn.ends_with(":user/alice"), "ARN must end with :user/alice, got {}", user.arn);
    assert!(user.permissions_boundary.is_none());
    assert!(user.tags.is_empty());
}

/// Create a user at a non-default path.
pub async fn test_create_user_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("bob")
        .path("/engineering/")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with path");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "bob");
    assert_eq!(user.path, "/engineering/");
    assert!(user.arn.ends_with(":user/engineering/bob"), "ARN must end with :user/engineering/bob, got {}", user.arn);
}

/// Create a user with tags attached.
pub async fn test_create_user_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("carol")
        .account_id("210987654321")
        .set_tags(vec![
            Tag::builder().key("Environment").value("Production").build().expect("Failed to build Environment tag"),
            Tag::builder().key("Team").value("Engineering").build().expect("Failed to build Team tag"),
        ])
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "carol");
    assert_eq!(user.path, "/");
    assert_eq!(user.tags.len(), 2);
    assert_eq!(user.tags[0].key, "Environment");
    assert_eq!(user.tags[0].value, "Production");
    assert_eq!(user.tags[1].key, "Team");
    assert_eq!(user.tags[1].value, "Engineering");
}

/// Create a user with an existing managed policy as the permissions boundary.
pub async fn test_create_user_with_permissions_boundary(pool: &sqlx::PgPool) {
    // The test data has "Example-Managed-Policy-1" in account 123456789012 at path "/".

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("dave")
        .account_id("123456789012")
        .permissions_boundary("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "dave");
    let pb = user.permissions_boundary.expect("User should have a permissions boundary");
    let pb_arn = pb.permissions_boundary_arn.expect("Permissions boundary should include an ARN");
    assert_eq!(pb_arn, "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1");
}

/// Attempting to create a user whose (lowercased) name already exists in the account must fail.
pub async fn test_create_user_duplicate_name(pool: &sqlx::PgPool) {
    // "alice" was committed by test_create_user_simple; re-inserting it must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate user name must fail");
}

/// Building a request with an invalid user name must fail before touching the database.
pub fn test_create_user_invalid_name() {
    // Spaces and `!` are not in the allowed character set.
    let result = CreateUserInternalRequest::builder().user_name("bad name!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// Creating a user in an account that does not exist must fail with a FK violation.
pub async fn test_create_user_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("eve")
        .account_id("999999999999")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user in a nonexistent account must fail");
}

/// Specifying a permissions boundary that references a policy that does not exist must fail.
pub async fn test_create_user_nonexistent_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("frank")
        .account_id("123456789012")
        .permissions_boundary("arn:aws:iam::123456789012:policy/NonExistentPolicy")
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user with a nonexistent permissions boundary must fail");
}

/// Tag an existing user and verify the tags appear in ListUserTags.
pub async fn test_tag_user(pool: &sqlx::PgPool) {
    // alice was created in account 123456789012 by test_create_user_simple.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tags(vec![
            Tag::builder().key("Dept").value("Engineering").build().expect("Failed to build tag"),
            Tag::builder().key("CostCenter").value("1234").build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify tags via ListUserTags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on alice");
    // Tags are returned sorted by key_lower.
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Engineering");
}

/// Tagging with an existing key should update the value (upsert).
pub async fn test_tag_user_upsert(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tags(vec![Tag::builder().key("Dept").value("Finance").build().expect("Failed to build tag")])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag on user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the value was updated and the other tag is still present.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags after upsert");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on alice after upsert");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Finance");
}

/// Tagging a nonexistent user must fail with NoSuchEntityException.
pub async fn test_tag_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagUserInternalRequest::builder()
        .user_name("nonexistent")
        .account_id("123456789012")
        .set_tags(vec![Tag::builder().key("Key").value("Value").build().expect("Failed to build tag")])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging a nonexistent user must fail");
}

/// Tagging with an empty tag list must fail.
pub async fn test_tag_user_empty_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tags(vec![])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging with an empty tag list must fail");
}

/// Untag an existing user and verify the tag is removed.
pub async fn test_untag_user(pool: &sqlx::PgPool) {
    // alice currently has CostCenter and Dept tags from previous tests.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tag_keys(vec!["Dept".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify only CostCenter remains.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags after untag");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 1, "Expected 1 tag on alice after removing Dept");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
}

/// Untagging a key that does not exist on the user should succeed silently.
pub async fn test_untag_user_nonexistent_key(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tag_keys(vec!["NoSuchTag".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Untagging a nonexistent key should succeed silently");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Untagging with an empty tag key list must fail.
pub async fn test_untag_user_empty_keys(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .set_tag_keys(vec![])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging with an empty tag key list must fail");
}

/// Untagging a nonexistent user must fail with NoSuchEntityException.
pub async fn test_untag_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagUserInternalRequest::builder()
        .user_name("nonexistent")
        .account_id("123456789012")
        .set_tag_keys(vec!["Key".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging a nonexistent user must fail");
}

/// Get a user that exists with no tags (bob was created at /engineering/ with no tags).
pub async fn test_get_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.user.user_name, "bob");
    assert_eq!(resp.user.path, "/engineering/");
    assert!(resp.user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert!(
        resp.user.arn.ends_with(":user/engineering/bob"),
        "ARN must end with :user/engineering/bob, got {}",
        resp.user.arn
    );
    assert!(resp.user.permissions_boundary.is_none());
    assert!(resp.user.tags.is_empty());
}

/// Get a user that has tags (alice has CostCenter tag after untag tests).
pub async fn test_get_user_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.user.user_name, "alice");
    assert_eq!(resp.user.path, "/");
    assert!(resp.user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert_eq!(resp.user.tags.len(), 1, "Expected 1 tag on alice");
    assert_eq!(resp.user.tags[0].key, "CostCenter");
    assert_eq!(resp.user.tags[0].value, "1234");
}

/// Getting a nonexistent user must fail.
pub async fn test_get_user_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetUserInternalRequest::builder()
        .user_name("nonexistent")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a nonexistent user must fail");
}

/// Getting a user without providing a user name must fail.
pub async fn test_get_user_no_user_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetUserInternalRequest::builder()
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a user without a user name must fail");
}

/// Clear a permissions boundary that is set on a user. The user exists and has a PB; afterwards
/// the column must be NULL.
pub async fn test_delete_user_permissions_boundary_simple(pool: &sqlx::PgPool) {
    // Set up: create a user with no PB, then attach a PB directly via SQL (the create_user API
    // verifies the PB exists by name, but we just need any seeded managed_policy_id here).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("DeleteMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMePbUser");
    let user_id: String =
        sqlx::query_scalar("SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2")
            .bind("123456789012")
            .bind("deletemepbuser")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMePbUser user_id");
    let managed_policy_id: String = sqlx::query_scalar(
        "SELECT managed_policy_id FROM iam.managed_policies WHERE account_id = $1 AND managed_policy_name_lower = $2",
    )
    .bind("123456789012")
    .bind("example-managed-policy-1")
    .fetch_one(tx.as_mut())
    .await
    .expect("Failed to fetch Example-Managed-Policy-1 managed_policy_id");
    sqlx::query("UPDATE iam.users SET permissions_boundary_managed_policy_id = $1 WHERE user_id = $2")
        .bind(managed_policy_id)
        .bind(&user_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to set DeleteMePbUser permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteUserPermissionsBoundaryInternalRequest::builder()
        .user_name("DeleteMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMePbUser permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let pb: Option<String> =
        sqlx::query_scalar("SELECT permissions_boundary_managed_policy_id FROM iam.users WHERE user_id = $1")
            .bind(&user_id)
            .fetch_one(pool)
            .await
            .expect("Failed to fetch DeleteMePbUser permissions boundary after delete");
    assert!(pb.is_none(), "permissions_boundary_managed_policy_id must be NULL after delete");

    // Clean up.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteUserInternalRequest::builder()
        .user_name("DeleteMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMePbUser");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteUserPermissionsBoundary on a user that has no PB must succeed (idempotent).
pub async fn test_delete_user_permissions_boundary_no_boundary(pool: &sqlx::PgPool) {
    // bob was committed earlier in test_create_user_with_path with no PB.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteUserPermissionsBoundaryInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("DeleteUserPermissionsBoundary on a user with no PB must succeed");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Calling DeleteUserPermissionsBoundary on a nonexistent user must fail with NoSuchEntity.
pub async fn test_delete_user_permissions_boundary_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteUserPermissionsBoundaryInternalRequest::builder()
        .user_name("nosuchpbuser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Clearing PB on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteUserPermissionsBoundary request with an invalid user name must fail before
/// touching the database.
pub fn test_delete_user_permissions_boundary_invalid_name() {
    let result = DeleteUserPermissionsBoundaryInternalRequest::builder()
        .user_name("bad name!")
        .account_id("123456789012")
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// PutUserPermissionsBoundary sets the boundary, and a second call replaces it (here using the
/// same policy, exercising the UPDATE path on a row that already has the column populated).
pub async fn test_put_user_permissions_boundary_simple(pool: &sqlx::PgPool) {
    let pb_arn = "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create PutMePbUser");
    PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set PutMePbUser permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get PutMePbUser");
    tx.rollback().await.expect("Failed to rollback transaction");
    let pb = resp.user.permissions_boundary.expect("User should have a permissions boundary");
    assert_eq!(pb.permissions_boundary_arn.as_deref(), Some(pb_arn));

    // Calling Put again on a user that already has a PB must succeed.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Re-putting the same permissions boundary on PutMePbUser must succeed");
    tx.commit().await.expect("Failed to commit transaction");

    // Clean up.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteUserPermissionsBoundaryInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to clear PutMePbUser PB");
    DeleteUserInternalRequest::builder()
        .user_name("PutMePbUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete PutMePbUser");
    tx.commit().await.expect("Failed to commit transaction");
}

/// PutUserPermissionsBoundary on a nonexistent user must fail with NoSuchEntity.
pub async fn test_put_user_permissions_boundary_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("nosuchputpbuser")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutUserPermissionsBoundary on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// PutUserPermissionsBoundary with a PB ARN that refers to a nonexistent policy must fail with
/// NoSuchEntity (raised by the permissions-boundary lookup helper).
pub async fn test_put_user_permissions_boundary_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/NoSuchPolicy")
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutUserPermissionsBoundary with a nonexistent PB policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// PutUserPermissionsBoundary with a malformed PB ARN must fail with ValidationError.
pub async fn test_put_user_permissions_boundary_invalid_arn(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .permissions_boundary("not-an-arn-but-long-enough-to-pass")
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutUserPermissionsBoundary with an invalid ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// Building a PutUserPermissionsBoundary request with an invalid user name must fail before
/// touching the database.
pub fn test_put_user_permissions_boundary_invalid_name() {
    let result = PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("bad name!")
        .account_id("123456789012")
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

const INLINE_POLICY_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
const INLINE_POLICY_EC2: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
const INLINE_POLICY_UNKNOWN_AWS_PRINCIPAL: &str = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

/// PutUserPolicy attaches an inline policy to an existing user.
pub async fn test_put_user_policy_simple(pool: &sqlx::PgPool) {
    // bob was committed earlier; reuse him.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .policy_document(INLINE_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to put inline policy on bob");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the row landed via raw SQL since there's no GetUserPolicy op yet.
    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("bob")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch bob's inline policy");
    assert_eq!(doc, INLINE_POLICY_S3);
}

/// PutUserPolicy with the same policy name replaces the document on the same row.
pub async fn test_put_user_policy_replaces(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .policy_document(INLINE_POLICY_EC2.to_string())
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to replace inline policy on bob");
    tx.commit().await.expect("Failed to commit transaction");

    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("bob")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch bob's inline policy after replace");
    assert_eq!(doc, INLINE_POLICY_EC2);

    // The total row count for bob's inline policies must still be exactly 1.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("bob")
    .fetch_one(pool)
    .await
    .expect("Failed to count bob's inline policies");
    assert_eq!(count, 1, "Replacing must not create a new row");
}

/// A second policy name on the same user creates a new row, leaving the first one intact.
pub async fn test_put_user_policy_additional_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineCompute")
        .policy_document(INLINE_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to put second inline policy on bob");
    tx.commit().await.expect("Failed to commit transaction");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("bob")
    .fetch_one(pool)
    .await
    .expect("Failed to count bob's inline policies");
    assert_eq!(count, 2, "A new policy name must create a new row");
}

/// A syntactically valid principal that references a non-existent user/account is still
/// accepted (the entity-existence check is intentionally not performed).
pub async fn test_put_user_policy_invalid_principal_accepted(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineWithMissingPrincipal")
        .policy_document(INLINE_POLICY_UNKNOWN_AWS_PRINCIPAL.to_string())
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Policies referring to non-existent principals must still be accepted");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A non-JSON / unparseable policy document must fail with MalformedPolicyDocument.
pub async fn test_put_user_policy_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineBroken")
        .policy_document("{ not valid aspen json }")
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutUserPolicy with malformed JSON must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(
        matches!(err, IamError::MalformedPolicyDocumentException(_)),
        "Expected MalformedPolicyDocumentException, got: {err:?}"
    );
}

/// PutUserPolicy on a nonexistent user must fail with NoSuchEntity.
pub async fn test_put_user_policy_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutUserPolicyInternalRequest::builder()
        .user_name("nosuchputpolicyuser")
        .account_id("123456789012")
        .policy_name("AnyName")
        .policy_document(INLINE_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutUserPolicy on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a PutUserPolicy request with an invalid user name must fail before touching the
/// database.
pub fn test_put_user_policy_invalid_name() {
    let result = PutUserPolicyInternalRequest::builder()
        .user_name("bad name!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .policy_document(INLINE_POLICY_S3.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// GetUserPolicy returns the policy document set via PutUserPolicy.
pub async fn test_get_user_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineRead")
        .build()
        .expect("Failed to build GetUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get inline policy on bob");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.user_name, "bob");
    assert_eq!(resp.policy_name, "InlineRead");
    assert_eq!(resp.policy_document, INLINE_POLICY_EC2);
}

/// GetUserPolicy returns the document under the original case for the policy name even when
/// looked up using a different case.
pub async fn test_get_user_policy_case_insensitive_lookup(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserPolicyInternalRequest::builder()
        .user_name("BOB")
        .account_id("123456789012")
        .policy_name("INLINEREAD")
        .build()
        .expect("Failed to build GetUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get inline policy via case-insensitive lookup");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.user_name, "bob");
    assert_eq!(resp.policy_name, "InlineRead");
}

/// GetUserPolicy on a nonexistent inline policy must fail with NoSuchEntity.
pub async fn test_get_user_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("NotAttached")
        .build()
        .expect("Failed to build GetUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("GetUserPolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// GetUserPolicy on a nonexistent user must fail with NoSuchEntity.
pub async fn test_get_user_policy_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetUserPolicyInternalRequest::builder()
        .user_name("nosuchgetpolicyuser")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build()
        .expect("Failed to build GetUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("GetUserPolicy on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a GetUserPolicy request with an invalid user name must fail before touching the
/// database.
pub fn test_get_user_policy_invalid_name() {
    let result = GetUserPolicyInternalRequest::builder()
        .user_name("bad name!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// ListUserPolicies returns the policy names attached to a user in sorted (case-insensitive)
/// order.
pub async fn test_list_user_policies_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserPoliciesInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on bob");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(
        resp.policy_names,
        vec!["InlineCompute".to_string(), "InlineRead".to_string(), "InlineWithMissingPrincipal".to_string()]
    );
    assert_eq!(resp.is_truncated, None);
    assert_eq!(resp.marker, None);
}

/// ListUserPolicies returns an empty list when the user has no inline policies attached.
pub async fn test_list_user_policies_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("ListPoliciesEmptyUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create ListPoliciesEmptyUser");
    let resp = ListUserPoliciesInternalRequest::builder()
        .user_name("ListPoliciesEmptyUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on empty user");
    assert!(resp.policy_names.is_empty(), "Expected no inline policies, got: {:?}", resp.policy_names);
    assert_eq!(resp.is_truncated, None);

    DeleteUserInternalRequest::builder()
        .user_name("ListPoliciesEmptyUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete ListPoliciesEmptyUser");
    tx.commit().await.expect("Failed to commit transaction");
}

/// ListUserPolicies honors `max_items` and emits a usable marker for the next page.
pub async fn test_list_user_policies_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListUserPoliciesInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .max_items(2)
        .build()
        .expect("Failed to build ListUserPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on bob (page 1)");
    assert_eq!(page1.policy_names, vec!["InlineCompute".to_string(), "InlineRead".to_string()]);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.clone().expect("Expected a pagination marker");

    let page2 = ListUserPoliciesInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .max_items(2)
        .marker(marker)
        .build()
        .expect("Failed to build ListUserPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on bob (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.policy_names, vec!["InlineWithMissingPrincipal".to_string()]);
    assert_eq!(page2.is_truncated, None);
    assert_eq!(page2.marker, None);
}

/// ListUserPolicies on a nonexistent user must fail with NoSuchEntity.
pub async fn test_list_user_policies_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListUserPoliciesInternalRequest::builder()
        .user_name("nosuchlistpoliciesuser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListUserPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("ListUserPolicies on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListUserPolicies request with an invalid user name must fail before touching the
/// database.
pub fn test_list_user_policies_invalid_name() {
    let result = ListUserPoliciesInternalRequest::builder().user_name("bad name!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// DeleteUserPolicy removes an inline policy previously attached via PutUserPolicy.
pub async fn test_delete_user_policy_simple(pool: &sqlx::PgPool) {
    // The "InlineWithMissingPrincipal" inline policy was added in test_put_user_policy_invalid_principal_accepted.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("InlineWithMissingPrincipal")
        .build()
        .expect("Failed to build DeleteUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete inline policy on bob");
    tx.commit().await.expect("Failed to commit transaction");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("bob")
    .bind("inlinewithmissingprincipal")
    .fetch_one(pool)
    .await
    .expect("Failed to count bob's inline policy after delete");
    assert_eq!(count, 0, "Deleted inline policy must be gone");

    // bob's other inline policies ("InlineRead", "InlineCompute") must still be present.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.user_inline_policies \
         WHERE user_id = (SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("bob")
    .fetch_one(pool)
    .await
    .expect("Failed to count remaining bob inline policies");
    assert_eq!(remaining, 2, "Only the targeted inline policy must be removed");
}

/// DeleteUserPolicy with a policy name that is not attached must fail with NoSuchEntity.
pub async fn test_delete_user_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteUserPolicyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .policy_name("NotAttached")
        .build()
        .expect("Failed to build DeleteUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteUserPolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// DeleteUserPolicy on a nonexistent user must fail with NoSuchEntity.
pub async fn test_delete_user_policy_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteUserPolicyInternalRequest::builder()
        .user_name("nosuchdeletepolicyuser")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build()
        .expect("Failed to build DeleteUserPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteUserPolicy on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteUserPolicy request with an invalid user name must fail before touching the
/// database.
pub fn test_delete_user_policy_invalid_name() {
    let result = DeleteUserPolicyInternalRequest::builder()
        .user_name("bad name!")
        .account_id("123456789012")
        .policy_name("AnyName")
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// A user with an attached managed policy (and nothing else) must not be deletable.
pub async fn test_delete_user_attached_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("DeleteMeAttachedUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeAttachedUser");
    let user_id: String =
        sqlx::query_scalar("SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeattacheduser")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeAttachedUser user_id");
    // AAAABBBBCCCCDDDD is the seeded Example-Managed-Policy-1.
    sqlx::query("INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES ($1, $2)")
        .bind(&user_id)
        .bind("AAAABBBBCCCCDDDD")
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach Example-Managed-Policy-1 to DeleteMeAttachedUser");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteUserInternalRequest::builder()
        .user_name("DeleteMeAttachedUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a user with an attached managed policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: detach the policy, confirm DeleteUser now succeeds.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.user_attached_policies WHERE user_id = $1")
        .bind(&user_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to detach managed policy");
    DeleteUserInternalRequest::builder()
        .user_name("DeleteMeAttachedUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeAttachedUser after detaching policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A user with inline policies must not be deletable.
pub async fn test_delete_user_inline_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("DeleteMeInlineUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeInlineUser");
    let user_id: String =
        sqlx::query_scalar("SELECT user_id FROM iam.users WHERE account_id = $1 AND user_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeinlineuser")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeInlineUser user_id");
    sqlx::query(
        "INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES ($1, $2, $3, $4)",
    )
    .bind(&user_id)
    .bind("inline-blocker")
    .bind("inline-blocker")
    .bind(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#)
    .execute(tx.as_mut())
    .await
    .expect("Failed to insert inline policy for DeleteMeInlineUser");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteUserInternalRequest::builder()
        .user_name("DeleteMeInlineUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a user with an inline policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: remove the inline policy and confirm DeleteUser then succeeds.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.user_inline_policies WHERE user_id = $1")
        .bind(&user_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to remove inline policy");
    DeleteUserInternalRequest::builder()
        .user_name("DeleteMeInlineUser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeInlineUser after removing inline policy");
    tx.commit().await.expect("Failed to commit transaction");
}

// -- Access key tests --------------------------------------------------------

/// CreateAccessKey for bob returns a new key whose id starts with "AKIA", whose secret is 40
/// characters long, and whose status is `Active`.
pub async fn test_create_access_key_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccessKeyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create access key for bob");
    tx.commit().await.expect("Failed to commit transaction");

    let access_key = resp.access_key;
    assert_eq!(access_key.user_name, "bob");
    assert!(
        access_key.access_key_id.starts_with("AKIA"),
        "Access key id must start with AKIA, got {}",
        access_key.access_key_id
    );
    assert_eq!(access_key.access_key_id.len(), 20, "Access key id must be 20 chars total");
    assert_eq!(access_key.secret_access_key.len(), 40, "Secret access key must be 40 chars long");
    assert!(matches!(access_key.status, StatusType::Active), "New key must be Active");
    assert!(access_key.create_date.is_some(), "create_date must be populated");
}

/// CreateAccessKey can be called multiple times for the same user; AWS allows up to two active
/// keys, which we don't enforce — but two should certainly succeed.
pub async fn test_create_access_key_second(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccessKeyInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create second access key for bob");
    tx.commit().await.expect("Failed to commit transaction");
    assert!(resp.access_key.access_key_id.starts_with("AKIA"));
}

/// CreateAccessKey without a user name must fail with ValidationError, since the implementation
/// has no caller identity to fall back to.
pub async fn test_create_access_key_no_user_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = CreateAccessKeyInternalRequest::builder()
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("CreateAccessKey without UserName must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// CreateAccessKey on a nonexistent user must fail with NoSuchEntity.
pub async fn test_create_access_key_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = CreateAccessKeyInternalRequest::builder()
        .user_name("nosuchaccesskeyuser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("CreateAccessKey on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a CreateAccessKey request with an invalid user name must fail before touching the
/// database.
pub fn test_create_access_key_invalid_user_name() {
    let result = CreateAccessKeyInternalRequest::builder().user_name("bad name!").account_id("123456789012").build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// ListAccessKeys returns the two keys that the previous CreateAccessKey tests added for bob.
pub async fn test_list_access_keys_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for bob");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.access_key_metadata.len(), 2, "Expected 2 access keys for bob");
    for meta in &resp.access_key_metadata {
        assert_eq!(meta.user_name.as_deref(), Some("bob"));
        assert!(meta.access_key_id.as_deref().unwrap().starts_with("AKIA"));
        assert!(matches!(meta.status, Some(StatusType::Active)));
        assert!(meta.create_date.is_some());
    }
    assert_eq!(resp.is_truncated, None);
}

/// ListAccessKeys returns the seeded access key for Example-User-1.
pub async fn test_list_access_keys_seeded(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccessKeysInternalRequest::builder()
        .user_name("Example-User-1")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.access_key_metadata.len(), 1, "Expected 1 seeded access key");
    let meta = &resp.access_key_metadata[0];
    assert_eq!(meta.user_name.as_deref(), Some("Example-User-1"));
    assert_eq!(meta.access_key_id.as_deref(), Some("AKIAEXAMPLEACCESSKEYID123"));
    assert!(matches!(meta.status, Some(StatusType::Active)));
}

/// ListAccessKeys returns an empty list for a user who has none.
pub async fn test_list_access_keys_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccessKeysInternalRequest::builder()
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for alice");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.access_key_metadata.is_empty(), "Expected no access keys for alice");
}

/// ListAccessKeys honors `max_items` and returns a usable continuation marker.
pub async fn test_list_access_keys_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .max_items(1)
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for bob (page 1)");
    assert_eq!(page1.access_key_metadata.len(), 1);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.clone().expect("Expected a pagination marker");

    let page2 = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .max_items(1)
        .marker(marker)
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for bob (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.access_key_metadata.len(), 1);
    assert_eq!(page2.is_truncated, None);
    let id1 = page1.access_key_metadata[0].access_key_id.as_deref().unwrap();
    let id2 = page2.access_key_metadata[0].access_key_id.as_deref().unwrap();
    assert_ne!(id1, id2, "Each page must return a distinct access key");
}

/// ListAccessKeys without a user name must fail with ValidationError.
pub async fn test_list_access_keys_no_user_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAccessKeysInternalRequest::builder()
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("ListAccessKeys without UserName must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// ListAccessKeys on a nonexistent user must fail with NoSuchEntity.
pub async fn test_list_access_keys_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListAccessKeysInternalRequest::builder()
        .user_name("nosuchlistaccesskeyuser")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("ListAccessKeys on a nonexistent user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// UpdateAccessKey flips the seeded access key to Inactive and back to Active.
pub async fn test_update_access_key_status_roundtrip(pool: &sqlx::PgPool) {
    let access_key_id = "AKIAEXAMPLEACCESSKEYID123";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateAccessKeyInternalRequest::builder()
        .access_key_id(access_key_id.to_string())
        .status(StatusType::Inactive)
        .user_name("Example-User-1")
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to deactivate seeded access key");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccessKeysInternalRequest::builder()
        .user_name("Example-User-1")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(resp.access_key_metadata[0].status, Some(StatusType::Inactive)));

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateAccessKeyInternalRequest::builder()
        .access_key_id(access_key_id.to_string())
        .status(StatusType::Active)
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to reactivate seeded access key without user name");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccessKeysInternalRequest::builder()
        .user_name("Example-User-1")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list access keys for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(resp.access_key_metadata[0].status, Some(StatusType::Active)));
}

/// UpdateAccessKey rejects the `Expired` status with ValidationError.
pub async fn test_update_access_key_expired_status_rejected(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateAccessKeyInternalRequest::builder()
        .access_key_id("AKIAEXAMPLEACCESSKEYID123")
        .status(StatusType::Expired)
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateAccessKey with Expired status must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// UpdateAccessKey with a user name that doesn't own the key must fail with NoSuchEntity.
pub async fn test_update_access_key_mismatched_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateAccessKeyInternalRequest::builder()
        .access_key_id("AKIAEXAMPLEACCESSKEYID123")
        .status(StatusType::Inactive)
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateAccessKey with a user that doesn't own the key must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// UpdateAccessKey for a nonexistent key must fail with NoSuchEntity.
pub async fn test_update_access_key_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateAccessKeyInternalRequest::builder()
        .access_key_id("AKIANOSUCHKEYIDXXXX1")
        .status(StatusType::Inactive)
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateAccessKey on a nonexistent key must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// UpdateAccessKey with an id missing the `AKIA` prefix must fail with ValidationError.
pub async fn test_update_access_key_bad_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UpdateAccessKeyInternalRequest::builder()
        .access_key_id("ASIAEXAMPLEACCESSKEYID123")
        .status(StatusType::Inactive)
        .account_id("123456789012")
        .build()
        .expect("Failed to build UpdateAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("UpdateAccessKey for a non-AKIA prefix must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// DeleteAccessKey removes a key created by one of the earlier tests.
pub async fn test_delete_access_key_simple(pool: &sqlx::PgPool) {
    // Find one of bob's keys to delete.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list bob's access keys");
    let target_id = list.access_key_metadata[0].access_key_id.clone().expect("Expected an access key id");
    let initial_count = list.access_key_metadata.len();

    DeleteAccessKeyInternalRequest::builder()
        .access_key_id(target_id.clone())
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete bob's access key");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let after = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to re-list bob's access keys");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(after.access_key_metadata.len(), initial_count - 1, "One key should be gone");
    assert!(
        !after.access_key_metadata.iter().any(|m| m.access_key_id.as_deref() == Some(target_id.as_str())),
        "Deleted key must not appear in the list"
    );
}

/// DeleteAccessKey works without a user name; the user is inferred from the access key id.
pub async fn test_delete_access_key_without_user_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list = ListAccessKeysInternalRequest::builder()
        .user_name("bob")
        .account_id("123456789012")
        .build()
        .expect("Failed to build ListAccessKeysInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list bob's access keys");
    let target_id = list.access_key_metadata[0].access_key_id.clone().expect("Expected an access key id");

    DeleteAccessKeyInternalRequest::builder()
        .access_key_id(target_id.clone())
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete bob's access key without user name");
    tx.commit().await.expect("Failed to commit transaction");
}

/// DeleteAccessKey with a mismatched user name must fail with NoSuchEntity.
pub async fn test_delete_access_key_mismatched_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteAccessKeyInternalRequest::builder()
        .access_key_id("AKIAEXAMPLEACCESSKEYID123")
        .user_name("alice")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteAccessKey with a mismatched user must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// DeleteAccessKey on a nonexistent key must fail with NoSuchEntity.
pub async fn test_delete_access_key_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteAccessKeyInternalRequest::builder()
        .access_key_id("AKIANOSUCHKEYIDXXXX2")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteAccessKey on a nonexistent key must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// DeleteAccessKey with an id missing the `AKIA` prefix must fail with ValidationError.
pub async fn test_delete_access_key_bad_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteAccessKeyInternalRequest::builder()
        .access_key_id("ASIAEXAMPLEACCESSKEYID123")
        .account_id("123456789012")
        .build()
        .expect("Failed to build DeleteAccessKeyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteAccessKey for a non-AKIA prefix must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}
