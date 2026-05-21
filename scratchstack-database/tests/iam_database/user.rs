//! User test suite.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreateUserInternalRequest, DeleteUserInternalRequest, DeleteUserPermissionsBoundaryInternalRequest,
            GetUserInternalRequest, ListUserTagsInternalRequest, PutUserPermissionsBoundaryInternalRequest,
            PutUserPolicyInternalRequest, TagUserInternalRequest, UntagUserInternalRequest,
        },
        types::Tag,
    },
};

/// Create a user with only a name and account — all other fields take defaults.
pub async fn test_create_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("bob".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
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
        .user_name("carol".to_string())
        .account_id("210987654321".to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build Environment tag"),
            Tag::builder()
                .key("Team".to_string())
                .value("Engineering".to_string())
                .build()
                .expect("Failed to build Team tag"),
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
        .user_name("dave".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1".to_string()))
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
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
    let result = CreateUserInternalRequest::builder()
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// Creating a user in an account that does not exist must fail with a FK violation.
pub async fn test_create_user_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("eve".to_string())
        .account_id("999999999999".to_string())
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
        .user_name("frank".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/NonExistentPolicy".to_string()))
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
        .user_name("alice".to_string())
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
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify tags via ListUserTags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Dept".to_string()).value("Finance".to_string()).build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag on user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the value was updated and the other tag is still present.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("nonexistent".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Key".to_string()).value("Value".to_string()).build().expect("Failed to build tag"),
        ])
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![])
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Dept".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify only CostCenter remains.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["NoSuchTag".to_string()])
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
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec![])
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
        .user_name("nonexistent".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Key".to_string()])
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
        .user_name(Some("bob".to_string()))
        .account_id("123456789012".to_string())
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
        .user_name(Some("alice".to_string()))
        .account_id("123456789012".to_string())
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
        .user_name(Some("nonexistent".to_string()))
        .account_id("123456789012".to_string())
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
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMePbUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMePbUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMePbUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("nosuchpbuser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// PutUserPermissionsBoundary sets the boundary, and a second call replaces it (here using the
/// same policy, exercising the UPDATE path on a row that already has the column populated).
pub async fn test_put_user_permissions_boundary_simple(pool: &sqlx::PgPool) {
    let pb_arn = "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("PutMePbUser".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create PutMePbUser");
    PutUserPermissionsBoundaryInternalRequest::builder()
        .user_name("PutMePbUser".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(pb_arn.to_string())
        .build()
        .expect("Failed to build PutUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set PutMePbUser permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name(Some("PutMePbUser".to_string()))
        .account_id("123456789012".to_string())
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
        .user_name("PutMePbUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("PutMePbUser".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteUserPermissionsBoundaryInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to clear PutMePbUser PB");
    DeleteUserInternalRequest::builder()
        .user_name("PutMePbUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("nosuchputpbuser".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/NoSuchPolicy".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary("not-an-arn-but-long-enough-to-pass".to_string())
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
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineRead".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineRead".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineCompute".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineWithMissingPrincipal".to_string())
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
        .user_name("bob".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineBroken".to_string())
        .policy_document("{ not valid aspen json }".to_string())
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
        .user_name("nosuchputpolicyuser".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
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
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .policy_document(INLINE_POLICY_S3.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// A user with an attached managed policy (and nothing else) must not be deletable.
pub async fn test_delete_user_attached_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateUserInternalRequest::builder()
        .user_name("DeleteMeAttachedUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMeAttachedUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMeAttachedUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMeInlineUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMeInlineUser".to_string())
        .account_id("123456789012".to_string())
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
        .user_name("DeleteMeInlineUser".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeInlineUser after removing inline policy");
    tx.commit().await.expect("Failed to commit transaction");
}
