//! Group test suite, including group membership tests.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::operation::{
        AddUserToGroupInternalRequest, CreateGroupInternalRequest, DeleteGroupInternalRequest, GetGroupInternalRequest,
        ListGroupsForUserInternalRequest, ListGroupsInternalRequest, RemoveUserFromGroupInternalRequest,
        UpdateGroupInternalRequest,
    },
};

/// Create a group with only a name and account — all other fields take defaults.
pub async fn test_create_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Create a group at a non-default path.
pub async fn test_create_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with path");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Attempting to create a group whose (lowercased) name already exists in the account must fail.
pub async fn test_create_group_duplicate_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate group name must fail");
}

/// Creating a group in an account that does not exist must fail.
pub async fn test_create_group_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("TestGroup".to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a group in a nonexistent account must fail");
}

/// Create a group with a 128-character name (the maximum allowed by AWS IAM).
pub async fn test_create_group_max_length_name(pool: &sqlx::PgPool) {
    // 128 characters: valid characters are [\w+=,.@-]
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, long_name);
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");

    // Verify we can retrieve the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group with 128-character name");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, long_name);
}

/// Get a group that exists with default path.
pub async fn test_get_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Get a group at a non-default path.
pub async fn test_get_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Getting a nonexistent group must fail.
pub async fn test_get_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a nonexistent group must fail");
}

/// List groups in an account.
pub async fn test_list_groups(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.groups.len() >= 2, "Expected at least 2 groups, got {}", resp.groups.len());
    // Groups are sorted by name (lowercased).
    let names: Vec<&str> = resp.groups.iter().map(|g| g.group_name.as_str()).collect();
    assert!(names.contains(&"Admins"), "Expected Admins in group list");
    assert!(names.contains(&"Developers"), "Expected Developers in group list");
}

/// List groups with a path prefix filter.
pub async fn test_list_groups_with_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("/engineering/".to_string()))
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups with path prefix");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected exactly 1 group under /engineering/");
    assert_eq!(resp.groups[0].group_name, "Developers");
}

/// Rename a group.
pub async fn test_update_group_rename(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .new_group_name(Some("Administrators".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to rename group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the rename took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get renamed group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Administrators");
}

/// Change the path of a group.
pub async fn test_update_group_change_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .new_path(Some("/admin/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update group path");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the path change took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group after path change");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.path, "/admin/");
}

/// Updating a nonexistent group must fail.
pub async fn test_update_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UpdateGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .new_group_name(Some("NewName".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Updating a nonexistent group must fail");
}

/// Delete the group with the maximum-length (128-character) name.
pub async fn test_delete_group_max_length_name(pool: &sqlx::PgPool) {
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name(long_name)
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Delete a group that exists.
pub async fn test_delete_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the group is gone.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a deleted group must fail");
}

/// Deleting a nonexistent group must fail.
pub async fn test_delete_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = DeleteGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Deleting a nonexistent group must fail");
}

// -- Group membership tests --------------------------------------------------

/// Add a user to a group. Uses alice (account 123456789012) and Administrators (renamed earlier).
pub async fn test_add_user_to_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to add user to group");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Adding the same user to the same group again should succeed (idempotent).
pub async fn test_add_user_to_group_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Adding user to group again should succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Adding a user to a nonexistent group must fail.
pub async fn test_add_user_to_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding user to nonexistent group must fail");
}

/// Adding a nonexistent user to a group must fail.
pub async fn test_add_user_to_group_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding nonexistent user to group must fail");
}

/// List groups for a user who is a member of at least one group.
pub async fn test_list_groups_for_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected 1 group for alice");
    assert_eq!(resp.groups[0].group_name, "Administrators");
}

/// Listing groups for a nonexistent user must fail.
pub async fn test_list_groups_for_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Listing groups for nonexistent user must fail");
}

/// Remove a user from a group.
pub async fn test_remove_user_from_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to remove user from group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify alice is no longer in the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user after removal");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 0, "Expected 0 groups for alice after removal");
}

/// Removing a user who is not a member of a group must fail.
pub async fn test_remove_user_from_group_not_member(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user who is not a group member must fail");
}

/// Removing a user from a nonexistent group must fail.
pub async fn test_remove_user_from_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user from nonexistent group must fail");
}
