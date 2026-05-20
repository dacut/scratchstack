//! Policy read-side test suite: GetPolicy, GetPolicyVersion, ListPolicyVersions, ListPolicies.
use {
    super::common::VALID_POLICY_DOCUMENT,
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            CreatePolicyInternalRequest, GetPolicyRequest, GetPolicyVersionRequest, ListPoliciesInternalRequest,
            ListPolicyVersionsRequest,
        },
        types::{PolicyScopeType, PolicyUsageType},
    },
};

// -- GetPolicy / GetPolicyVersion tests ----------------------------------------

pub async fn test_get_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("TestPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/"));
    assert_eq!(policy.default_version_id.as_deref(), Some("v1"));
    assert_eq!(policy.is_attachable, Some(true));
    assert_eq!(policy.arn.as_deref(), Some("arn:test-partition:iam::123456789012:policy/TestPolicy"));
    assert!(policy.tags.is_empty());
    assert!(policy.policy_id.as_ref().unwrap().starts_with("ANPA"));
    assert!(policy.create_date.is_some());
    assert!(policy.update_date.is_some());
}

pub async fn test_get_policy_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get PathPolicy at /engineering/");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("PathPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/engineering/"));
}

/// Look up the AWS-owned policy created earlier in the delete tests by using "aws" in the ARN.
pub async fn test_get_policy_aws_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get AwsOwnedDelVersion via 'aws' account");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("AwsOwnedDelVersion"));
}

pub async fn test_get_policy_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/TestPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get with mismatched path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_get_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchGetPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// VersionedPolicy has v3 as default after CreatePolicyVersion tests.
pub async fn test_get_policy_version_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get v3 of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pv = resp.policy_version.expect("Response should include policy_version");
    assert_eq!(pv.version_id.as_deref(), Some("v3"));
    assert_eq!(pv.is_default_version, Some(true));
    assert!(pv.document.is_some());
    assert!(pv.create_date.is_some());

    // Also fetch a non-default version (v4 was created non-default in CreatePolicyVersion tests).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v4".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get v4 of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pv = resp.policy_version.expect("Response should include policy_version");
    assert_eq!(pv.version_id.as_deref(), Some("v4"));
    assert_eq!(pv.is_default_version, Some(false));
}

pub async fn test_get_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get nonexistent version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_get_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get with wrong path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- ListPolicyVersions tests -------------------------------------------------

pub async fn test_list_policy_versions_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPolicyVersionsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list versions of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    // VersionedPolicy has v2..v5 after v1 was deleted in delete tests.
    let version_ids: Vec<String> = resp.versions.iter().filter_map(|v| v.version_id.clone()).collect();
    assert_eq!(version_ids, vec!["v5".to_string(), "v4".to_string(), "v3".to_string(), "v2".to_string()]);

    // v3 should be marked as the default.
    let v3 = resp.versions.iter().find(|v| v.version_id.as_deref() == Some("v3")).expect("v3 should exist");
    assert_eq!(v3.is_default_version, Some(true));
    let v4 = resp.versions.iter().find(|v| v.version_id.as_deref() == Some("v4")).expect("v4 should exist");
    assert_eq!(v4.is_default_version, Some(false));
}

pub async fn test_list_policy_versions_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListPolicyVersionsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchListVersions".to_string())
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect_err("List versions on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_list_policy_versions_pagination(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/VersionedPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListPolicyVersionsRequest::builder()
        .policy_arn(arn.to_string())
        .max_items(Some(2))
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list page 1");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page1.versions.len(), 2);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.expect("Page 1 should have a marker");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page2 = ListPolicyVersionsRequest::builder()
        .policy_arn(arn.to_string())
        .max_items(Some(2))
        .marker(Some(marker))
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list page 2");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.versions.len(), 2);
    let all: Vec<String> =
        page1.versions.iter().chain(page2.versions.iter()).filter_map(|v| v.version_id.clone()).collect();
    assert_eq!(all, vec!["v5".to_string(), "v4".to_string(), "v3".to_string(), "v2".to_string()]);
}

// -- ListPolicies tests -------------------------------------------------------

pub async fn test_list_policies_local(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Local))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list local policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"TestPolicy".to_string()), "Expected TestPolicy in local list: {names:?}");
    assert!(names.contains(&"Example-Managed-Policy-1".to_string()), "Expected Example-Managed-Policy-1: {names:?}");
    assert!(names.iter().all(|n| n != "AwsOwnedDelVersion"), "AwsOwnedDelVersion should not be local for this account");
}

pub async fn test_list_policies_aws(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Aws))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list AWS-scope policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"AwsOwnedDelVersion".to_string()), "Expected AwsOwnedDelVersion in AWS-scope: {names:?}");
    assert!(names.iter().all(|n| n != "TestPolicy"), "TestPolicy is customer-managed and must not appear");
}

pub async fn test_list_policies_all(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list all policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"TestPolicy".to_string()));
    assert!(names.contains(&"AwsOwnedDelVersion".to_string()));
}

pub async fn test_list_policies_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Local))
        .path_prefix(Some("/engineering/".to_string()))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list policies with /engineering/ path");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"PathPolicy".to_string()), "Expected PathPolicy: {names:?}");
    assert!(names.contains(&"PathDelVersion".to_string()), "Expected PathDelVersion: {names:?}");
    for policy in &resp.policies {
        assert_eq!(policy.path.as_deref(), Some("/engineering/"));
    }
}

/// only_attached=true should surface policies attached to entities in the caller's account, but
/// must NOT surface a policy whose only attachment is cross-account.
///
/// Positive: Example-Managed-Policy-1 (AAAABBBBCCCCDDDD, owned by 123456789012) is attached to
/// EXAMPLEGROUPID123 and EXAMPLEROLEID123 (both in 123456789012) via the seeded data, so it
/// must appear.
///
/// Negative: we create a fresh policy in 123456789012, attach it only to a fresh group in
/// 210987654321 (via raw SQL inside a tx that rolls back), and verify it does NOT appear from
/// 123456789012's view. This is the case the pre-fix code leaked.
pub async fn test_list_policies_only_attached(pool: &sqlx::PgPool) {
    // Positive case (uses seeded in-account attachments).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .only_attached(Some(true))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list attached policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(
        names.contains(&"Example-Managed-Policy-1".to_string()),
        "Expected Example-Managed-Policy-1 via in-account group/role attachments: {names:?}"
    );
    assert!(!names.contains(&"TestPolicy".to_string()), "TestPolicy is not attached and should not appear");

    // Negative case: a policy with only a cross-account attachment must not leak. All writes and
    // the read happen in the same transaction so nothing persists into later tests.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let create_resp = CreatePolicyInternalRequest::builder()
        .policy_name("CrossAttachOnly".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create CrossAttachOnly");
    // managed_policy_id stored in the DB is the IAM id without its 4-char "ANPA" prefix.
    let managed_policy_id = create_resp
        .policy
        .unwrap()
        .policy_id
        .unwrap()
        .strip_prefix("ANPA")
        .expect("policy_id has ANPA prefix")
        .to_string();

    // Insert a fresh group in 210987654321 and attach the policy to it cross-account.
    sqlx::query(
        "INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind("XACCTGRPIDXACCTGR")
    .bind("210987654321")
    .bind("xacct-grp")
    .bind("xacct-grp")
    .bind("/")
    .execute(tx.as_mut())
    .await
    .expect("Failed to insert cross-account group");
    sqlx::query("INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES ($1, $2)")
        .bind("XACCTGRPIDXACCTGR")
        .bind(&managed_policy_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to insert cross-account attachment");

    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Local))
        .only_attached(Some(true))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list attached policies");
    tx.rollback().await.expect("Failed to rollback transaction");
    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(
        !names.contains(&"CrossAttachOnly".to_string()),
        "CrossAttachOnly is only attached cross-account and must not appear from 123456789012's \
         view: {names:?}"
    );
}

/// Example-Managed-Policy-1 is also the permissions boundary of EXAMPLEUSERID123, so it should
/// appear when filtering for PermissionsBoundary usage.
pub async fn test_list_policies_usage_filter_pb(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .policy_usage_filter(Some(PolicyUsageType::PermissionsBoundary))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list PB policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"Example-Managed-Policy-1".to_string()), "Expected Example-Managed-Policy-1: {names:?}");

    // TestPolicy is unattached and not used as a permissions boundary, so it should not appear.
    assert!(
        !names.contains(&"TestPolicy".to_string()),
        "TestPolicy is not used as a permissions boundary and should not appear"
    );
}

/// Example-Managed-Policy-1 is attached (via the seeded group/role in 123456789012) so it should
/// appear under PolicyUsageFilter=PermissionsPolicy. TestPolicy is unattached and must not.
pub async fn test_list_policies_usage_filter_permissions_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .policy_usage_filter(Some(PolicyUsageType::PermissionsPolicy))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list PermissionsPolicy-filtered policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(
        names.contains(&"Example-Managed-Policy-1".to_string()),
        "Expected Example-Managed-Policy-1 under PermissionsPolicy filter: {names:?}"
    );
    assert!(
        !names.contains(&"TestPolicy".to_string()),
        "TestPolicy is not attached and must not appear under PermissionsPolicy filter"
    );
}

/// Walk the marker-based pagination path: create 5 policies under a fresh path, list 3 pages
/// with max_items=2, and verify the union covers all 5 with no duplicates. All writes and reads
/// happen in a transaction that rolls back so subsequent tests aren't affected.
pub async fn test_list_policies_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    // Create 5 policies in a fresh path so the path_prefix filter gives a deterministic subset.
    for i in 0..5 {
        CreatePolicyInternalRequest::builder()
            .policy_name(format!("PaginationPolicy{i}"))
            .policy_document(VALID_POLICY_DOCUMENT.to_string())
            .account_id("123456789012".to_string())
            .path(Some("/pagination/".to_string()))
            .build()
            .expect("Failed to build CreatePolicyInternalRequest")
            .execute(&mut tx)
            .await
            .unwrap_or_else(|e| panic!("Failed to create PaginationPolicy{i}: {e:?}"));
    }

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListPoliciesResponse {
        let mut builder = ListPoliciesInternalRequest::builder()
            .account_id("123456789012".to_string())
            .scope(Some(PolicyScopeType::Local))
            .path_prefix(Some("/pagination/".to_string()))
            .max_items(Some(2));
        if let Some(marker) = marker {
            builder = builder.marker(Some(marker));
        }
        builder
            .build()
            .expect("Failed to build ListPoliciesInternalRequest")
            .execute(tx)
            .await
            .expect("Failed to list policies page")
    };

    let page1 = list_page(&mut tx, None).await;
    assert_eq!(page1.policies.len(), 2, "page 1 should have max_items=2 entries");
    assert_eq!(page1.is_truncated, Some(true), "page 1 should be truncated");
    let marker1 = page1.marker.clone().expect("page 1 should have a marker");

    let page2 = list_page(&mut tx, Some(marker1)).await;
    assert_eq!(page2.policies.len(), 2, "page 2 should have max_items=2 entries");
    assert_eq!(page2.is_truncated, Some(true), "page 2 should be truncated");
    let marker2 = page2.marker.clone().expect("page 2 should have a marker");

    let page3 = list_page(&mut tx, Some(marker2)).await;
    assert_eq!(page3.policies.len(), 1, "page 3 should have the remaining 1 entry");
    assert!(page3.is_truncated != Some(true), "page 3 should not be truncated");
    assert!(page3.marker.is_none(), "page 3 should have no marker");

    let mut all_names: Vec<String> = page1
        .policies
        .iter()
        .chain(page2.policies.iter())
        .chain(page3.policies.iter())
        .filter_map(|p| p.policy_name.clone())
        .collect();
    let unique: std::collections::HashSet<&String> = all_names.iter().collect();
    assert_eq!(unique.len(), all_names.len(), "Pages must not contain duplicate policy names: {all_names:?}");

    all_names.sort();
    let expected: Vec<String> = (0..5).map(|i| format!("PaginationPolicy{i}")).collect();
    assert_eq!(all_names, expected, "Union of pages should cover all 5 policies");

    tx.rollback().await.expect("Failed to rollback transaction");
}
