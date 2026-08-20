//! Policy read-side test suite: GetPolicy, GetPolicyVersion, ListPolicyVersions, ListPolicies,
//! ListEntitiesForPolicy, ListPolicyTags.
use {
    super::common::VALID_POLICY_DOCUMENT,
    pretty_assertions::assert_eq,
    scratchstack_core::RequestId,
    scratchstack_iam_database::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AttachGroupPolicyInternalRequest, AttachRolePolicyInternalRequest, AttachUserPolicyInternalRequest,
            CreateGroupInternalRequest, CreatePolicyInternalRequest, CreateUserInternalRequest, DeletePolicyRequest,
            GetPolicyRequest, GetPolicyVersionRequest, ListEntitiesForPolicyRequest, ListPoliciesInternalRequest,
            ListPolicyTagsRequest, ListPolicyVersionsRequest, TagPolicyRequest,
        },
        types::{EntityType, PolicyScopeType, PolicyUsageType, Tag},
    },
};

// -- GetPolicy / GetPolicyVersion tests ----------------------------------------

pub async fn test_get_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy")
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathPolicy")
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion")
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to get AwsOwnedDelVersion via 'aws' account");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("AwsOwnedDelVersion"));
}

pub async fn test_get_policy_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/TestPolicy")
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Get with mismatched path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_get_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchGetPolicy")
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Get on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// VersionedPolicy has v3 as default after CreatePolicyVersion tests.
pub async fn test_get_policy_version_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy")
        .version_id("v3")
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy")
        .version_id("v4")
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy")
        .version_id("v99")
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Get nonexistent version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

pub async fn test_get_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/VersionedPolicy")
        .version_id("v1")
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Get with wrong path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- ListPolicyVersions tests -------------------------------------------------

pub async fn test_list_policy_versions_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPolicyVersionsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy")
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchListVersions")
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx, RequestId::new())
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
        .max_items(2)
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list page 1");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page1.versions.len(), 2);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.expect("Page 1 should have a marker");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page2 = ListPolicyVersionsRequest::builder()
        .policy_arn(arn.to_string())
        .max_items(2)
        .marker(marker)
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::Local)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::Aws)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::All)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::Local)
        .path_prefix("/engineering/")
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::All)
        .only_attached(true)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .policy_name("CrossAttachOnly")
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::Local)
        .only_attached(true)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::All)
        .policy_usage_filter(PolicyUsageType::PermissionsBoundary)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
        .account_id("123456789012")
        .scope(PolicyScopeType::All)
        .policy_usage_filter(PolicyUsageType::PermissionsPolicy)
        .max_items(1000)
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx, RequestId::new())
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
            .account_id("123456789012")
            .path("/pagination/")
            .build()
            .expect("Failed to build CreatePolicyInternalRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .unwrap_or_else(|e| panic!("Failed to create PaginationPolicy{i}: {e:?}"));
    }

    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListPoliciesResponse {
        let mut builder = ListPoliciesInternalRequest::builder()
            .account_id("123456789012")
            .scope(PolicyScopeType::Local)
            .path_prefix("/pagination/")
            .max_items(2);
        if let Some(marker) = marker {
            builder = builder.marker(marker);
        }
        builder
            .build()
            .expect("Failed to build ListPoliciesInternalRequest")
            .execute(tx, RequestId::new())
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

// -- ListEntitiesForPolicy tests ----------------------------------------------

/// At this point in the test sequence, Example-Managed-Policy-1 is attached (via seed) to:
///   * group Example-Group-1 (account 123456789012)
///   * role  Example-Role-1  (account 123456789012)
///   * user  Example-User-2  (account 210987654321)
///
/// Default filter is PermissionsPolicy, so the response includes one entity in each section.
pub async fn test_list_entities_for_policy_default(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for policy");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.policy_groups.len(), 1, "Expected one attached group");
    assert_eq!(resp.policy_groups[0].group_name.as_deref(), Some("Example-Group-1"));
    assert_eq!(resp.policy_groups[0].group_id.as_deref(), Some("AGPAEXAMPLEGROUPID123"));

    assert_eq!(resp.policy_roles.len(), 1, "Expected one attached role");
    assert_eq!(resp.policy_roles[0].role_name.as_deref(), Some("Example-Role-1"));
    assert_eq!(resp.policy_roles[0].role_id.as_deref(), Some("AROAEXAMPLEROLEID123"));

    assert_eq!(resp.policy_users.len(), 1, "Expected one attached user");
    assert_eq!(resp.policy_users[0].user_name.as_deref(), Some("Example-User-2"));
    assert_eq!(resp.policy_users[0].user_id.as_deref(), Some("AIDAEXAMPLEUSERID456"));

    assert!(!resp.is_truncated.unwrap_or(false), "Result should not be truncated");
    assert!(resp.marker.is_none(), "No marker expected for a single page");
}

pub async fn test_list_entities_for_policy_user_filter(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .entity_filter(EntityType::User)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for policy with user filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.policy_groups.is_empty(), "Group section must be empty under User filter");
    assert!(resp.policy_roles.is_empty(), "Role section must be empty under User filter");
    assert_eq!(resp.policy_users.len(), 1);
    assert_eq!(resp.policy_users[0].user_name.as_deref(), Some("Example-User-2"));
}

pub async fn test_list_entities_for_policy_group_filter(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .entity_filter(EntityType::Group)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for policy with group filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.policy_groups.len(), 1);
    assert_eq!(resp.policy_groups[0].group_name.as_deref(), Some("Example-Group-1"));
    assert!(resp.policy_roles.is_empty());
    assert!(resp.policy_users.is_empty());
}

pub async fn test_list_entities_for_policy_role_filter(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .entity_filter(EntityType::Role)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for policy with role filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.policy_groups.is_empty());
    assert_eq!(resp.policy_roles.len(), 1);
    assert_eq!(resp.policy_roles[0].role_name.as_deref(), Some("Example-Role-1"));
    assert!(resp.policy_users.is_empty());
}

/// Example-Managed-Policy-1 is set as the permissions boundary of Example-User-1 (in seed) and
/// of dave (created earlier in the test sequence via test_create_user_with_permissions_boundary).
/// Under PermissionsBoundary filter we should get both users and no groups or roles.
pub async fn test_list_entities_for_policy_pb_filter(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .policy_usage_filter(PolicyUsageType::PermissionsBoundary)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for policy with PB filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.policy_groups.is_empty(), "Groups cannot have a permissions boundary");
    assert!(resp.policy_roles.is_empty(), "No role uses Example-Managed-Policy-1 as PB at this point");

    let user_names: Vec<String> = resp.policy_users.iter().filter_map(|u| u.user_name.clone()).collect();
    assert!(user_names.contains(&"dave".to_string()), "Expected dave in PB users: {user_names:?}");
    assert!(user_names.contains(&"Example-User-1".to_string()), "Expected Example-User-1 in PB users: {user_names:?}");
}

/// Walk the cross-section marker pagination path: attach Example-Managed-Policy-1's three seed
/// entities with max_items=2, then verify page 1 returns 2 entities and a marker, and page 2
/// returns the remaining 1 entity.
pub async fn test_list_entities_for_policy_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let page1 = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .max_items(2)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities (page 1)");

    let page1_total = page1.policy_groups.len() + page1.policy_roles.len() + page1.policy_users.len();
    assert_eq!(page1_total, 2, "Page 1 should hold 2 entities total");
    // Section order is groups → roles → users, so page 1 picks up the group and the role.
    assert_eq!(page1.policy_groups.len(), 1);
    assert_eq!(page1.policy_roles.len(), 1);
    assert!(page1.policy_users.is_empty());
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.expect("Page 1 should provide a continuation marker");

    let page2 = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .max_items(2)
        .marker(marker)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(page2.policy_groups.is_empty(), "Page 2 should have no groups");
    assert!(page2.policy_roles.is_empty(), "Page 2 should have no roles");
    assert_eq!(page2.policy_users.len(), 1, "Page 2 should hold the remaining user");
    assert_eq!(page2.policy_users[0].user_name.as_deref(), Some("Example-User-2"));
    assert!(!page2.is_truncated.unwrap_or(false), "Page 2 should not be truncated");
    assert!(page2.marker.is_none(), "Page 2 should have no marker");
}

pub async fn test_list_entities_for_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchListEntities")
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing entities for a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// path_prefix filters by the entity's path, not the policy's. Example-Group-1 is at "/"; a
/// filter that does not match "/" should exclude it. We also attach a fresh group at
/// "/engineering/" in the same transaction and confirm only it appears under the prefix filter.
pub async fn test_list_entities_for_policy_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    // Add a /engineering/ group attached to the policy in this transaction.
    CreateGroupInternalRequest::builder()
        .account_id("123456789012")
        .group_name("EngineeringGroup")
        .path("/engineering/")
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create EngineeringGroup");
    AttachGroupPolicyInternalRequest::builder()
        .account_id("123456789012")
        .group_name("EngineeringGroup")
        .policy_arn("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach Example-Managed-Policy-1 to EngineeringGroup");

    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .path_prefix("/engineering/")
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities with path_prefix");
    tx.rollback().await.expect("Failed to rollback transaction");

    // Only the /engineering/ group qualifies; Example-Group-1 (path "/") is excluded, and roles
    // and users at "/" are also excluded.
    assert_eq!(resp.policy_groups.len(), 1);
    assert_eq!(resp.policy_groups[0].group_name.as_deref(), Some("EngineeringGroup"));
    assert!(resp.policy_roles.is_empty(), "No /engineering/ roles attached");
    assert!(resp.policy_users.is_empty(), "No /engineering/ users attached");
}

/// EntityFilter values that don't name an entity type (e.g. AWSManagedPolicy) must be rejected.
pub async fn test_list_entities_for_policy_invalid_filter(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .entity_filter(EntityType::AWSManagedPolicy)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("EntityFilter=AWSManagedPolicy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// Attaching a policy to one user in an account other than the policy's owning account must NOT
/// be possible in normal flow (attach_user_policy blocks it). To exercise that ListEntitiesForPolicy
/// would surface cross-account attachments if they existed, insert one directly via SQL and verify
/// the entity shows up. This mirrors how real AWS-managed policies (account 000000000000) are
/// attached to entities in any account.
pub async fn test_list_entities_for_policy_cross_account_attachment(pool: &sqlx::PgPool) {
    // Create an AWS-managed policy and a user in account 123456789012, then attach across accounts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    CreatePolicyInternalRequest::builder()
        .policy_name("CrossAccountListEntities")
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("000000000000")
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create AWS-managed policy");
    CreateUserInternalRequest::builder()
        .account_id("123456789012")
        .user_name("xacct-user")
        .build()
        .expect("Failed to build CreateUserInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create xacct-user");
    CreateGroupInternalRequest::builder()
        .account_id("210987654321")
        .group_name("xacct-group")
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create xacct-group");

    AttachUserPolicyInternalRequest::builder()
        .account_id("123456789012")
        .user_name("xacct-user")
        .policy_arn("arn:aws:iam::aws:policy/CrossAccountListEntities")
        .build()
        .expect("Failed to build AttachUserPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach AWS-managed policy to xacct-user");
    AttachGroupPolicyInternalRequest::builder()
        .account_id("210987654321")
        .group_name("xacct-group")
        .policy_arn("arn:aws:iam::aws:policy/CrossAccountListEntities")
        .build()
        .expect("Failed to build AttachGroupPolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to attach AWS-managed policy to xacct-group");

    // List entities — should return both the user (account 123456789012) and the group
    // (account 210987654321), since AWS-managed policies attach across accounts.
    let resp = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/CrossAccountListEntities")
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities for cross-account policy");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.policy_groups.len(), 1);
    assert_eq!(resp.policy_groups[0].group_name.as_deref(), Some("xacct-group"));
    assert!(resp.policy_roles.is_empty());
    assert_eq!(resp.policy_users.len(), 1);
    assert_eq!(resp.policy_users[0].user_name.as_deref(), Some("xacct-user"));
}

/// Attaching the same managed policy to roles whose name happens to fall lexicographically
/// between two attached roles must be reachable in pagination. We create three additional roles,
/// attach all three to a fresh policy, and walk pages of size 2.
pub async fn test_list_entities_for_policy_within_section_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    CreatePolicyInternalRequest::builder()
        .policy_name("WithinSectionPaginationPolicy")
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012")
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create WithinSectionPaginationPolicy");

    for (role_name, role_id) in [
        ("ApolloRole", "WSPAPOLLOROLEIDXX1"),
        ("BeagleRole", "WSPBEAGLEROLEIDXX2"),
        ("CassiniRole", "WSPCASSINIROLEID3"),
    ] {
        sqlx::query(
            "INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, \
             assume_role_policy_document) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(role_id)
        .bind("123456789012")
        .bind(role_name.to_lowercase())
        .bind(role_name)
        .bind("/")
        .bind(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#)
        .execute(tx.as_mut())
        .await
        .unwrap_or_else(|e| panic!("Failed to insert {role_name}: {e}"));
        AttachRolePolicyInternalRequest::builder()
            .account_id("123456789012")
            .role_name(role_name.to_string())
            .policy_arn("arn:aws:iam::123456789012:policy/WithinSectionPaginationPolicy")
            .build()
            .expect("Failed to build AttachRolePolicyInternalRequest")
            .execute(&mut tx, RequestId::new())
            .await
            .unwrap_or_else(|e| panic!("Failed to attach to {role_name}: {e:?}"));
    }

    // Page through with max_items=2.
    let page1 = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/WithinSectionPaginationPolicy")
        .max_items(2)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities (page 1)");
    let marker = page1.marker.clone().expect("Page 1 should provide a continuation marker");

    let page2 = ListEntitiesForPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/WithinSectionPaginationPolicy")
        .max_items(2)
        .marker(marker)
        .build()
        .expect("Failed to build ListEntitiesForPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list entities (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    // Three roles split across two pages: 2 in page 1, 1 in page 2.
    let mut role_names: Vec<String> =
        page1.policy_roles.iter().chain(page2.policy_roles.iter()).filter_map(|r| r.role_name.clone()).collect();
    role_names.sort();
    assert_eq!(role_names, vec!["ApolloRole".to_string(), "BeagleRole".to_string(), "CassiniRole".to_string()]);
    assert_eq!(page1.policy_roles.len(), 2, "Page 1 should contain 2 roles");
    assert_eq!(page2.policy_roles.len(), 1, "Page 2 should contain 1 role");
}

// -- ListPolicyTags tests -----------------------------------------------------

/// List tags on `TestPolicy`. At this point in the suite the policy has only Env=Staging left
/// after the tag/untag-policy tests.
pub async fn test_list_policy_tags_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPolicyTagsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy")
        .build()
        .expect("Failed to build ListPolicyTagsRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list tags on TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 1, "Expected 1 tag on TestPolicy, got: {:?}", resp.tags);
    assert_eq!(resp.tags[0].key, "Env");
    assert_eq!(resp.tags[0].value, "Staging");
    assert!(resp.is_truncated != Some(true), "Expected no truncation, got {:?}", resp.is_truncated);
    assert!(resp.marker.is_none(), "Expected no marker, got {:?}", resp.marker);
}

/// Listing tags on a policy with no tags must succeed and return an empty list. Example-Managed-
/// Policy-1 has no tags in the seed data.
pub async fn test_list_policy_tags_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPolicyTagsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1")
        .build()
        .expect("Failed to build ListPolicyTagsRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to list tags on Example-Managed-Policy-1");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(resp.tags.is_empty(), "Expected empty tag list, got {} tags", resp.tags.len());
}

/// Listing tags on a nonexistent policy must fail with NoSuchEntity.
pub async fn test_list_policy_tags_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListPolicyTagsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchPolicyTags")
        .build()
        .expect("Failed to build ListPolicyTagsRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing tags on a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Listing tags with an unparseable ARN must fail with ValidationError.
pub async fn test_list_policy_tags_invalid_arn(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListPolicyTagsRequest::builder()
        // Long enough to satisfy the Smithy >= 20 character length, but not a valid ARN.
        .policy_arn("not-an-arn-but-long-enough-to-pass")
        .build()
        .expect("Failed to build ListPolicyTagsRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect_err("Listing tags with a bad ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// Building a ListPolicyTags request with an ARN shorter than the Smithy minimum (20 chars) must
/// fail at the builder before reaching the database.
pub fn test_list_policy_tags_builder_arn_too_short() {
    let result = ListPolicyTagsRequest::builder().policy_arn("short-arn").build();
    assert!(result.is_err(), "Building a request with an ARN under 20 chars must fail");
}

/// Walk pagination: create a fresh policy with 5 tags, page through them with max_items=2, then
/// clean the policy up so subsequent tests aren't affected.
pub async fn test_list_policy_tags_pagination(pool: &sqlx::PgPool) {
    let pol_arn = "arn:test-partition:iam::123456789012:policy/PaginationTagsPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .account_id("123456789012")
        .policy_name("PaginationTagsPolicy")
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to create PaginationTagsPolicy");
    let tags: Vec<Tag> = (0..5)
        .map(|i| {
            Tag::builder()
                .key(format!("Key{i}"))
                .value(format!("Value{i}"))
                .build()
                .expect("Failed to build pagination tag")
        })
        .collect();
    TagPolicyRequest::builder()
        .policy_arn(pol_arn.to_string())
        .set_tags(tags)
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to tag PaginationTagsPolicy");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_page = async |tx: &mut sqlx::PgTransaction<'_>,
                           marker: Option<String>|
           -> scratchstack_shapes_iam::operation::ListPolicyTagsResponse {
        let mut builder = ListPolicyTagsRequest::builder().policy_arn(pol_arn.to_string()).max_items(2);
        if let Some(marker) = marker {
            builder = builder.marker(marker);
        }
        builder
            .build()
            .expect("Failed to build ListPolicyTagsRequest")
            .execute(tx, RequestId::new())
            .await
            .expect("Failed to list policy tags page")
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

    // Clean up the fresh policy outside the rolled-back transaction.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyRequest::builder()
        .policy_arn(pol_arn.to_string())
        .build()
        .expect("Failed to build DeletePolicyRequest")
        .execute(&mut tx, RequestId::new())
        .await
        .expect("Failed to delete PaginationTagsPolicy");
    tx.commit().await.expect("Failed to commit transaction");
}
