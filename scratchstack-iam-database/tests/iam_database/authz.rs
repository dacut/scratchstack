//! Authorization test suite: gathering the policies that apply to a principal and evaluating
//! them with Aspen's `authorize`.
use {
    pretty_assertions::assert_eq,
    scratchstack_aspen::{Context, Decision, PolicySet, PolicySource, authorize},
    scratchstack_aws_principal::{Principal as PrincipalActor, SessionData, SessionValue, User},
    scratchstack_core::RequestId,
    scratchstack_iam_database::{authz::get_policies_for_user, user::put_user_policy},
};

const EXAMPLE_ACCOUNT_1: &str = "123456789012";
const EXAMPLE_ACCOUNT_2: &str = "210987654321";
const EXAMPLE_USER_ID_1: &str = "EXAMPLEUSERID123";
const EXAMPLE_USER_ID_2: &str = "EXAMPLEUSERID456";

/// Build an evaluation context for the given seeded user.
fn make_context(service: &str, api: &str, account_id: &str, path: &str, user_name: &str) -> Context {
    make_context_with_session(service, api, account_id, path, user_name, SessionData::new())
}

/// Build an evaluation context for the given seeded user with explicit session data.
fn make_context_with_session(
    service: &str,
    api: &str,
    account_id: &str,
    path: &str,
    user_name: &str,
    session_data: SessionData,
) -> Context {
    let actor = PrincipalActor::from(
        User::new("test-partition", account_id, path, user_name).expect("Failed to create user principal"),
    );
    Context::builder()
        .api(api)
        .actor(actor)
        .service(service)
        .session_data(session_data)
        .build()
        .expect("Failed to build context")
}

pub async fn test_get_policies_for_user_direct(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_2, EXAMPLE_USER_ID_2, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-2");
    tx.rollback().await.expect("Failed to rollback transaction");

    let sources: Vec<&PolicySource> = policy_set.policies().iter().map(|(source, _)| source).collect();
    assert_eq!(sources.len(), 2);
    assert!(sources.contains(&&PolicySource::new_entity_inline(
        "arn:test-partition:iam::210987654321:user/a/b/c/Example-User-2",
        "AIDAEXAMPLEUSERID456",
        "Example-Inline-Policy-1",
    )));
    assert!(sources.contains(&&PolicySource::new_entity_attached_policy(
        "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1",
        "ANPAAAAABBBBCCCCDDDD",
        "v1",
    )));
}

pub async fn test_get_policies_for_user_via_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_1, EXAMPLE_USER_ID_1, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");

    let sources: Vec<&PolicySource> = policy_set.policies().iter().map(|(source, _)| source).collect();
    assert_eq!(sources.len(), 3);
    assert!(sources.contains(&&PolicySource::new_group_inline(
        "arn:test-partition:iam::123456789012:group/Example-Group-1",
        "AGPAEXAMPLEGROUPID123",
        "Example-Group-Inline-Policy-1",
    )));
    assert!(sources.contains(&&PolicySource::new_group_attached_policy(
        "arn:test-partition:iam::123456789012:group/Example-Group-1",
        "AGPAEXAMPLEGROUPID123",
        "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1",
        "ANPAAAAABBBBCCCCDDDD",
        "v1",
    )));
    assert!(sources.contains(&&PolicySource::new_permission_boundary(
        "arn:test-partition:iam::123456789012:policy/Example-Managed-Policy-1",
        "ANPAAAAABBBBCCCCDDDD",
        "v1",
    )));
}

pub async fn test_get_policies_for_user_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_1, "NONEXISTENTUSERID", RequestId::new())
        .await
        .expect("Gathering policies for a nonexistent user should succeed");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(policy_set, PolicySet::new());
}

pub async fn test_authorize_allow_via_group_attached(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_1, EXAMPLE_USER_ID_1, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");

    // The group-attached managed policy allows s3:ListBucket, and the permissions boundary
    // (the same policy) allows it as well.
    let context = make_context("s3", "ListBucket", EXAMPLE_ACCOUNT_1, "/", "Example-User-1");
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::Allow);
    assert!(result.is_allowed());
    assert!(result.sources().iter().any(|source| matches!(source, PolicySource::GroupAttachedPolicy { .. })));
}

pub async fn test_authorize_boundary_deny(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_1, EXAMPLE_USER_ID_1, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-1");
    tx.rollback().await.expect("Failed to rollback transaction");

    // The group inline policy allows dynamodb:*, but the permissions boundary only allows
    // s3:ListBucket, so the request is denied by the boundary.
    let context = make_context("dynamodb", "PutItem", EXAMPLE_ACCOUNT_1, "/", "Example-User-1");
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::Deny);
    assert!(!result.is_allowed());
    assert_eq!(result.sources().len(), 1);
    assert!(result.sources()[0].is_boundary());
}

pub async fn test_authorize_default_deny_no_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_2, EXAMPLE_USER_ID_2, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-2");
    tx.rollback().await.expect("Failed to rollback transaction");

    // Example-User-2's policies cover ec2:* and s3:ListBucket, but not iam:ListUsers.
    let context = make_context("iam", "ListUsers", EXAMPLE_ACCOUNT_2, "/a/b/c/", "Example-User-2");
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::DefaultDeny);
    assert!(!result.is_allowed());
    assert!(result.sources().is_empty());
}

pub async fn test_authorize_explicit_deny(pool: &sqlx::PgPool) {
    const DENY_LIST_BUCKET: &str = concat!(
        r#"{"Version": "2012-10-17", "Statement": ["#,
        r#"{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, "#,
        r#"{"Effect": "Deny", "Action": "s3:ListBucket", "Resource": "*"}"#,
        r#"]}"#,
    );

    // Store the policy through the real write path, gather it back, and evaluate — all inside a
    // transaction that is rolled back at the end.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    put_user_policy(&mut tx, EXAMPLE_ACCOUNT_2, "Example-User-2", "DenyListBucket", DENY_LIST_BUCKET, RequestId::new())
        .await
        .expect("Failed to put user policy");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_2, EXAMPLE_USER_ID_2, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-2");
    tx.rollback().await.expect("Failed to rollback transaction");

    // The explicit deny overrides the allow that appears before it in the same policy.
    let context = make_context("s3", "ListBucket", EXAMPLE_ACCOUNT_2, "/a/b/c/", "Example-User-2");
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::Deny);

    // Other s3 actions are still allowed by the new policy.
    let context = make_context("s3", "GetObject", EXAMPLE_ACCOUNT_2, "/a/b/c/", "Example-User-2");
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::Allow);
}

pub async fn test_authorize_condition_keys(pool: &sqlx::PgPool) {
    const CONDITIONAL_ALLOW: &str = concat!(
        r#"{"Version": "2012-10-17", "Statement": ["#,
        r#"{"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*", "#,
        r#""Condition": {"StringEquals": {"aws:username": "Example-User-2"}}}"#,
        r#"]}"#,
    );

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    put_user_policy(
        &mut tx,
        EXAMPLE_ACCOUNT_2,
        "Example-User-2",
        "ConditionalListUsers",
        CONDITIONAL_ALLOW,
        RequestId::new(),
    )
    .await
    .expect("Failed to put user policy");
    let policy_set = get_policies_for_user(&mut tx, EXAMPLE_ACCOUNT_2, EXAMPLE_USER_ID_2, RequestId::new())
        .await
        .expect("Failed to gather policies for Example-User-2");
    tx.rollback().await.expect("Failed to rollback transaction");

    let mut session_data = SessionData::new();
    session_data.insert("aws:username", SessionValue::from("Example-User-2"));
    let context =
        make_context_with_session("iam", "ListUsers", EXAMPLE_ACCOUNT_2, "/a/b/c/", "Example-User-2", session_data);
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::Allow);

    let mut session_data = SessionData::new();
    session_data.insert("aws:username", SessionValue::from("Someone-Else"));
    let context =
        make_context_with_session("iam", "ListUsers", EXAMPLE_ACCOUNT_2, "/a/b/c/", "Example-User-2", session_data);
    let result = authorize(&context, &policy_set).expect("Failed to authorize");
    assert_eq!(result.decision(), Decision::DefaultDeny);
}
