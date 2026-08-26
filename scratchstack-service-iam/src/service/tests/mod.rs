use {
    crate::service::{ServiceState, serve_request},
    chrono::{DateTime, Utc},
    http_body_util::BodyExt as _,
    pct_str::PctStr,
    scratchstack_aws_principal::{AssumedRole, Principal, RootUser, SessionData, SessionValue, User},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_config::{ForwardedForConfig, Resolvable as _},
    scratchstack_core::{
        RequestId,
        axum::{
            body::{Body, Bytes},
            extract::{ConnectInfo, Extension, RawQuery, State},
            http::{HeaderMap, StatusCode},
            response::Response,
        },
    },
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::{AssertSqlSafe, raw_sql},
    std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr as _,
        sync::{
            Arc, LazyLock, Weak,
            atomic::{AtomicU64, Ordering},
        },
    },
    tokio::sync::Mutex,
};

mod policy;
mod role;
mod user;

/// The token the seed data uses where the test's own account id belongs.
///
/// Each test is seeded into an account of its own, so the account id cannot be written into
/// the seed data literally; [`TestDatabase::new`] substitutes this for the one it assigned.
const ACCOUNT_ID_PLACEHOLDER: &str = "%ACCOUNT_ID%";

/// The first account id handed out to a test.
///
/// This is well clear of the account ids the seed data names outright -- `210987654321` for the
/// account a policy deliberately does not grant, `000000000000` for the AWS-managed policies --
/// so a test's own account is never one of them.
const FIRST_TEST_ACCOUNT_ID: u64 = 900_000_000_000;

/// The region test requests are signed for; the signing-key provider records it as
/// `aws:RequestedRegion` for both long-term and temporary credentials.
const TEST_REGION: &str = "us-east-1";

/// The peer address test requests arrive from unless a test names another, backing the
/// `aws:SourceIp` condition key. The addresses used here come from the documentation ranges
/// reserved by RFC 5737 and RFC 3849.
const TEST_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

/// A pagination marker this service did not issue: base64-encoded JSON, which is the shape of
/// the client-side pagination token the AWS CLI and several SDKs hand out in place of the
/// marker they wrap. It is well-formed enough to reach the token itself, which is where a
/// caller passing the wrong one back finds out.
const FOREIGN_PAGINATION_TOKEN: &str = "eyJNYXJrZXIiOiAiMGFiYyIsICJib3RvX3RydW5jYXRlX2Ftb3VudCI6IDJ9";

/// A peer address outside the CIDR block the source-IP test policies grant.
const OUTSIDE_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

/// A peer address inside the IPv6 CIDR block the source-IP test policies grant.
const TEST_SOURCE_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

/// The address of the load balancer in the forwarded-header tests, inside the CIDR block
/// [`proxied_state`] trusts.
const TEST_PROXY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

/// Seed data for the authorization tests: one user whose inline policy allows
/// `iam:ListUsers`, one user with no policies at all, and users whose grants are gated on
/// the request-time condition keys (`aws:SecureTransport`, `aws:CurrentTime`,
/// `aws:EpochTime`, `aws:SourceIp`, `aws:referer`, `aws:UserAgent`) that
/// `check_authorization` injects, and on the `aws:TokenIssueTime` the session token carries.
const AUTHZ_TEST_DATA: &str = r#"
    INSERT INTO iam.accounts(account_id, email, alias) VALUES
    ('%ACCOUNT_ID%', 'authz-test@example.com', 'authz-test');

    INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
    ('SVCTESTALLOWUSER', '%ACCOUNT_ID%', 'allowed-user', 'Allowed-User', '/'),
    ('SVCTESTDENYUSER1', '%ACCOUNT_ID%', 'denied-user', 'Denied-User', '/'),
    ('SVCTESTTLSUSER01', '%ACCOUNT_ID%', 'tls-user', 'Tls-User', '/'),
    ('SVCTESTTIMEUSER1', '%ACCOUNT_ID%', 'time-user', 'Time-User', '/'),
    ('SVCTESTPASTUSER1', '%ACCOUNT_ID%', 'past-user', 'Past-User', '/'),
    ('SVCTESTEPOCHUSR1', '%ACCOUNT_ID%', 'epoch-user', 'Epoch-User', '/'),
    ('SVCTESTIPV4USER1', '%ACCOUNT_ID%', 'ipv4-user', 'Ipv4-User', '/'),
    ('SVCTESTIPV6USER1', '%ACCOUNT_ID%', 'ipv6-user', 'Ipv6-User', '/'),
    ('SVCTESTDENYIPUSR', '%ACCOUNT_ID%', 'deny-ip-user', 'Deny-Ip-User', '/'),
    ('SVCTESTTOKENUSER', '%ACCOUNT_ID%', 'token-user', 'Token-User', '/'),
    ('SVCTESTREGIONUSR', '%ACCOUNT_ID%', 'region-user', 'Region-User', '/'),
    ('SVCTESTOTHERRGN1', '%ACCOUNT_ID%', 'other-region-user', 'Other-Region-User', '/'),
    ('SVCTESTDIRECTUSR', '%ACCOUNT_ID%', 'direct-call-user', 'Direct-Call-User', '/'),
    ('SVCTESTAGENTUSR1', '%ACCOUNT_ID%', 'agent-user', 'Agent-User', '/'),
    ('SVCTESTACCTUSER1', '%ACCOUNT_ID%', 'account-user', 'Account-User', '/'),
    ('SVCTESTOTHRACCT1', '%ACCOUNT_ID%', 'other-account-user', 'Other-Account-User', '/');

    INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTESTALLOWUSER', 'allow-list-users', 'Allow-List-Users',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}'),
    ('SVCTESTTLSUSER01', 'allow-if-tls', 'Allow-If-Tls',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}'),
    ('SVCTESTTIMEUSER1', 'allow-after-2020', 'Allow-After-2020',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}'),
    ('SVCTESTPASTUSER1', 'allow-before-2020', 'Allow-Before-2020',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}'),
    ('SVCTESTEPOCHUSR1', 'allow-after-2020-epoch', 'Allow-After-2020-Epoch',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"NumericGreaterThan":{"aws:EpochTime":"1577836800"}}}]}'),
    ('SVCTESTIPV4USER1', 'allow-from-ipv4-block', 'Allow-From-Ipv4-Block',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}'),
    ('SVCTESTIPV6USER1', 'allow-from-ipv6-block', 'Allow-From-Ipv6-Block',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}}]}'),
    ('SVCTESTACCTUSER1', 'allow-own-account', 'Allow-Own-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"%ACCOUNT_ID%"}}}]}'),
    ('SVCTESTOTHRACCT1', 'allow-other-account', 'Allow-Other-Account',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringEquals":{"aws:ResourceAccount":"210987654321"}}}]}'),
    ('SVCTESTAGENTUSR1', 'allow-known-clients', 'Allow-Known-Clients',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringLike":{"aws:UserAgent":"aws-cli/*"},
                    "StringEquals":{"aws:referer":"https://console.example.com/"}}}]}'),
    ('SVCTESTDIRECTUSR', 'allow-direct-calls', 'Allow-Direct-Calls',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"Bool":{"aws:ViaAWSService":"false","aws:PrincipalIsAWSService":"false"}}}]}'),
    ('SVCTESTREGIONUSR', 'allow-in-us-east-1', 'Allow-In-Us-East-1',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}'),
    ('SVCTESTOTHERRGN1', 'allow-in-eu-west-1', 'Allow-In-Eu-West-1',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}'),
    ('SVCTESTTOKENUSER', 'allow-recent-sessions', 'Allow-Recent-Sessions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}'),
    ('SVCTESTDENYIPUSR', 'deny-outside-ipv4-block', 'Deny-Outside-Ipv4-Block',
        '{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"},
        {"Effect":"Deny","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}');

    INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
    ('SVCTESTROLE00001', '%ACCOUNT_ID%', 'session-role', 'Session-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTESTTOKENROLE', '%ACCOUNT_ID%', 'token-role', 'Token-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTESTRGNROLE01', '%ACCOUNT_ID%', 'region-role', 'Region-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
    ('SVCTESTDIRROLE01', '%ACCOUNT_ID%', 'direct-call-role', 'Direct-Call-Role', '/',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

    INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
    ('SVCTESTROLE00001', 'allow-list-users', 'Allow-List-Users',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}'),
    ('SVCTESTTOKENROLE', 'allow-recent-sessions', 'Allow-Recent-Sessions',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}'),
    ('SVCTESTRGNROLE01', 'allow-in-us-east-1', 'Allow-In-Us-East-1',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}'),
    ('SVCTESTDIRROLE01', 'allow-direct-calls', 'Allow-Direct-Calls',
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*",
        "Condition":{"Bool":{"aws:ViaAWSService":"false","aws:PrincipalIsAWSService":"false"}}}]}');

    INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
    ('SVCTESTSESSPOL01', '%ACCOUNT_ID%', 'session-allow-iam', 'Session-Allow-Iam', '/', 1, false, 1);

    INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
    ('SVCTESTSESSPOL01', 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}');
"#;

/// Build the query parameters for a `GetUser` request, naming a user or leaving `UserName`
/// off so it defaults to the caller.
fn get_user_parameters(user_name: Option<&str>) -> String {
    let mut parameters = vec![("Action", "GetUser"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `CreateUser` request naming `user_name`, optionally
/// under a path, carrying tags, and asking for a permissions boundary.
fn create_user_parameters(
    user_name: &str,
    path: Option<&str>,
    tags: &[(&str, &str)],
    permissions_boundary: Option<&str>,
) -> String {
    let mut parameters = action_parameters("CreateUser");
    parameters.push(("UserName".to_string(), user_name.to_string()));

    if let Some(path) = path {
        parameters.push(("Path".to_string(), path.to_string()));
    }

    append_tag_parameters(&mut parameters, tags);

    if let Some(permissions_boundary) = permissions_boundary {
        parameters.push(("PermissionsBoundary".to_string(), permissions_boundary.to_string()));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `DeleteUser` request, naming a user or leaving `UserName`
/// off entirely.
fn delete_user_parameters(user_name: Option<&str>) -> String {
    let mut parameters = vec![("Action", "DeleteUser"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Extract the `PolicyDocument` from a policy response and percent-decode it, standing in for
/// the URL decoding a client applies.
///
/// IAM reports policy documents percent-encoded, so a test that wants to look at the policy
/// itself has to undo that first. The encoded form carries no XML metacharacters, so what is
/// between the tags is exactly what was encoded.
fn decoded_policy_document(body: &str) -> String {
    decoded_document_element(body, "PolicyDocument")
}

/// Extract the `Document` from a policy-version response and percent-decode it.
///
/// A managed policy version reports its document under `Document` where an inline policy reports
/// it under `PolicyDocument`; both are percent-encoded the same way.
fn decoded_policy_version_document(body: &str) -> String {
    decoded_document_element(body, "Document")
}

/// Extract the element named `tag` from a response body and percent-decode it, standing in for
/// the URL decoding a client applies.
fn decoded_document_element(body: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = body.find(&open).unwrap_or_else(|| panic!("no {tag} in body")) + open.len();
    let end = start + body[start..].find(&close).unwrap_or_else(|| panic!("unterminated {tag}"));

    PctStr::new(&body[start..end]).unwrap_or_else(|_| panic!("{tag} is not percent-encoded")).decode()
}

/// Build the query parameters for a `GetUserPolicy` request, naming a user and a policy or
/// leaving either off.
fn get_user_policy_parameters(user_name: Option<&str>, policy_name: Option<&str>) -> String {
    user_policy_parameters("GetUserPolicy", user_name, policy_name, None)
}

/// Build the query parameters for a `PutUserPolicy` request, naming a user, a policy, and the
/// document to store under it, or leaving any of them off.
fn put_user_policy_parameters(
    user_name: Option<&str>,
    policy_name: Option<&str>,
    policy_document: Option<&str>,
) -> String {
    user_policy_parameters("PutUserPolicy", user_name, policy_name, policy_document)
}

/// Build the query parameters for a `DeleteUserPolicy` request, naming a user and a policy or
/// leaving either off.
fn delete_user_policy_parameters(user_name: Option<&str>, policy_name: Option<&str>) -> String {
    user_policy_parameters("DeleteUserPolicy", user_name, policy_name, None)
}

/// Build the query parameters for an inline-user-policy request, leaving off the parameters
/// the caller does not supply so that a request missing a required one can be exercised.
///
/// The parameters are form-encoded rather than interpolated: a policy document carries JSON
/// punctuation that the query string would otherwise be read as its own.
fn user_policy_parameters(
    action: &str,
    user_name: Option<&str>,
    policy_name: Option<&str>,
    policy_document: Option<&str>,
) -> String {
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(policy_name) = policy_name {
        parameters.push(("PolicyName", policy_name));
    }
    if let Some(policy_document) = policy_document {
        parameters.push(("PolicyDocument", policy_document));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `AttachUserPolicy` request, naming a user and a managed
/// policy or leaving either off.
fn attach_user_policy_parameters(user_name: Option<&str>, policy_arn: Option<&str>) -> String {
    user_policy_attachment_parameters("AttachUserPolicy", user_name, policy_arn)
}

/// Build the query parameters for a `DetachUserPolicy` request, naming a user and a managed
/// policy or leaving either off.
fn detach_user_policy_parameters(user_name: Option<&str>, policy_arn: Option<&str>) -> String {
    user_policy_attachment_parameters("DetachUserPolicy", user_name, policy_arn)
}

/// Build the query parameters for a managed-policy attachment request, leaving off the
/// parameters the caller does not supply so that a request missing a required one can be
/// exercised.
///
/// The parameters are form-encoded rather than interpolated: a policy ARN carries colons and
/// slashes that the query string would otherwise be read as its own.
fn user_policy_attachment_parameters(action: &str, user_name: Option<&str>, policy_arn: Option<&str>) -> String {
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `PutUserPermissionsBoundary` request, naming a user and
/// the managed policy to impose as its boundary, or leaving either off.
///
/// The parameters are form-encoded rather than interpolated: a policy ARN carries colons and
/// slashes that the query string would otherwise be read as its own.
fn put_user_permissions_boundary_parameters(user_name: Option<&str>, permissions_boundary: Option<&str>) -> String {
    let mut parameters = vec![("Action", "PutUserPermissionsBoundary"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(permissions_boundary) = permissions_boundary {
        parameters.push(("PermissionsBoundary", permissions_boundary));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `DeleteUserPermissionsBoundary` request, naming a user or
/// leaving `UserName` off.
fn delete_user_permissions_boundary_parameters(user_name: Option<&str>) -> String {
    let mut parameters = vec![("Action", "DeleteUserPermissionsBoundary"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `TagUser` request, naming a user or leaving `UserName`
/// off, and carrying the tags to apply.
fn tag_user_parameters(user_name: Option<&str>, tags: &[(&str, &str)]) -> String {
    let mut parameters = action_parameters("TagUser");

    if let Some(user_name) = user_name {
        parameters.push(("UserName".to_string(), user_name.to_string()));
    }

    append_tag_parameters(&mut parameters, tags);
    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `UntagUser` request, naming a user or leaving `UserName`
/// off, and carrying the tag keys to remove.
fn untag_user_parameters(user_name: Option<&str>, tag_keys: &[&str]) -> String {
    let mut parameters = action_parameters("UntagUser");

    if let Some(user_name) = user_name {
        parameters.push(("UserName".to_string(), user_name.to_string()));
    }

    // A list of scalars is indexed the same way a list of structures is, with no field name
    // after the index.
    for (index, key) in tag_keys.iter().enumerate() {
        let index = index + 1;
        parameters.push((format!("TagKeys.member.{index}"), key.to_string()));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `CreateAccessKey` request, naming a user or leaving
/// `UserName` off so it defaults to the caller.
fn create_access_key_parameters(user_name: Option<&str>) -> String {
    let mut parameters = vec![("Action", "CreateAccessKey"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `DeleteAccessKey` request, naming an access key and the
/// user carrying it, or leaving either off.
fn delete_access_key_parameters(user_name: Option<&str>, access_key_id: Option<&str>) -> String {
    let mut parameters = vec![("Action", "DeleteAccessKey"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(access_key_id) = access_key_id {
        parameters.push(("AccessKeyId", access_key_id));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `UpdateAccessKey` request, naming an access key, the
/// user carrying it, and the state to assign it, or leaving any of them off.
///
/// `Status` is taken as a string rather than as a [`StatusType`](
/// scratchstack_shapes_iam::types::StatusType) so that a state this operation cannot assign --
/// or one that names no state at all -- can be exercised.
fn update_access_key_parameters(user_name: Option<&str>, access_key_id: Option<&str>, status: Option<&str>) -> String {
    let mut parameters = vec![("Action", "UpdateAccessKey"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(access_key_id) = access_key_id {
        parameters.push(("AccessKeyId", access_key_id));
    }
    if let Some(status) = status {
        parameters.push(("Status", status));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `UpdateUser` request, naming the user to update and the
/// new name and path to give it, leaving either replacement off.
fn update_user_parameters(user_name: Option<&str>, new_user_name: Option<&str>, new_path: Option<&str>) -> String {
    let mut parameters = vec![("Action", "UpdateUser"), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(new_user_name) = new_user_name {
        parameters.push(("NewUserName", new_user_name));
    }
    if let Some(new_path) = new_path {
        parameters.push(("NewPath", new_path));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `CreateRole` request naming the role to create and the trust
/// policy to attach to it, leaving off the parameters the caller does not supply so that a
/// request missing a required one can be exercised.
fn create_role_parameters(
    role_name: Option<&str>,
    assume_role_policy_document: Option<&str>,
    path: Option<&str>,
    description: Option<&str>,
    max_session_duration: Option<i32>,
    tags: &[(&str, &str)],
    permissions_boundary: Option<&str>,
) -> String {
    let mut parameters = action_parameters("CreateRole");

    if let Some(role_name) = role_name {
        parameters.push(("RoleName".to_string(), role_name.to_string()));
    }
    if let Some(assume_role_policy_document) = assume_role_policy_document {
        parameters.push(("AssumeRolePolicyDocument".to_string(), assume_role_policy_document.to_string()));
    }
    if let Some(path) = path {
        parameters.push(("Path".to_string(), path.to_string()));
    }
    if let Some(description) = description {
        parameters.push(("Description".to_string(), description.to_string()));
    }
    if let Some(max_session_duration) = max_session_duration {
        parameters.push(("MaxSessionDuration".to_string(), max_session_duration.to_string()));
    }

    append_tag_parameters(&mut parameters, tags);

    if let Some(permissions_boundary) = permissions_boundary {
        parameters.push(("PermissionsBoundary".to_string(), permissions_boundary.to_string()));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `GetRole` request naming a role, or leaving `RoleName` off.
fn get_role_parameters(role_name: Option<&str>) -> String {
    role_name_parameters("GetRole", role_name)
}

/// Build the query parameters for a `DeleteRole` request naming a role, or leaving `RoleName`
/// off.
fn delete_role_parameters(role_name: Option<&str>) -> String {
    role_name_parameters("DeleteRole", role_name)
}

/// Build the query parameters for a request whose only argument is the name of the role it acts
/// on, leaving `RoleName` off when the caller does not supply one so that a request missing it
/// can be exercised.
fn role_name_parameters(action: &str, role_name: Option<&str>) -> String {
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(role_name) = role_name {
        parameters.push(("RoleName", role_name));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `UpdateRole` request naming the role to update and the
/// description and maximum session duration to give it, leaving either replacement off.
fn update_role_parameters(
    role_name: Option<&str>,
    description: Option<&str>,
    max_session_duration: Option<i32>,
) -> String {
    let max_session_duration = max_session_duration.map(|duration| duration.to_string());
    let mut parameters = vec![("Action", "UpdateRole"), ("Version", "2010-05-08")];

    if let Some(role_name) = role_name {
        parameters.push(("RoleName", role_name));
    }
    if let Some(description) = description {
        parameters.push(("Description", description));
    }
    if let Some(max_session_duration) = max_session_duration.as_deref() {
        parameters.push(("MaxSessionDuration", max_session_duration));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `ListRoles` request, filtering by the path of the roles
/// reported and carrying the pagination arguments the caller supplies.
fn list_roles_parameters(path_prefix: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    list_parameters("ListRoles", None, path_prefix, max_items, marker)
}

/// Extract the `AssumeRolePolicyDocument` from a role response and percent-decode it, standing in
/// for the URL decoding a client applies.
fn decoded_trust_policy_document(body: &str) -> String {
    decoded_document_element(body, "AssumeRolePolicyDocument")
}

/// Build the query parameters for a `CreatePolicy` request naming the managed policy to create
/// and the document to store as its first version, leaving off the parameters the caller does not
/// supply so that a request missing a required one can be exercised.
fn create_policy_parameters(
    policy_name: Option<&str>,
    policy_document: Option<&str>,
    path: Option<&str>,
    description: Option<&str>,
    tags: &[(&str, &str)],
) -> String {
    let mut parameters = action_parameters("CreatePolicy");

    if let Some(policy_name) = policy_name {
        parameters.push(("PolicyName".to_string(), policy_name.to_string()));
    }
    if let Some(policy_document) = policy_document {
        parameters.push(("PolicyDocument".to_string(), policy_document.to_string()));
    }
    if let Some(path) = path {
        parameters.push(("Path".to_string(), path.to_string()));
    }
    if let Some(description) = description {
        parameters.push(("Description".to_string(), description.to_string()));
    }

    append_tag_parameters(&mut parameters, tags);
    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `GetPolicy` request naming a managed policy by ARN, or
/// leaving `PolicyArn` off.
fn get_policy_parameters(policy_arn: Option<&str>) -> String {
    policy_arn_parameters("GetPolicy", policy_arn)
}

/// Build the query parameters for a `DeletePolicy` request naming a managed policy by ARN, or
/// leaving `PolicyArn` off.
fn delete_policy_parameters(policy_arn: Option<&str>) -> String {
    policy_arn_parameters("DeletePolicy", policy_arn)
}

/// Build the query parameters for a request whose only argument is the ARN of the managed policy
/// it acts on, leaving `PolicyArn` off when the caller does not supply one so that a request
/// missing it can be exercised.
///
/// The parameters are form-encoded rather than interpolated: a policy ARN carries colons and
/// slashes that the query string would otherwise be read as its own.
fn policy_arn_parameters(action: &str, policy_arn: Option<&str>) -> String {
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `CreatePolicyVersion` request naming the policy to version
/// and the document to store as the new version, leaving off the parameters the caller does not
/// supply so that a request missing a required one can be exercised.
fn create_policy_version_parameters(
    policy_arn: Option<&str>,
    policy_document: Option<&str>,
    set_as_default: Option<bool>,
) -> String {
    let set_as_default = set_as_default.map(|set_as_default| set_as_default.to_string());
    let mut parameters = vec![("Action", "CreatePolicyVersion"), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }
    if let Some(policy_document) = policy_document {
        parameters.push(("PolicyDocument", policy_document));
    }
    if let Some(set_as_default) = set_as_default.as_deref() {
        parameters.push(("SetAsDefault", set_as_default));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `DeletePolicyVersion` request naming a policy and one of its
/// versions, or leaving either off.
fn delete_policy_version_parameters(policy_arn: Option<&str>, version_id: Option<&str>) -> String {
    policy_version_parameters("DeletePolicyVersion", policy_arn, version_id)
}

/// Build the query parameters for a `GetPolicyVersion` request naming a policy and one of its
/// versions, or leaving either off.
fn get_policy_version_parameters(policy_arn: Option<&str>, version_id: Option<&str>) -> String {
    policy_version_parameters("GetPolicyVersion", policy_arn, version_id)
}

/// Build the query parameters for a request naming a managed policy and one of its versions,
/// leaving off the parameters the caller does not supply so that a request missing a required one
/// can be exercised.
///
/// `version_id` is taken as a string rather than as a version number so that something that is
/// not a version id at all can be exercised.
fn policy_version_parameters(action: &str, policy_arn: Option<&str>, version_id: Option<&str>) -> String {
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }
    if let Some(version_id) = version_id {
        parameters.push(("VersionId", version_id));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `SetDefaultPolicyVersion` request naming a policy and the
/// version to make its default, or leaving either off.
fn set_default_policy_version_parameters(policy_arn: Option<&str>, version_id: Option<&str>) -> String {
    policy_version_parameters("SetDefaultPolicyVersion", policy_arn, version_id)
}

/// Build the query parameters for a `TagPolicy` request naming a policy, or leaving `PolicyArn`
/// off, and carrying the tags to apply.
fn tag_policy_parameters(policy_arn: Option<&str>, tags: &[(&str, &str)]) -> String {
    let mut parameters = action_parameters("TagPolicy");

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn".to_string(), policy_arn.to_string()));
    }

    append_tag_parameters(&mut parameters, tags);
    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for an `UntagPolicy` request naming a policy, or leaving `PolicyArn`
/// off, and carrying the tag keys to remove.
fn untag_policy_parameters(policy_arn: Option<&str>, tag_keys: &[&str]) -> String {
    let mut parameters = action_parameters("UntagPolicy");

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn".to_string(), policy_arn.to_string()));
    }

    // A list of scalars is indexed the same way a list of structures is, with no field name
    // after the index.
    for (index, key) in tag_keys.iter().enumerate() {
        let index = index + 1;
        parameters.push((format!("TagKeys.member.{index}"), key.to_string()));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `ListPolicyTags` request naming a policy, or leaving
/// `PolicyArn` off, and carrying the pagination arguments the caller supplies.
fn list_policy_tags_parameters(policy_arn: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    let max_items = max_items.map(|max_items| max_items.to_string());
    let mut parameters = vec![("Action", "ListPolicyTags"), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }
    if let Some(max_items) = max_items.as_deref() {
        parameters.push(("MaxItems", max_items));
    }
    if let Some(marker) = marker {
        parameters.push(("Marker", marker));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `ListEntitiesForPolicy` request naming a policy, or leaving
/// `PolicyArn` off, and carrying the filters and pagination arguments the caller supplies.
///
/// `entity_filter` and `policy_usage_filter` are taken as strings rather than as the enumerations
/// they name so that a value neither one defines can be exercised.
fn list_entities_for_policy_parameters(
    policy_arn: Option<&str>,
    entity_filter: Option<&str>,
    path_prefix: Option<&str>,
    policy_usage_filter: Option<&str>,
    max_items: Option<i32>,
    marker: Option<&str>,
) -> String {
    let max_items = max_items.map(|max_items| max_items.to_string());
    let mut parameters = vec![("Action", "ListEntitiesForPolicy"), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }
    if let Some(entity_filter) = entity_filter {
        parameters.push(("EntityFilter", entity_filter));
    }
    if let Some(path_prefix) = path_prefix {
        parameters.push(("PathPrefix", path_prefix));
    }
    if let Some(policy_usage_filter) = policy_usage_filter {
        parameters.push(("PolicyUsageFilter", policy_usage_filter));
    }
    if let Some(max_items) = max_items.as_deref() {
        parameters.push(("MaxItems", max_items));
    }
    if let Some(marker) = marker {
        parameters.push(("Marker", marker));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `ListPolicyVersions` request naming a policy, or leaving
/// `PolicyArn` off, and carrying the pagination arguments the caller supplies.
fn list_policy_versions_parameters(policy_arn: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    let max_items = max_items.map(|max_items| max_items.to_string());
    let mut parameters = vec![("Action", "ListPolicyVersions"), ("Version", "2010-05-08")];

    if let Some(policy_arn) = policy_arn {
        parameters.push(("PolicyArn", policy_arn));
    }
    if let Some(max_items) = max_items.as_deref() {
        parameters.push(("MaxItems", max_items));
    }
    if let Some(marker) = marker {
        parameters.push(("Marker", marker));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Build the query parameters for a `ListPolicies` request, carrying the filters and the
/// pagination arguments the caller supplies.
///
/// `scope` and `policy_usage_filter` are taken as strings rather than as the enumerations they
/// name so that a value neither one defines can be exercised.
fn list_policies_parameters(
    scope: Option<&str>,
    path_prefix: Option<&str>,
    only_attached: Option<bool>,
    policy_usage_filter: Option<&str>,
    max_items: Option<i32>,
    marker: Option<&str>,
) -> String {
    let max_items = max_items.map(|max_items| max_items.to_string());
    let only_attached = only_attached.map(|only_attached| only_attached.to_string());
    let mut parameters = vec![("Action", "ListPolicies"), ("Version", "2010-05-08")];

    if let Some(scope) = scope {
        parameters.push(("Scope", scope));
    }
    if let Some(path_prefix) = path_prefix {
        parameters.push(("PathPrefix", path_prefix));
    }
    if let Some(only_attached) = only_attached.as_deref() {
        parameters.push(("OnlyAttached", only_attached));
    }
    if let Some(policy_usage_filter) = policy_usage_filter {
        parameters.push(("PolicyUsageFilter", policy_usage_filter));
    }
    if let Some(max_items) = max_items.as_deref() {
        parameters.push(("MaxItems", max_items));
    }
    if let Some(marker) = marker {
        parameters.push(("Marker", marker));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Start the parameter list for a request invoking `action`, for the builders whose
/// parameters carry indexed names and so cannot borrow them.
///
/// Every builder here finishes by form-encoding the pairs it collected rather than
/// interpolating them into a query string. Interpolating is wrong for more inputs than it
/// looks: the service decodes its parameters with form decoding, so a `+` -- legal in a user
/// name, a path, a tag key, and a tag value alike -- arrives as a space, and an `&` in a tag
/// value ends the value early and starts a parameter of its own. A request built that way
/// names something other than what the test asked for, and the assertion that follows is
/// measuring the wrong request.
fn action_parameters(action: &str) -> Vec<(String, String)> {
    vec![("Action".to_string(), action.to_string()), ("Version".to_string(), "2010-05-08".to_string())]
}

/// Append the parameters naming `tags` to a parameter list being built.
///
/// Lists arrive in the query string indexed under a `member` segment, one parameter per
/// field, as the AWS query protocol spells them.
fn append_tag_parameters(parameters: &mut Vec<(String, String)>, tags: &[(&str, &str)]) {
    for (index, (key, value)) in tags.iter().enumerate() {
        let index = index + 1;
        parameters.push((format!("Tags.member.{index}.Key"), key.to_string()));
        parameters.push((format!("Tags.member.{index}.Value"), value.to_string()));
    }
}

/// Build the query parameters for a `ListAccessKeys` request, naming a user or leaving
/// `UserName` off so it defaults to the caller, and carrying the pagination arguments the
/// caller supplies.
fn list_access_keys_parameters(user_name: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    list_parameters("ListAccessKeys", user_name, None, max_items, marker)
}

/// Build the query parameters for a `ListAttachedUserPolicies` request, naming a user or
/// leaving `UserName` off, filtering by the path of the policies reported, and carrying the
/// pagination arguments the caller supplies.
fn list_attached_user_policies_parameters(
    user_name: Option<&str>,
    path_prefix: Option<&str>,
    max_items: Option<i32>,
    marker: Option<&str>,
) -> String {
    list_parameters("ListAttachedUserPolicies", user_name, path_prefix, max_items, marker)
}

/// Build the query parameters for a `ListUserPolicies` request, naming a user or leaving
/// `UserName` off, and carrying the pagination arguments the caller supplies.
fn list_user_policies_parameters(user_name: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    list_parameters("ListUserPolicies", user_name, None, max_items, marker)
}

/// Build the query parameters for a `ListUserTags` request, naming a user or leaving
/// `UserName` off, and carrying the pagination arguments the caller supplies.
fn list_user_tags_parameters(user_name: Option<&str>, max_items: Option<i32>, marker: Option<&str>) -> String {
    list_parameters("ListUserTags", user_name, None, max_items, marker)
}

/// Build the query parameters for a paginated listing request, leaving off the parameters the
/// caller does not supply so that a request missing a required one can be exercised. A listing
/// that takes no path prefix passes `None`.
///
/// Every parameter is form-encoded rather than interpolated. A pagination token is opaque and
/// nothing here relies on what it happens to be made of; a path carries slashes, and may carry
/// a `+`, which the service decodes as a space rather than as itself -- a request built by
/// interpolation would arrive naming something other than what the test asked for.
fn list_parameters(
    action: &str,
    user_name: Option<&str>,
    path_prefix: Option<&str>,
    max_items: Option<i32>,
    marker: Option<&str>,
) -> String {
    let max_items = max_items.map(|max_items| max_items.to_string());
    let mut parameters = vec![("Action", action), ("Version", "2010-05-08")];

    if let Some(user_name) = user_name {
        parameters.push(("UserName", user_name));
    }
    if let Some(path_prefix) = path_prefix {
        parameters.push(("PathPrefix", path_prefix));
    }
    if let Some(max_items) = max_items.as_deref() {
        parameters.push(("MaxItems", max_items));
    }
    if let Some(marker) = marker {
        parameters.push(("Marker", marker));
    }

    serde_urlencoded::to_string(parameters).expect("failed to encode parameters")
}

/// Extract the `AccessKeyId` a response reports, to be named by the operations acting on that
/// key afterwards.
///
/// An access key id is alphanumeric, so what is between the tags is the id itself: there is
/// nothing in it for the response serializer to escape. A `CreateAccessKey` response carries
/// exactly one, and a listing's first is the first key it reports.
fn access_key_id(body: &str) -> String {
    const OPEN: &str = "<AccessKeyId>";
    const CLOSE: &str = "</AccessKeyId>";

    let start = body.find(OPEN).expect("no AccessKeyId in body") + OPEN.len();
    let end = start + body[start..].find(CLOSE).expect("unterminated AccessKeyId");

    body[start..end].to_string()
}

/// Extract the `Marker` a truncated listing reports, to be handed back as the next page's
/// `Marker` parameter.
///
/// A pagination token is a version character followed by URL-safe base64, so what is between
/// the tags is the token itself: there is nothing in it for the response serializer to escape.
fn pagination_marker(body: &str) -> String {
    const OPEN: &str = "<Marker>";
    const CLOSE: &str = "</Marker>";

    let start = body.find(OPEN).expect("no Marker in body") + OPEN.len();
    let end = start + body[start..].find(CLOSE).expect("unterminated Marker");

    body[start..end].to_string()
}

/// A copy of `svc_state` configured to believe the `X-Forwarded-For` header of proxies in
/// `10.0.0.0/8`, standing in for a deployment behind a load balancer.
fn proxied_state(svc_state: &ServiceState) -> ServiceState {
    let forwarded_for = ForwardedForConfig::builder()
        .trusted_proxies(vec!["10.0.0.0/8".to_string()])
        .build()
        .resolve()
        .expect("failed to resolve forwarded_for configuration");

    ServiceState::builder()
        .db(svc_state.db.clone())
        .forwarded_for(Arc::new(forwarded_for))
        .secure_transport(true)
        .build()
}

/// Invoke `serve_request` directly with the given identity and return the status and body.
async fn call(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    parameters: &str,
) -> (StatusCode, String) {
    call_as(
        svc_state,
        principal,
        session_data,
        SessionPolicies::default(),
        TEST_SOURCE_IP,
        HeaderMap::new(),
        parameters,
    )
    .await
}

/// Invoke `serve_request` directly with the given identity and session policies and return
/// the status and body.
async fn call_with_session_policies(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    parameters: &str,
) -> (StatusCode, String) {
    call_as(svc_state, principal, session_data, session_policies, TEST_SOURCE_IP, HeaderMap::new(), parameters).await
}

/// Invoke `serve_request` directly with the given identity from the given peer address and
/// return the status and body.
async fn call_from(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    source_ip: IpAddr,
    parameters: &str,
) -> (StatusCode, String) {
    call_as(svc_state, principal, session_data, SessionPolicies::default(), source_ip, HeaderMap::new(), parameters)
        .await
}

/// Invoke `serve_request` directly for a request carrying the given headers.
async fn call_with_headers(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    headers: HeaderMap,
    parameters: &str,
) -> (StatusCode, String) {
    call_as(svc_state, principal, session_data, SessionPolicies::default(), TEST_SOURCE_IP, headers, parameters).await
}

/// Build a header map carrying a `Referer`, a `User-Agent`, or both.
fn client_headers(referer: Option<&str>, user_agent: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(referer) = referer {
        headers.append("referer", referer.parse().expect("invalid header value"));
    }
    if let Some(user_agent) = user_agent {
        headers.append("user-agent", user_agent.parse().expect("invalid header value"));
    }
    headers
}

/// Invoke `serve_request` directly for a request that arrived from `source_ip` carrying
/// `forwarded_for` in its `X-Forwarded-For` header.
async fn call_forwarded(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    source_ip: IpAddr,
    forwarded_for: &str,
    parameters: &str,
) -> (StatusCode, String) {
    let mut headers = HeaderMap::new();
    headers.append("x-forwarded-for", forwarded_for.parse().expect("invalid header value"));

    call_as(svc_state, principal, session_data, SessionPolicies::default(), source_ip, headers, parameters).await
}

/// Invoke `serve_request` directly with every facet of the request spelled out, standing in
/// for the connection information and identity the pipeline would otherwise supply.
#[allow(clippy::too_many_arguments)]
async fn call_as(
    svc_state: &ServiceState,
    principal: Principal,
    session_data: SessionData,
    session_policies: SessionPolicies,
    source_ip: IpAddr,
    headers: HeaderMap,
    parameters: &str,
) -> (StatusCode, String) {
    let response: Response<Body> = serve_request(
        State(svc_state.clone()),
        RequestId::new(),
        Some(Extension(ConnectInfo(SocketAddr::new(source_ip, 49152)))),
        headers,
        Extension(principal),
        Extension(session_data),
        Extension(session_policies),
        RawQuery(None),
        Bytes::from(parameters.as_bytes().to_vec()),
    )
    .await;

    let status = response.status();
    let body = response.into_body().collect().await.expect("failed to read body").to_bytes();
    (status, String::from_utf8(body.to_vec()).expect("body is not UTF-8"))
}

/// The embedded PostgreSQL instance -- and the one migrated database on it -- the service
/// tests share.
///
/// Starting an instance costs a couple of seconds and migrating a database another second, both
/// far more than the tests that run against them. The first test to ask for a database starts
/// the instance, migrates `scratchstack_iam` once, and records the partition every test reads;
/// the rest is shut down once the last test holding a [`TestDatabase`] is done. Holding a
/// [`Weak`] is what gives that its timing: it keeps the running instance reachable without
/// keeping it alive.
static SHARED_SERVER: LazyLock<Mutex<Weak<TempDatabase>>> = LazyLock::new(|| Mutex::new(Weak::new()));

/// Hands out the account id each test is seeded into.
static TEST_ACCOUNT_COUNT: AtomicU64 = AtomicU64::new(0);

/// One test's seeded account in the shared database.
///
/// The tests share a database rather than taking one apiece, so they are held apart by account
/// instead: each is seeded into an account of its own, and every IAM read is scoped to the
/// account of the caller making it. Keeping the handle alive keeps the instance running, so it
/// has to outlive the requests made against the [`ServiceState`] it hands out.
///
/// What the tests still share, beyond the schema, is the row in `iam.partition` and the
/// AWS-managed policies in account `000000000000`, neither of which belongs to any one account.
/// Tests seeding an AWS-managed policy have to keep its name distinct from every other test's.
struct TestDatabase {
    /// The account this test's seed data was loaded into.
    account_id: String,

    /// The state to serve requests against.
    ///
    /// This *must* be before `server` so that the pool it holds is dropped before the instance
    /// that pool connects to is stopped.
    svc_state: ServiceState,

    /// The shared instance this test's account lives on.
    ///
    /// Nothing reads this: it is held so that the instance outlives the handle, and stops once
    /// the last handle is dropped.
    #[allow(dead_code)]
    server: Arc<TempDatabase>,
}

impl TestDatabase {
    /// Claim an account on the shared database -- starting and migrating it if no other test is
    /// currently holding it -- and load `test_data` into that account.
    ///
    /// `test_data` names the account as [`ACCOUNT_ID_PLACEHOLDER`] wherever it means "this
    /// test's account", which is substituted here. Account ids it spells out literally are left
    /// alone, since those name accounts the test is deliberately not in.
    async fn new(test_data: &str) -> Self {
        let server = shared_server().await;
        let account_id = format!("{:012}", FIRST_TEST_ACCOUNT_ID + TEST_ACCOUNT_COUNT.fetch_add(1, Ordering::Relaxed));

        let pool = server
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");
        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        raw_sql(AssertSqlSafe(test_data.replace(ACCOUNT_ID_PLACEHOLDER, &account_id)))
            .execute(&mut *c)
            .await
            .expect("Failed to load test data into database");
        drop(c);

        Self {
            account_id,
            svc_state: ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build(),
            server,
        }
    }

    /// The account this test's seed data was loaded into, and the account its callers are in.
    fn account_id(&self) -> &str {
        &self.account_id
    }

    /// An ARN in this test's account, from the part after the account id -- `policy/Admin-Policy`,
    /// `user/Broad-Reader`, and so on.
    fn arn(&self, resource: &str) -> String {
        format!("arn:aws:iam::{}:{resource}", self.account_id)
    }

    /// The service state requests against this database are served with.
    fn svc_state(&self) -> &ServiceState {
        &self.svc_state
    }

    /// Build the principal and session data the SigV4 layer would produce for a seeded user.
    fn user_identity(&self, user_id: &str, user_name: &str) -> (Principal, SessionData) {
        let principal = Principal::from(
            User::builder()
                .partition("aws")
                .account_id(&self.account_id)
                .path("/")
                .user_name(user_name)
                .build()
                .expect("failed to build user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(self.account_id.clone()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:iam::{}:user/{user_name}", self.account_id)),
        );
        session_data.insert("aws:userid", SessionValue::String(format!("AIDA{user_id}")));
        session_data.insert("aws:username", SessionValue::String(user_name.to_string()));
        session_data.insert("aws:PrincipalType", SessionValue::String("User".to_string()));
        session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
        session_data.insert("aws:RequestedRegion", SessionValue::String(TEST_REGION.to_string()));
        session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));
        (principal, session_data)
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role, issued just now.
    fn role_identity(&self, role_id: &str, role_name: &str) -> (Principal, SessionData) {
        self.role_identity_issued_at(role_id, role_name, Utc::now())
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role that `sts:AssumeRole` minted at `issued_at`.
    ///
    /// The keys here mirror the session metadata `AssumeRole` records in the session token, which
    /// the signing-key provider hands back verbatim as the session data for a request signed with
    /// the resulting temporary credentials.
    fn role_identity_issued_at(
        &self,
        role_id: &str,
        role_name: &str,
        issued_at: DateTime<Utc>,
    ) -> (Principal, SessionData) {
        let principal = Principal::from(
            AssumedRole::builder()
                .partition("aws")
                .account_id(&self.account_id)
                .role_name(role_name)
                .session_name("test-session")
                .build()
                .expect("failed to build assumed role"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(self.account_id.clone()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:sts::{}:assumed-role/{role_name}/test-session", self.account_id)),
        );
        session_data.insert("aws:userid", SessionValue::String(format!("AROA{role_id}:test-session")));
        session_data.insert("aws:PrincipalType", SessionValue::String("AssumedRole".to_string()));
        session_data.insert("aws:MultiFactorAuthPresent", SessionValue::Bool(false));
        session_data.insert("aws:PrincipalIsAWSService", SessionValue::Bool(false));
        session_data.insert("aws:RequestedRegion", SessionValue::String(TEST_REGION.to_string()));
        session_data.insert("aws:TokenIssueTime", SessionValue::Timestamp(issued_at));
        session_data.insert("aws:ViaAWSService", SessionValue::Bool(false));
        (principal, session_data)
    }

    /// Build the principal and session data the SigV4 layer would produce for the account root
    /// user.
    fn root_identity(&self) -> (Principal, SessionData) {
        let principal = Principal::from(
            RootUser::builder()
                .partition("aws")
                .account_id(&self.account_id)
                .build()
                .expect("failed to build root user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(self.account_id.clone()));
        (principal, session_data)
    }
}

/// Return the shared PostgreSQL instance, starting, bootstrapping and migrating one if no test
/// currently holds it.
///
/// The lock is held across the startup so that tests arriving while an instance is coming up
/// wait for it rather than starting instances of their own.
async fn shared_server() -> Arc<TempDatabase> {
    let mut shared = SHARED_SERVER.lock().await;

    if let Some(server) = shared.upgrade() {
        return server;
    }

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");

    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");
    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");

    // Every test reads this and none of them owns it, so it is recorded once here rather than by
    // the seed data. The service fails any request unless the table holds exactly one row.
    raw_sql("INSERT INTO iam.partition(partition) VALUES ('aws');")
        .execute(&mut *c)
        .await
        .expect("Failed to record the partition");
    drop(c);

    // This pool belongs to the runtime of whichever test got here first, which is gone once that
    // test ends; close it now rather than leaving connections behind for the server to reap.
    pool.close().await;

    let server = Arc::new(database);
    *shared = Arc::downgrade(&server);
    server
}
