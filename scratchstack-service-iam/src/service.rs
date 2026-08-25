use {
    crate::{
        constants::*,
        operations::{
            create_user, delete_user, delete_user_policy, get_user, get_user_policy, list_users, put_user_policy,
            tag_user, untag_user,
        },
    },
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_aws_signature::SessionPolicies,
    scratchstack_core::{
        RequestId,
        axum::{
            body::{Body, Bytes},
            extract::{ConnectInfo, Extension, RawQuery, State},
            http::HeaderMap,
            response::Response,
        },
        response::Responder as _,
    },
    scratchstack_service_common::query::{join_parameters, scan_action_version},
    scratchstack_shapes_iam::{
        action::{Action, VERSION as IAM_VERSION},
        types::error::{InternalFailure, InvalidAction, MalformedInput},
    },
    std::{net::SocketAddr, str::from_utf8},
};

pub(crate) use scratchstack_service_common::{RequestMetadata, ServiceState};

// A handler's parameters are its extractors: each one pulls a different piece of the request out
// of the pipeline, so there is nothing to bundle.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_request(
    State(svc_state): State<ServiceState>,
    request_id: RequestId,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Extension(principal): Extension<Principal>,
    Extension(session_data): Extension<SessionData>,
    Extension(session_policies): Extension<SessionPolicies>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response<Body> {
    // Policies may be conditioned on the connection the request arrived on, and a missing
    // aws:SourceIp silently satisfies a NotIpAddress condition; a request whose peer address is
    // unknown cannot be evaluated safely, so fail closed.
    let Some(request_metadata) = RequestMetadata::from_request(
        svc_state.secure_transport,
        svc_state.forwarded_for.as_deref(),
        connect_info,
        &headers,
    ) else {
        log::error!("{request_id}: Request carries no connection information");
        return internal_failure(request_id);
    };

    let body = match from_utf8(&body) {
        Ok(body) => body,
        Err(e) => {
            log::debug!("{request_id}: Request body is not valid UTF-8: {e}");
            return malformed_input(request_id);
        }
    };

    let parameters = join_parameters(query.as_deref().unwrap_or_default(), body);
    let (action, version) = scan_action_version(&parameters);

    if version != IAM_VERSION {
        return invalid_action(request_id, &action, &version);
    }

    match action.parse::<Action>() {
        Ok(Action::CreateUser) => {
            create_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::DeleteUser) => {
            delete_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::DeleteUserPolicy) => {
            delete_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::GetUser) => {
            get_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::GetUserPolicy) => {
            get_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::ListUsers) => {
            list_users(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::PutUserPolicy) => {
            put_user_policy(
                svc_state,
                request_id,
                principal,
                session_data,
                session_policies,
                request_metadata,
                &parameters,
            )
            .await
        }
        Ok(Action::TagUser) => {
            tag_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        Ok(Action::UntagUser) => {
            untag_user(svc_state, request_id, principal, session_data, session_policies, request_metadata, &parameters)
                .await
        }
        _ => invalid_action(request_id, &action, &version),
    }
}

/// Generate an `InternalFailure` error response.
pub(crate) fn internal_failure(request_id: RequestId) -> Response<Body> {
    InternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().respond()
}

/// Generate an `InvalidAction` error response.
fn invalid_action(request_id: RequestId, action: &str, version: &str) -> Response<Body> {
    InvalidAction::builder()
        .message(format!("Could not find operation {action} for version {version}"))
        .request_id(request_id)
        .build()
        .respond()
}

/// Generate a `MalformedInput` error response.
///
/// IAM does not report a message with this error, so neither do we.
pub(crate) fn malformed_input(request_id: RequestId) -> Response<Body> {
    MalformedInput::builder().request_id(request_id).build().respond()
}

#[cfg(test)]
mod tests {
    use {
        super::{ServiceState, serve_request},
        chrono::{DateTime, Utc},
        http_body_util::BodyExt as _,
        pct_str::PctStr,
        pretty_assertions::assert_eq,
        scratchstack_aspen::Policy as AspenPolicy,
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
        sqlx::raw_sql,
        std::{
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
            str::FromStr as _,
            sync::Arc,
        },
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";

    /// The region test requests are signed for; the signing-key provider records it as
    /// `aws:RequestedRegion` for both long-term and temporary credentials.
    const TEST_REGION: &str = "us-east-1";

    /// The peer address test requests arrive from unless a test names another, backing the
    /// `aws:SourceIp` condition key. The addresses used here come from the documentation ranges
    /// reserved by RFC 5737 and RFC 3849.
    const TEST_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

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
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'authz-test@example.com', 'authz-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCTESTALLOWUSER', '123456789012', 'allowed-user', 'Allowed-User', '/'),
        ('SVCTESTDENYUSER1', '123456789012', 'denied-user', 'Denied-User', '/'),
        ('SVCTESTTLSUSER01', '123456789012', 'tls-user', 'Tls-User', '/'),
        ('SVCTESTTIMEUSER1', '123456789012', 'time-user', 'Time-User', '/'),
        ('SVCTESTPASTUSER1', '123456789012', 'past-user', 'Past-User', '/'),
        ('SVCTESTEPOCHUSR1', '123456789012', 'epoch-user', 'Epoch-User', '/'),
        ('SVCTESTIPV4USER1', '123456789012', 'ipv4-user', 'Ipv4-User', '/'),
        ('SVCTESTIPV6USER1', '123456789012', 'ipv6-user', 'Ipv6-User', '/'),
        ('SVCTESTDENYIPUSR', '123456789012', 'deny-ip-user', 'Deny-Ip-User', '/'),
        ('SVCTESTTOKENUSER', '123456789012', 'token-user', 'Token-User', '/'),
        ('SVCTESTREGIONUSR', '123456789012', 'region-user', 'Region-User', '/'),
        ('SVCTESTOTHERRGN1', '123456789012', 'other-region-user', 'Other-Region-User', '/'),
        ('SVCTESTDIRECTUSR', '123456789012', 'direct-call-user', 'Direct-Call-User', '/'),
        ('SVCTESTAGENTUSR1', '123456789012', 'agent-user', 'Agent-User', '/'),
        ('SVCTESTACCTUSER1', '123456789012', 'account-user', 'Account-User', '/'),
        ('SVCTESTOTHRACCT1', '123456789012', 'other-account-user', 'Other-Account-User', '/');

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
           "Condition":{"StringEquals":{"aws:ResourceAccount":"123456789012"}}}]}'),
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
        ('SVCTESTROLE00001', '123456789012', 'session-role', 'Session-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTTOKENROLE', '123456789012', 'token-role', 'Token-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTRGNROLE01', '123456789012', 'region-role', 'Region-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'),
        ('SVCTESTDIRROLE01', '123456789012', 'direct-call-role', 'Direct-Call-Role', '/',
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
        ('SVCTESTSESSPOL01', '123456789012', 'session-allow-iam', 'Session-Allow-Iam', '/', 1, false, 1);

        INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
        ('SVCTESTSESSPOL01', 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}');
    "#;

    /// Seed data for the `GetUser` authorization tests. The users being read carry the paths and
    /// tags the resource ARN and the `aws:ResourceTag`/`iam:ResourceTag` condition keys are
    /// derived from; the callers carry grants scoped by principal variable, by resource path, and
    /// by resource tag.
    const GET_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'get-user-test@example.com', 'get-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCGETUSERSELF01', '123456789012', 'self-user', 'Self-User', '/'),
        ('SVCGETUSERPATH01', '123456789012', 'path-user', 'Path-User', '/'),
        ('SVCGETUSERTAG001', '123456789012', 'tag-user', 'Tag-User', '/'),
        ('SVCGETUSERIAMTG1', '123456789012', 'iam-tag-user', 'Iam-Tag-User', '/'),
        ('SVCGETUSERBROAD1', '123456789012', 'broad-user', 'Broad-User', '/'),
        ('SVCGETUSERNARROW', '123456789012', 'narrow-user', 'Narrow-User', '/'),
        ('SVCGETUSERDIVSN1', '123456789012', 'division-user', 'Division-User', '/division/'),
        ('SVCGETUSERENGNR1', '123456789012', 'engineering-user', 'Engineering-User', '/'),
        ('SVCGETUSERSALES1', '123456789012', 'sales-user', 'Sales-User', '/'),
        ('SVCGETUSRACCT001', '123456789012', 'account-user', 'Account-User', '/'),
        ('SVCGETUSRACCT002', '123456789012', 'other-account-user', 'Other-Account-User', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCGETUSERENGNR1', 'department', 'Department', 'Engineering'),
        ('SVCGETUSERSALES1', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGETUSERSELF01', 'allow-get-self', 'Allow-Get-Self',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/${aws:username}"}]}'),
        ('SVCGETUSERPATH01', 'allow-get-division', 'Allow-Get-Division',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCGETUSERTAG001', 'allow-get-engineering', 'Allow-Get-Engineering',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCGETUSERIAMTG1', 'allow-get-engineering-iam', 'Allow-Get-Engineering-Iam',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"iam:ResourceTag/Department":"Engineering"}}}]}'),
        ('SVCGETUSERBROAD1', 'allow-get-any', 'Allow-Get-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}'),
        ('SVCGETUSRACCT001', 'allow-get-in-own-account', 'Allow-Get-In-Own-Account',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceAccount":"123456789012"}}}]}'),
        ('SVCGETUSRACCT002', 'allow-get-in-other-account', 'Allow-Get-In-Other-Account',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceAccount":"210987654321"}}}]}'),
        ('SVCGETUSERNARROW', 'allow-get-broad-user', 'Allow-Get-Broad-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser",
           "Resource":"arn:aws:iam::123456789012:user/Broad-User"}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
        ('SVCGETUSERROLE01', '123456789012', 'get-user-role', 'Get-User-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

        INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGETUSERROLE01', 'allow-get-any', 'Allow-Get-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}]}');
    "#;

    /// Seed data for the `CreateUser` authorization tests. The callers carry grants scoped by the
    /// path the new user is created under, by the tags the request asks to apply, by the tag keys
    /// it may name at all, and by the permissions boundary it asks to attach; `Boundary-Policy` is
    /// the managed policy the boundary-scoped grant names. `Create-Only-Creator` is allowed
    /// `iam:CreateUser` and nothing else, so it shows that tagging a user at creation is gated
    /// separately while attaching a permissions boundary is not.
    const CREATE_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'create-user-test@example.com', 'create-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCCREUSERBROAD', '123456789012', 'broad-creator', 'Broad-Creator', '/'),
        ('SVCCREUSERPATH1', '123456789012', 'path-creator', 'Path-Creator', '/'),
        ('SVCCREUSERTAG01', '123456789012', 'tag-creator', 'Tag-Creator', '/'),
        ('SVCCREUSERKEYS1', '123456789012', 'tag-key-creator', 'Tag-Key-Creator', '/'),
        ('SVCCREUSERPB001', '123456789012', 'boundary-creator', 'Boundary-Creator', '/'),
        ('SVCCREUSERNONE1', '123456789012', 'no-grant-creator', 'No-Grant-Creator', '/'),
        ('SVCCREUSERONLY1', '123456789012', 'create-only-creator', 'Create-Only-Creator', '/'),
        ('SVCCREUSERARN01', '123456789012', 'arn-boundary-creator', 'Arn-Boundary-Creator', '/'),
        ('SVCCREUSEREXIST', '123456789012', 'existing-user', 'Existing-User', '/');

        INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower,
            managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
        ('SVCCREUSERBND01', '123456789012', 'boundary-policy', 'Boundary-Policy', '/', 1, false, 1);

        INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
        ('SVCCREUSERBND01', 1,
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCCREUSERBROAD', 'allow-create-any', 'Allow-Create-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
           "Resource":"*"}]}'),
        ('SVCCREUSERPATH1', 'allow-create-in-division', 'Allow-Create-In-Division',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCCREUSERTAG01', 'allow-create-engineering', 'Allow-Create-Engineering',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
           "Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
        ('SVCCREUSERKEYS1', 'allow-create-with-known-tags', 'Allow-Create-With-Known-Tags',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],
           "Resource":"*","Condition":{"ForAllValues:StringEquals":
             {"aws:TagKeys":["Department","Project"]}}}]}'),
        ('SVCCREUSERPB001', 'allow-create-with-boundary', 'Allow-Create-With-Boundary',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*",
           "Condition":{"StringEquals":
             {"iam:PermissionsBoundary":"arn:aws:iam::123456789012:policy/Boundary-Policy"}}}]}'),
        ('SVCCREUSERONLY1', 'allow-create-only', 'Allow-Create-Only',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}]}'),
        ('SVCCREUSERARN01', 'allow-create-with-arn-boundary', 'Allow-Create-With-Arn-Boundary',
         '{"Version":"2012-10-17","Statement":[{"Sid":"VisualEditor0","Effect":"Allow","Action":"iam:CreateUser",
           "Resource":"*","Condition":{"ArnEquals":
             {"iam:PermissionsBoundary":"arn:aws:iam::123456789012:policy/Boundary-Policy"}}}]}');
    "#;

    /// Seed data for the `DeleteUser` authorization tests. The users being deleted carry the paths
    /// and tags the resource ARN and the `aws:ResourceTag` condition keys are derived from, and
    /// `Policy-Holder` owns an inline policy that blocks its deletion.
    const DELETE_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'delete-user-test@example.com', 'delete-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCDELUSERBROAD', '123456789012', 'broad-deleter', 'Broad-Deleter', '/'),
        ('SVCDELUSERPATH1', '123456789012', 'path-deleter', 'Path-Deleter', '/'),
        ('SVCDELUSERTAG01', '123456789012', 'tag-deleter', 'Tag-Deleter', '/'),
        ('SVCDELUSERNARRW', '123456789012', 'narrow-deleter', 'Narrow-Deleter', '/'),
        ('SVCDELUSERTGT01', '123456789012', 'delete-me', 'Delete-Me', '/'),
        ('SVCDELUSERTGT02', '123456789012', 'delete-me-too', 'Delete-Me-Too', '/'),
        ('SVCDELUSERTGT03', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCDELUSERTGT04', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCDELUSERTGT05', '123456789012', 'sales-target', 'Sales-Target', '/'),
        ('SVCDELUSERTGT06', '123456789012', 'policy-holder', 'Policy-Holder', '/'),
        ('SVCDELUSERTGT07', '123456789012', 'root-target', 'Root-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCDELUSERTGT04', 'department', 'Department', 'Engineering'),
        ('SVCDELUSERTGT05', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCDELUSERBROAD', 'allow-delete-any', 'Allow-Delete-Any',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:DeleteUser","iam:GetUser"],
           "Resource":"*"}]}'),
        ('SVCDELUSERPATH1', 'allow-delete-in-division', 'Allow-Delete-In-Division',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCDELUSERTAG01', 'allow-delete-engineering', 'Allow-Delete-Engineering',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCDELUSERNARRW', 'allow-delete-one-user', 'Allow-Delete-One-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUser",
           "Resource":"arn:aws:iam::123456789012:user/Delete-Me-Too"}]}'),
        ('SVCDELUSERTGT06', 'keep-me', 'Keep-Me',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
    "#;

    /// Seed data for the `GetUserPolicy` authorization tests. `Policy-Holder` carries two inline
    /// policies, so a grant reaching the user can be shown to reach both; the other targets carry
    /// the paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived
    /// from.
    const GET_USER_POLICY_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'get-user-policy-test@example.com', 'get-user-policy-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCGUPBROADRDR01', '123456789012', 'broad-reader', 'Broad-Reader', '/'),
        ('SVCGUPPATHRDR001', '123456789012', 'path-reader', 'Path-Reader', '/'),
        ('SVCGUPTAGRDR0001', '123456789012', 'tag-reader', 'Tag-Reader', '/'),
        ('SVCGUPNARROWRDR1', '123456789012', 'narrow-reader', 'Narrow-Reader', '/'),
        ('SVCGUPNOGRANTRD1', '123456789012', 'no-grant-reader', 'No-Grant-Reader', '/'),
        ('SVCGUPTGTHOLDER1', '123456789012', 'policy-holder', 'Policy-Holder', '/'),
        ('SVCGUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCGUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCGUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCGUPTGTENGNR01', 'department', 'Department', 'Engineering'),
        ('SVCGUPTGTSALES01', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGUPBROADRDR01', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*"}]}'),
        ('SVCGUPPATHRDR001', 'allow-get-division-policy', 'Allow-Get-Division-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCGUPTAGRDR0001', 'allow-get-engineering-policy', 'Allow-Get-Engineering-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCGUPNARROWRDR1', 'allow-get-holder-policy', 'Allow-Get-Holder-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/Policy-Holder"}]}'),
        ('SVCGUPTGTHOLDER1', 'app-access', 'App-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
        ('SVCGUPTGTHOLDER1', 'db-access', 'Db-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
        ('SVCGUPTGTDIVSN01', 'division-access', 'Division-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
        ('SVCGUPTGTENGNR01', 'eng-access', 'Eng-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
        ('SVCGUPTGTSALES01', 'sales-access', 'Sales-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}');

        INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, assume_role_policy_document) VALUES
        ('SVCGUPROLE000001', '123456789012', 'get-user-policy-role', 'Get-User-Policy-Role', '/',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}');

        INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCGUPROLE000001', 'allow-get-any-policy', 'Allow-Get-Any-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUserPolicy","Resource":"*"}]}');
    "#;

    /// Seed data for the `PutUserPolicy` authorization tests. `Policy-Target` already carries an
    /// inline policy, so replacing one can be told apart from adding one; the other targets carry
    /// the paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived
    /// from. `Broad-Writer` is also allowed `iam:GetUserPolicy`, so the tests can read back what
    /// a write did or did not leave behind.
    const PUT_USER_POLICY_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'put-user-policy-test@example.com', 'put-user-policy-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCPUPBROADWTR01', '123456789012', 'broad-writer', 'Broad-Writer', '/'),
        ('SVCPUPPATHWTR001', '123456789012', 'path-writer', 'Path-Writer', '/'),
        ('SVCPUPTAGWTR0001', '123456789012', 'tag-writer', 'Tag-Writer', '/'),
        ('SVCPUPNARROWWTR1', '123456789012', 'narrow-writer', 'Narrow-Writer', '/'),
        ('SVCPUPNOGRANTWR1', '123456789012', 'no-grant-writer', 'No-Grant-Writer', '/'),
        ('SVCPUPTGTPOLICY1', '123456789012', 'policy-target', 'Policy-Target', '/'),
        ('SVCPUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCPUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCPUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
        ('SVCPUPTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCPUPTGTENGNR01', 'department', 'Department', 'Engineering'),
        ('SVCPUPTGTSALES01', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCPUPBROADWTR01', 'allow-put-any-policy', 'Allow-Put-Any-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
           "Action":["iam:PutUserPolicy","iam:GetUserPolicy"],"Resource":"*"}]}'),
        ('SVCPUPPATHWTR001', 'allow-put-division-policy', 'Allow-Put-Division-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCPUPTAGWTR0001', 'allow-put-engineering-policy', 'Allow-Put-Engineering-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCPUPNARROWWTR1', 'allow-put-target-policy', 'Allow-Put-Target-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/Policy-Target"}]}'),
        ('SVCPUPTGTPOLICY1', 'existing-access', 'Existing-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
    "#;

    /// Seed data for the `DeleteUserPolicy` authorization tests. `Policy-Target` carries several
    /// inline policies, so a grant reaching the user can be shown to reach all of them and a
    /// denied delete can be shown to have left its policy behind; the other targets carry the
    /// paths and tags the resource ARN and the `aws:ResourceTag` condition keys are derived from.
    /// `Broad-Deleter` is also allowed `iam:GetUserPolicy`, so the tests can read back what a
    /// delete did or did not remove.
    const DELETE_USER_POLICY_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'delete-user-policy-test@example.com', 'delete-user-policy-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCDUPBROADDEL01', '123456789012', 'broad-deleter', 'Broad-Deleter', '/'),
        ('SVCDUPPATHDEL001', '123456789012', 'path-deleter', 'Path-Deleter', '/'),
        ('SVCDUPTAGDEL0001', '123456789012', 'tag-deleter', 'Tag-Deleter', '/'),
        ('SVCDUPNARROWDEL1', '123456789012', 'narrow-deleter', 'Narrow-Deleter', '/'),
        ('SVCDUPNOGRANTDL1', '123456789012', 'no-grant-deleter', 'No-Grant-Deleter', '/'),
        ('SVCDUPTGTPOLICY1', '123456789012', 'policy-target', 'Policy-Target', '/'),
        ('SVCDUPTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCDUPTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCDUPTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
        ('SVCDUPTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCDUPTGTENGNR01', 'department', 'Department', 'Engineering'),
        ('SVCDUPTGTSALES01', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCDUPBROADDEL01', 'allow-delete-any-policy', 'Allow-Delete-Any-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
           "Action":["iam:DeleteUserPolicy","iam:GetUserPolicy"],"Resource":"*"}]}'),
        ('SVCDUPPATHDEL001', 'allow-delete-division-policy', 'Allow-Delete-Division-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCDUPTAGDEL0001', 'allow-delete-engineering-policy', 'Allow-Delete-Engineering-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCDUPNARROWDEL1', 'allow-delete-target-policy', 'Allow-Delete-Target-Policy',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:DeleteUserPolicy",
           "Resource":"arn:aws:iam::123456789012:user/Policy-Target"}]}'),
        ('SVCDUPTGTPOLICY1', 'app-access', 'App-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'),
        ('SVCDUPTGTPOLICY1', 'db-access', 'Db-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}'),
        ('SVCDUPTGTPOLICY1', 'keep-access', 'Keep-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}]}'),
        ('SVCDUPTGTDIVSN01', 'division-access', 'Division-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}'),
        ('SVCDUPTGTENGNR01', 'eng-access', 'Eng-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}'),
        ('SVCDUPTGTSALES01', 'sales-access', 'Sales-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}'),
        ('SVCDUPTGTROOT001', 'root-access', 'Root-Access',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:PutMetricData",
           "Resource":"*"}]}');
    "#;

    /// Seed data for the `TagUser` authorization tests. `Tag-Target` already carries a tag, so
    /// replacing one can be told apart from adding one; the other targets carry the paths and tags
    /// the resource ARN and the `aws:ResourceTag` condition keys are derived from. `Broad-Tagger`
    /// is also allowed `iam:GetUser`, so the tests can read back what a request did or did not
    /// leave on a user. The remaining callers carry grants scoped by the target's path, by the
    /// tags the request asks to apply, by the tag keys it may name at all, and by the tags the
    /// target already carries.
    const TAG_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'tag-user-test@example.com', 'tag-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCTUSBROADTAG01', '123456789012', 'broad-tagger', 'Broad-Tagger', '/'),
        ('SVCTUSPATHTAG001', '123456789012', 'path-tagger', 'Path-Tagger', '/'),
        ('SVCTUSREQTAG0001', '123456789012', 'request-tag-tagger', 'Request-Tag-Tagger', '/'),
        ('SVCTUSKEYSTAG001', '123456789012', 'tag-key-tagger', 'Tag-Key-Tagger', '/'),
        ('SVCTUSRESTAG0001', '123456789012', 'resource-tag-tagger', 'Resource-Tag-Tagger', '/'),
        ('SVCTUSNARROWTAG1', '123456789012', 'narrow-tagger', 'Narrow-Tagger', '/'),
        ('SVCTUSNOGRANTTG1', '123456789012', 'no-grant-tagger', 'No-Grant-Tagger', '/'),
        ('SVCTUSTGTPLAIN01', '123456789012', 'tag-target', 'Tag-Target', '/'),
        ('SVCTUSTGTREQST01', '123456789012', 'request-target', 'Request-Target', '/'),
        ('SVCTUSTGTKEYS001', '123456789012', 'keys-target', 'Keys-Target', '/'),
        ('SVCTUSTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCTUSTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCTUSTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
        ('SVCTUSTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCTUSTGTPLAIN01', 'env', 'Env', 'Staging'),
        ('SVCTUSTGTENGNR01', 'department', 'Department', 'Engineering'),
        ('SVCTUSTGTSALES01', 'department', 'Department', 'Sales');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCTUSBROADTAG01', 'allow-tag-any-user', 'Allow-Tag-Any-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:TagUser","iam:GetUser"],
           "Resource":"*"}]}'),
        ('SVCTUSPATHTAG001', 'allow-tag-division-user', 'Allow-Tag-Division-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCTUSREQTAG0001', 'allow-tag-engineering', 'Allow-Tag-Engineering',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:RequestTag/department":"Engineering"}}}]}'),
        ('SVCTUSKEYSTAG001', 'allow-tag-with-known-keys', 'Allow-Tag-With-Known-Keys',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
           "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Department","Project"]}}}]}'),
        ('SVCTUSRESTAG0001', 'allow-tag-engineering-user', 'Allow-Tag-Engineering-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCTUSNARROWTAG1', 'allow-tag-target-user', 'Allow-Tag-Target-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:TagUser",
           "Resource":"arn:aws:iam::123456789012:user/Tag-Target"}]}');
    "#;

    /// Seed data for the `UntagUser` authorization tests. Every target carries the tags a request
    /// asks to remove, and `Broad-Untagger` is also allowed `iam:GetUser`, so the tests can read
    /// back what a request did or did not remove. The remaining callers carry grants scoped by the
    /// target's path, by the tag keys the request may name at all, and by the tags the target
    /// already carries -- the last of which governs a request that removes that very tag.
    const UNTAG_USER_TEST_DATA: &str = r#"
        INSERT INTO iam.partition(partition) VALUES ('aws');

        INSERT INTO iam.accounts(account_id, email, alias) VALUES
        ('123456789012', 'untag-user-test@example.com', 'untag-user-test');

        INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path) VALUES
        ('SVCUTSBROADUTG01', '123456789012', 'broad-untagger', 'Broad-Untagger', '/'),
        ('SVCUTSPATHUTG001', '123456789012', 'path-untagger', 'Path-Untagger', '/'),
        ('SVCUTSKEYSUTG001', '123456789012', 'tag-key-untagger', 'Tag-Key-Untagger', '/'),
        ('SVCUTSRESUTG0001', '123456789012', 'resource-tag-untagger', 'Resource-Tag-Untagger', '/'),
        ('SVCUTSNARROWUTG1', '123456789012', 'narrow-untagger', 'Narrow-Untagger', '/'),
        ('SVCUTSNOGRANTUT1', '123456789012', 'no-grant-untagger', 'No-Grant-Untagger', '/'),
        ('SVCUTSTGTPLAIN01', '123456789012', 'untag-target', 'Untag-Target', '/'),
        ('SVCUTSTGTDIVSN01', '123456789012', 'division-target', 'Division-Target', '/division/'),
        ('SVCUTSTGTENGNR01', '123456789012', 'engineering-target', 'Engineering-Target', '/'),
        ('SVCUTSTGTSALES01', '123456789012', 'sales-target', 'Sales-Target', '/'),
        ('SVCUTSTGTROOT001', '123456789012', 'root-target', 'Root-Target', '/');

        INSERT INTO iam.user_tags(user_id, key_lower, key_cased, value) VALUES
        ('SVCUTSTGTPLAIN01', 'department', 'Department', 'Engineering'),
        ('SVCUTSTGTPLAIN01', 'project', 'Project', 'Scratchstack'),
        ('SVCUTSTGTPLAIN01', 'keep', 'Keep', 'Yes'),
        ('SVCUTSTGTDIVSN01', 'project', 'Project', 'Division'),
        ('SVCUTSTGTENGNR01', 'department', 'Department', 'Engineering'),
        ('SVCUTSTGTENGNR01', 'costcenter', 'CostCenter', '1234'),
        ('SVCUTSTGTSALES01', 'department', 'Department', 'Sales'),
        ('SVCUTSTGTROOT001', 'root', 'Root', 'Tag');

        INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
        ('SVCUTSBROADUTG01', 'allow-untag-any-user', 'Allow-Untag-Any-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:UntagUser","iam:GetUser"],
           "Resource":"*"}]}'),
        ('SVCUTSPATHUTG001', 'allow-untag-division-user', 'Allow-Untag-Division-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser",
           "Resource":"arn:aws:iam::123456789012:user/division/*"}]}'),
        ('SVCUTSKEYSUTG001', 'allow-untag-known-keys', 'Allow-Untag-Known-Keys',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser","Resource":"*",
           "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["Project"]}}}]}'),
        ('SVCUTSRESUTG0001', 'allow-untag-engineering-user', 'Allow-Untag-Engineering-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser","Resource":"*",
           "Condition":{"StringEquals":{"aws:ResourceTag/department":"Engineering"}}}]}'),
        ('SVCUTSNARROWUTG1', 'allow-untag-target-user', 'Allow-Untag-Target-User',
         '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:UntagUser",
           "Resource":"arn:aws:iam::123456789012:user/Untag-Target"}]}');
    "#;

    /// Build the principal and session data the SigV4 layer would produce for a seeded user.
    fn user_identity(user_id: &str, user_name: &str) -> (Principal, SessionData) {
        let principal = Principal::from(
            User::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .path("/")
                .user_name(user_name)
                .build()
                .expect("failed to build user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:iam::{TEST_ACCOUNT_ID}:user/{user_name}")),
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
    fn role_identity(role_id: &str, role_name: &str) -> (Principal, SessionData) {
        role_identity_issued_at(role_id, role_name, Utc::now())
    }

    /// Build the principal and session data the SigV4 layer would produce for a session on the
    /// seeded role that `sts:AssumeRole` minted at `issued_at`.
    ///
    /// The keys here mirror the session metadata `AssumeRole` records in the session token, which
    /// the signing-key provider hands back verbatim as the session data for a request signed with
    /// the resulting temporary credentials.
    fn role_identity_issued_at(role_id: &str, role_name: &str, issued_at: DateTime<Utc>) -> (Principal, SessionData) {
        let principal = Principal::from(
            AssumedRole::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .role_name(role_name)
                .session_name("test-session")
                .build()
                .expect("failed to build assumed role"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        session_data.insert(
            "aws:PrincipalArn",
            SessionValue::String(format!("arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/{role_name}/test-session")),
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
    fn root_identity() -> (Principal, SessionData) {
        let principal = Principal::from(
            RootUser::builder()
                .partition("aws")
                .account_id(TEST_ACCOUNT_ID)
                .build()
                .expect("failed to build root user"),
        );
        let mut session_data = SessionData::new();
        session_data.insert("aws:PrincipalAccount", SessionValue::String(TEST_ACCOUNT_ID.to_string()));
        (principal, session_data)
    }

    /// Build the query parameters for a `GetUser` request, naming a user or leaving `UserName`
    /// off so it defaults to the caller.
    fn get_user_parameters(user_name: Option<&str>) -> String {
        match user_name {
            Some(user_name) => format!("Action=GetUser&Version=2010-05-08&UserName={user_name}"),
            None => "Action=GetUser&Version=2010-05-08".to_string(),
        }
    }

    /// Build the query parameters for a `CreateUser` request naming `user_name`, optionally
    /// under a path, carrying tags, and asking for a permissions boundary.
    fn create_user_parameters(
        user_name: &str,
        path: Option<&str>,
        tags: &[(&str, &str)],
        permissions_boundary: Option<&str>,
    ) -> String {
        let mut parameters = format!("Action=CreateUser&Version=2010-05-08&UserName={user_name}");

        if let Some(path) = path {
            parameters.push_str(&format!("&Path={}", path.replace('/', "%2F")));
        }

        append_tag_parameters(&mut parameters, tags);

        if let Some(permissions_boundary) = permissions_boundary {
            parameters.push_str(&format!("&PermissionsBoundary={}", permissions_boundary.replace('/', "%2F")));
        }

        parameters
    }

    /// Build the query parameters for a `DeleteUser` request, naming a user or leaving `UserName`
    /// off entirely.
    fn delete_user_parameters(user_name: Option<&str>) -> String {
        match user_name {
            Some(user_name) => format!("Action=DeleteUser&Version=2010-05-08&UserName={user_name}"),
            None => "Action=DeleteUser&Version=2010-05-08".to_string(),
        }
    }

    /// Extract the `PolicyDocument` from a policy response and percent-decode it, standing in for
    /// the URL decoding a client applies.
    ///
    /// IAM reports policy documents percent-encoded, so a test that wants to look at the policy
    /// itself has to undo that first. The encoded form carries no XML metacharacters, so what is
    /// between the tags is exactly what was encoded.
    fn decoded_policy_document(body: &str) -> String {
        const OPEN: &str = "<PolicyDocument>";
        const CLOSE: &str = "</PolicyDocument>";

        let start = body.find(OPEN).expect("no PolicyDocument in body") + OPEN.len();
        let end = start + body[start..].find(CLOSE).expect("unterminated PolicyDocument");

        PctStr::new(&body[start..end]).expect("PolicyDocument is not percent-encoded").decode()
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

    /// Build the query parameters for a `TagUser` request, naming a user or leaving `UserName`
    /// off, and carrying the tags to apply.
    fn tag_user_parameters(user_name: Option<&str>, tags: &[(&str, &str)]) -> String {
        let mut parameters = "Action=TagUser&Version=2010-05-08".to_string();

        if let Some(user_name) = user_name {
            parameters.push_str(&format!("&UserName={user_name}"));
        }

        append_tag_parameters(&mut parameters, tags);
        parameters
    }

    /// Build the query parameters for an `UntagUser` request, naming a user or leaving `UserName`
    /// off, and carrying the tag keys to remove.
    fn untag_user_parameters(user_name: Option<&str>, tag_keys: &[&str]) -> String {
        let mut parameters = "Action=UntagUser&Version=2010-05-08".to_string();

        if let Some(user_name) = user_name {
            parameters.push_str(&format!("&UserName={user_name}"));
        }

        // A list of scalars is indexed the same way a list of structures is, with no field name
        // after the index.
        for (index, key) in tag_keys.iter().enumerate() {
            let index = index + 1;
            parameters.push_str(&format!("&TagKeys.member.{index}={key}"));
        }

        parameters
    }

    /// Append the parameters naming `tags` to a query string being built.
    ///
    /// Lists arrive in the query string indexed under a `member` segment, one parameter per
    /// field, as the AWS query protocol spells them.
    fn append_tag_parameters(parameters: &mut String, tags: &[(&str, &str)]) {
        for (index, (key, value)) in tags.iter().enumerate() {
            let index = index + 1;
            parameters.push_str(&format!("&Tags.member.{index}.Key={key}&Tags.member.{index}.Value={value}"));
        }
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
        call_as(svc_state, principal, session_data, session_policies, TEST_SOURCE_IP, HeaderMap::new(), parameters)
            .await
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
        call_as(svc_state, principal, session_data, SessionPolicies::default(), TEST_SOURCE_IP, headers, parameters)
            .await
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

    /// End-to-end authorization checks through `serve_request` against an embedded PostgreSQL
    /// database. A single test function is used because the database is stateful and expensive
    /// to start.
    #[test_log::test(tokio::test)]
    async fn test_list_users_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(AUTHZ_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();
        let parameters = "Action=ListUsers&Version=2010-05-08";

        // A user whose inline policy allows iam:ListUsers gets a successful response.
        let (principal, session_data) = user_identity("SVCTESTALLOWUSER", "Allowed-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // A user with no policies is denied with a 403 AccessDenied error.
        let (principal, session_data) = user_identity("SVCTESTDENYUSER1", "Denied-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Denied-User is not authorized to perform: \
                 iam:ListUsers on resource: *"
            )),
            "unexpected body: {body}"
        );

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:SecureTransport reflects the listener's TLS configuration: a grant conditioned on
        // it succeeds on a TLS listener and fails on a plaintext one.
        let (principal, session_data) = user_identity("SVCTESTTLSUSER01", "Tls-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let insecure_state = ServiceState::builder().db(svc_state.db.clone()).secure_transport(false).build();
        let (principal, session_data) = user_identity("SVCTESTTLSUSER01", "Tls-User");
        let (status, body) = call(&insecure_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:CurrentTime carries the evaluation time as a timestamp: a DateGreaterThan
        // condition against a past instant passes, and a DateLessThan against it fails.
        let (principal, session_data) = user_identity("SVCTESTTIMEUSER1", "Time-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTPASTUSER1", "Past-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:EpochTime carries the evaluation time in integer seconds, satisfying a
        // NumericGreaterThan condition against a past epoch value.
        let (principal, session_data) = user_identity("SVCTESTEPOCHUSR1", "Epoch-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:SourceIp carries the address the request arrived from: a grant conditioned on a
        // CIDR block admits a caller inside the block...
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...and refuses one outside it.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A dual-stack listener reports an IPv4 peer as an IPv4-mapped IPv6 address. The mapping
        // is unwrapped before evaluation, so an IPv4 grant still matches such a caller.
        let mapped_source_ip = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped());
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) = call_from(&svc_state, principal, session_data, mapped_source_ip, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // IPv6 CIDR blocks are matched the same way, and do not match an IPv4 caller.
        let (principal, session_data) = user_identity("SVCTESTIPV6USER1", "Ipv6-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IPV6, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTIPV6USER1", "Ipv6-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A NotIpAddress condition on an explicit Deny statement leaves callers inside the block
        // alone and stops everyone else.
        let (principal, session_data) = user_identity("SVCTESTDENYIPUSR", "Deny-Ip-User");
        let (status, body) = call_from(&svc_state, principal, session_data, TEST_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTDENYIPUSR", "Deny-Ip-User");
        let (status, body) = call_from(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("with an explicit deny in an identity-based policy"), "unexpected body: {body}");

        // A listener that trusts no proxy does not read the X-Forwarded-For header, so a caller
        // outside the granted block cannot talk its way inside one.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&svc_state, principal, session_data, OUTSIDE_SOURCE_IP, "203.0.113.10", parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A listener behind a load balancer takes the address that balancer reports, so the same
        // grant is evaluated against the client rather than against the balancer...
        let proxied_state = proxied_state(&svc_state);
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&proxied_state, principal, session_data, TEST_PROXY_IP, "203.0.113.10", parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...including when the client the balancer names is outside the block.
        let (principal, session_data) = user_identity("SVCTESTIPV4USER1", "Ipv4-User");
        let (status, body) =
            call_forwarded(&proxied_state, principal, session_data, TEST_PROXY_IP, "198.51.100.7", parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:RequestedRegion names the region the request was signed for, so a grant scoped to
        // one region admits a request in it and a grant scoped to another does not.
        let (principal, session_data) = user_identity("SVCTESTREGIONUSR", "Region-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTOTHERRGN1", "Other-Region-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A role session carries the key too, now that the signing-key provider records it for
        // temporary credentials rather than leaving it to the session token.
        let (principal, session_data) = role_identity("SVCTESTRGNROLE01", "Region-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // iam:ListUsers names no resource ARN, so the account it lists supplies
        // aws:ResourceAccount: a grant scoped to that account admits the request, and one scoped
        // to another account does not.
        let (principal, session_data) = user_identity("SVCTESTACCTUSER1", "Account-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = user_identity("SVCTESTOTHRACCT1", "Other-Account-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:referer and aws:UserAgent carry the headers the caller sent, so a grant gated on
        // both admits a request that announces itself as expected...
        let headers = client_headers(Some("https://console.example.com/"), Some("aws-cli/2.15.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...refuses one whose User-Agent does not match the pattern...
        let headers = client_headers(Some("https://console.example.com/"), Some("curl/8.4.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // ...and refuses one that sends neither header, since a condition on an absent key does
        // not match.
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A caller that sends only the User-Agent still fails the Referer half of the grant,
        // confirming both keys are read rather than one standing in for the other.
        let headers = client_headers(None, Some("aws-cli/2.15.0"));
        let (principal, session_data) = user_identity("SVCTESTAGENTUSR1", "Agent-User");
        let (status, body) = call_with_headers(&svc_state, principal, session_data, headers, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // aws:ViaAWSService and aws:PrincipalIsAWSService are both false for a request a
        // principal makes for itself. A plain Bool condition does not match an absent key, so a
        // grant gated on them proves they reach evaluation -- for user credentials and, now that
        // the signing-key provider records them for temporary credentials too, for role
        // sessions.
        let (principal, session_data) = user_identity("SVCTESTDIRECTUSR", "Direct-Call-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        let (principal, session_data) = role_identity("SVCTESTDIRROLE01", "Direct-Call-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // aws:TokenIssueTime comes from the session token rather than the request, carrying the
        // moment sts:AssumeRole minted the credentials: a grant restricted to sessions issued
        // after a cutoff admits a session minted now...
        let (principal, session_data) = role_identity("SVCTESTTOKENROLE", "Token-Role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // ...and refuses one minted before it.
        let issued_at =
            DateTime::parse_from_rfc3339("2019-06-01T00:00:00Z").expect("bad timestamp").with_timezone(&Utc);
        let (principal, session_data) = role_identity_issued_at("SVCTESTTOKENROLE", "Token-Role", issued_at);
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Long-term IAM user credentials are not a session and carry no aws:TokenIssueTime at
        // all, so the same condition never matches for them -- as on AWS.
        let (principal, session_data) = user_identity("SVCTESTTOKENUSER", "Token-User");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // An assumed-role session with no session policies is governed by the role's inline
        // policy, which allows iam:ListUsers.
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) = call(&svc_state, principal, session_data, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // An inline session policy that also allows iam:ListUsers leaves the intersection
        // intact.
        let allow_iam = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}"#,
        )
        .expect("failed to parse policy");
        let session_policies = SessionPolicies::builder().inline_policy(allow_iam).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // An inline session policy that does not allow iam:ListUsers removes it from the
        // intersection even though the role's own policy allows it.
        let allow_s3_only = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        )
        .expect("failed to parse policy");
        let session_policies = SessionPolicies::builder().inline_policy(allow_s3_only).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:sts::{TEST_ACCOUNT_ID}:assumed-role/session-role/test-session is not \
                 authorized to perform: iam:ListUsers on resource: * because no session policy allows \
                 the iam:ListUsers action"
            )),
            "unexpected body: {body}"
        );

        // A managed session policy resolves to its current default version, which allows iam:*.
        let session_policies =
            SessionPolicies::builder().managed_policy_ids(["ANPASVCTESTSESSPOL01".to_string()]).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<ListUsersResult>"), "unexpected body: {body}");

        // A managed session policy that no longer resolves cannot be reconstructed; the request
        // is denied (not an internal failure).
        let session_policies =
            SessionPolicies::builder().managed_policy_ids(["ANPADOESNOTEXIST0000".to_string()]).build();
        let (principal, session_data) = role_identity("SVCTESTROLE00001", "session-role");
        let (status, body) =
            call_with_session_policies(&svc_state, principal, session_data, session_policies, parameters).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(body.contains("because no session policy allows the iam:ListUsers action"), "unexpected body: {body}");
    }

    /// End-to-end `GetUser` authorization checks through `serve_request` against an embedded
    /// PostgreSQL database. As with the `ListUsers` test, one test function covers every case
    /// because the database is stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_get_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(GET_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // An omitted UserName names the calling user. The grant here is scoped to the caller's
        // own ARN through the aws:username policy variable, so it covers exactly that lookup.
        let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User</Arn>")),
            "unexpected body: {body}"
        );

        // The same grant does not reach any other user.
        let (principal, session_data) = user_identity("SVCGETUSERSELF01", "Self-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Self-User is not authorized to perform: \
                 iam:GetUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User"
            )),
            "unexpected body: {body}"
        );

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Division-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/division/Division-User</Arn>")),
            "unexpected body: {body}"
        );
        assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCGETUSERPATH01", "Path-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The target user's tags back the aws:ResourceTag condition keys. The policy spells the
        // tag key in lower case while the tag itself is stored as "Department", confirming that
        // tag keys are matched case-insensitively.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
            "unexpected body: {body}"
        );

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Neither does a user carrying no tags at all: the condition key is absent.
        let (principal, session_data) = user_identity("SVCGETUSERTAG001", "Tag-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // IAM's own iam:ResourceTag condition key carries the same values.
        let (principal, session_data) = user_identity("SVCGETUSERIAMTG1", "Iam-Tag-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Engineering-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Engineering-User</Arn>")),
            "unexpected body: {body}"
        );

        // The resource ARN carries the account that owns the user being read, which supplies
        // aws:ResourceAccount: a grant scoped to that account reaches the user...
        let (principal, session_data) = user_identity("SVCGETUSRACCT001", "Account-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User</Arn>")),
            "unexpected body: {body}"
        );

        // ...and one scoped to a different account does not.
        let (principal, session_data) = user_identity("SVCGETUSRACCT002", "Other-Account-User");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:GetUser on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCGETUSERBROAD1", "Broad-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on specific users learns nothing about it.
        let (principal, session_data) = user_identity("SVCGETUSERNARROW", "Narrow-User");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // An assumed-role session has no user to default UserName to.
        let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");
        assert!(
            body.contains("Must specify userName when calling with non-User credentials"),
            "unexpected body: {body}"
        );

        // Naming the user explicitly works, governed by the role's own policy.
        let (principal, session_data) = role_identity("SVCGETUSERROLE01", "Get-User-Role");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Broad-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Broad-User</Arn>")),
            "unexpected body: {body}"
        );

        // The account root user is implicitly allowed, but is not an IAM user either, so it must
        // also name the user explicitly.
        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

        let (principal, session_data) = root_identity();
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Sales-User"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Sales-User</Arn>")),
            "unexpected body: {body}"
        );
    }

    /// End-to-end authorization checks for `CreateUser` through `serve_request` against an
    /// embedded PostgreSQL database. A single test function is used because the database is
    /// stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_create_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(CREATE_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:CreateUser on any user creates one at the root path.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("New-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/New-User</Arn>")),
            "unexpected body: {body}"
        );
        assert!(body.contains("<Path>/</Path>"), "unexpected body: {body}");
        assert!(body.contains("<UserName>New-User</UserName>"), "unexpected body: {body}");

        // The user is now readable, so the create was committed rather than rolled back.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("New-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

        // User names are compared case-insensitively, so a name differing only in case collides
        // with the user just created.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("NEW-USER", None, &[], None)).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>EntityAlreadyExists</Code>"), "unexpected body: {body}");

        // The path the request asks for is part of the ARN being authorized, so a grant scoped to
        // a path prefix reaches users created under that path...
        let (principal, session_data) = user_identity("SVCCREUSERPATH1", "Path-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Division-User", Some("/division/"), &[], None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/division/Division-User</Arn>")),
            "unexpected body: {body}"
        );
        assert!(body.contains("<Path>/division/</Path>"), "unexpected body: {body}");

        // ...and no further: the same caller cannot create a user at the root path.
        let (principal, session_data) = user_identity("SVCCREUSERPATH1", "Path-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Root-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Path-Creator is not authorized to perform: \
                 iam:CreateUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Root-User"
            )),
            "unexpected body: {body}"
        );

        // A denial rolls the transaction back, so nothing was created.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Root-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
        // spells the tag key in lower case while the request spells it "Department", confirming
        // that tag keys are matched case-insensitively.
        let (principal, session_data) = user_identity("SVCCREUSERTAG01", "Tag-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Tagged-User", None, &[("Department", "Engineering")], None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<Key>Department</Key>"), "unexpected body: {body}");
        assert!(body.contains("<Value>Engineering</Value>"), "unexpected body: {body}");

        // A request asking for the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCCREUSERTAG01", "Tag-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Sales-User", None, &[("Department", "Sales")], None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Neither does a request asking for no tags at all: the condition key is absent, so the
        // grant does not apply rather than matching an empty value.
        let (principal, session_data) = user_identity("SVCCREUSERTAG01", "Tag-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Bare-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A grant conditioned on aws:TagKeys limits which tags the request may name at all,
        // whatever values it asks to give them: every tag key the request carries has to be one
        // the policy lists.
        let (principal, session_data) = user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters(
                "Known-Tags-User",
                None,
                &[("Department", "Engineering"), ("Project", "Scratchstack")],
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<Key>Project</Key>"), "unexpected body: {body}");

        // One tag key outside the set the policy lists is enough to fail, even alongside keys
        // that are in it.
        let (principal, session_data) = user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters(
                "Extra-Tag-User",
                None,
                &[("Department", "Engineering"), ("Cost-Center", "1234")],
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A request naming no tags at all satisfies ForAllValues vacuously: there is no tag key
        // the policy would have to allow.
        let (principal, session_data) = user_identity("SVCCREUSERKEYS1", "Tag-Key-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Untagged-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // Two tags with the same key ask for two values for one tag. That is the caller's error,
        // not ours, so it is reported as invalid input rather than an internal failure. The keys
        // here differ only in case, which IAM treats as the same key.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters(
                "Dupe-Tag-User",
                None,
                &[("Department", "Engineering"), ("department", "Sales")],
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");

        // Verified against the live service: this is the error element AWS returns, verbatim.
        assert!(
            body.contains(
                "<Error><Type>Sender</Type><Code>InvalidInput</Code><Message>Duplicate tag keys found. \
                 Please note that Tag keys are case insensitive.</Message></Error>"
            ),
            "unexpected body: {body}"
        );

        // The rejection rolled the transaction back, so the name is still free.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Dupe-Tag-User", None, &[("Department", "Engineering")], None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // The permissions boundary the request asks for backs iam:PermissionsBoundary, which is
        // what lets a policy require that users be created only under a boundary.
        let boundary = format!("arn:aws:iam::{TEST_ACCOUNT_ID}:policy/Boundary-Policy");
        let (principal, session_data) = user_identity("SVCCREUSERPB001", "Boundary-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Bounded-User", None, &[], Some(&boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
            "unexpected body: {body}"
        );

        // Omitting the boundary leaves the condition key absent, so the grant does not apply.
        let (principal, session_data) = user_identity("SVCCREUSERPB001", "Boundary-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Unbounded-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Naming a different boundary does not satisfy the condition either.
        let other_boundary = format!("arn:aws:iam::{TEST_ACCOUNT_ID}:policy/Other-Policy");
        let (principal, session_data) = user_identity("SVCCREUSERPB001", "Boundary-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Other-Bounded-User", None, &[], Some(&other_boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Tagging a user is a separate action from creating one, so a caller allowed only
        // iam:CreateUser can create a user...
        let (principal, session_data) = user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Plain-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...but not a tagged one, and the denial names the action actually missing.
        let (principal, session_data) = user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Tagged-Denied-User", None, &[("Department", "Engineering")], None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Create-Only-Creator is not authorized to perform: \
                 iam:TagUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Tagged-Denied-User"
            )),
            "unexpected body: {body}"
        );

        // A permissions boundary, by contrast, needs no second action: the same caller can attach
        // one under iam:CreateUser alone, as the service allows.
        let (principal, session_data) = user_identity("SVCCREUSERONLY1", "Create-Only-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Plain-Bounded-User", None, &[], Some(&boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
            "unexpected body: {body}"
        );

        // The denials rolled their transactions back, so neither user was created.
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Tagged-Denied-User", None, &[("Department", "Engineering")], None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // The boundary condition works with the ArnEquals operator as well as StringEquals, which
        // is what the console's policy editor emits for an ARN-valued key. Aspen treats ArnEquals
        // and ArnLike identically, as AWS documents them to be.
        let (principal, session_data) = user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Arn-Bounded-User", None, &[], Some(&boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<PermissionsBoundaryArn>{boundary}</PermissionsBoundaryArn>")),
            "unexpected body: {body}"
        );

        // A different boundary does not satisfy it.
        let (principal, session_data) = user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Arn-Other-Bounded-User", None, &[], Some(&other_boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Nor does omitting the boundary: the condition key is absent, which an ARN operator
        // treats as a null that only its IfExists variant would accept. This is the case that
        // matters, since a policy written this way exists to stop unbounded users being created.
        let (principal, session_data) = user_identity("SVCCREUSERARN01", "Arn-Boundary-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Arn-Unbounded-User", None, &[], None))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A caller with no grant at all is refused.
        let (principal, session_data) = user_identity("SVCCREUSERNONE1", "No-Grant-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Denied-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A malformed user name is rejected before the request is authorized, so the caller
        // learns the request was invalid rather than that it was denied.
        let (principal, session_data) = user_identity("SVCCREUSERNONE1", "No-Grant-Creator");
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("bad%20name%21", None, &[], None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

        // A permissions boundary naming a policy that does not exist is reported as such.
        let missing_boundary = format!("arn:aws:iam::{TEST_ACCOUNT_ID}:policy/No-Such-Policy");
        let (principal, session_data) = user_identity("SVCCREUSERBROAD", "Broad-Creator");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &create_user_parameters("Missing-Boundary-User", None, &[], Some(&missing_boundary)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) =
            call(&svc_state, principal, session_data, &create_user_parameters("Root-Made-User", None, &[], None)).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(
            body.contains(&format!("<Arn>arn:aws:iam::{TEST_ACCOUNT_ID}:user/Root-Made-User</Arn>")),
            "unexpected body: {body}"
        );
    }

    /// End-to-end authorization checks for `DeleteUser` through `serve_request` against an
    /// embedded PostgreSQL database. A single test function is used because the database is
    /// stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_delete_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(DELETE_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:DeleteUser on any user deletes one.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<DeleteUserResponse"), "unexpected body: {body}");

        // The delete was committed rather than rolled back, so the user is gone. The same caller
        // is allowed iam:GetUser, so it is told the user no longer exists.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Delete-Me"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // Deleting it a second time reports that it no longer exists.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCDELUSERPATH1", "Path-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Division-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCDELUSERPATH1", "Path-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me-Too"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The target user's own tags back the aws:ResourceTag condition keys, unlike CreateUser
        // where the tags come from the request.
        let (principal, session_data) = user_identity("SVCDELUSERTAG01", "Tag-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Engineering-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCDELUSERTAG01", "Tag-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Sales-Target"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The denial rolled the transaction back, so the user is still there to be deleted by a
        // caller that is allowed to.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Sales-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user that still owns dependent resources cannot be deleted; the caller is allowed the
        // action, so it learns the delete conflicts rather than that it was denied.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Policy-Holder"))).await;
        assert_eq!(status, StatusCode::CONFLICT, "unexpected response: {body}");
        assert!(body.contains("<Code>DeleteConflict</Code>"), "unexpected body: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:DeleteUser on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCDELUSERNARRW", "Narrow-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("No-Such-User"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Unlike GetUser, an omitted UserName does not default to the calling user: DeleteUser
        // requires the name, so a caller cannot delete itself by leaving it off.
        let (principal, session_data) = user_identity("SVCDELUSERBROAD", "Broad-Deleter");
        let (status, body) = call(&svc_state, principal, session_data, &delete_user_parameters(None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

        // The narrow grant reaches exactly the user it names.
        let (principal, session_data) = user_identity("SVCDELUSERNARRW", "Narrow-Deleter");
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Delete-Me-Too"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) =
            call(&svc_state, principal, session_data, &delete_user_parameters(Some("Root-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }
    /// End-to-end authorization checks for `GetUserPolicy` through `serve_request` against an
    /// embedded PostgreSQL database. A single test function is used because the database is
    /// stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_get_user_policy_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(GET_USER_POLICY_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:GetUserPolicy on any user reads an inline policy off one.
        let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<UserName>Policy-Holder</UserName>"), "unexpected body: {body}");
        assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

        // The document goes out percent-encoded rather than as the JSON it is stored as, so the
        // raw policy does not appear on the wire at all and a client decodes what it reads back.
        assert!(body.contains("%7B%22Version%22%3A%222012-10-17%22"), "unexpected body: {body}");
        assert!(!body.contains("s3:GetObject"), "unexpected body: {body}");
        assert!(decoded_policy_document(&body).contains("s3:GetObject"), "unexpected body: {body}");

        // Policy names are matched case-insensitively, and the name comes back cased as it was
        // stored rather than as the request spelled it.
        let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("app-access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<PolicyName>App-Access</PolicyName>"), "unexpected body: {body}");

        // An inline policy is part of the user carrying it rather than a resource of its own, so
        // PolicyName narrows nothing: a grant naming just the user reaches every inline policy on
        // it.
        for policy_name in ["App-Access", "Db-Access"] {
            let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
            let (status, body) = call(
                &svc_state,
                principal,
                session_data,
                &get_user_policy_parameters(Some("Policy-Holder"), Some(policy_name)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
            assert!(body.contains(&format!("<PolicyName>{policy_name}</PolicyName>")), "unexpected body: {body}");
        }

        // ...and reaches exactly the user it names, and no other.
        let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCGUPPATHRDR001", "Path-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Division-Target"), Some("Division-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCGUPPATHRDR001", "Path-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
        let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("ec2:DescribeInstances"), "unexpected body: {body}");

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Neither does a user carrying no tags at all: the condition key is absent.
        let (principal, session_data) = user_identity("SVCGUPTAGRDR0001", "Tag-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A caller with no grant at all is denied, and is told what it was denied.
        let (principal, session_data) = user_identity("SVCGUPNOGRANTRD1", "No-Grant-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Reader is not authorized to perform: \
                 iam:GetUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Policy-Holder"
            )),
            "unexpected body: {body}"
        );

        // A policy name that is not attached to the user is reported as missing to a caller
        // allowed to read the user's policies.
        let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("No-Such-Policy")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:GetUserPolicy on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCGUPNARROWRDR1", "Narrow-Reader");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Both names are required; neither defaults to anything.
        for parameters in [
            get_user_policy_parameters(Some("Policy-Holder"), None),
            get_user_policy_parameters(None, Some("App-Access")),
        ] {
            let (principal, session_data) = user_identity("SVCGUPBROADRDR01", "Broad-Reader");
            let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
            assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
        }

        // An assumed-role session is governed by the role's own policy.
        let (principal, session_data) = role_identity("SVCGUPROLE000001", "Get-User-Policy-Role");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Holder"), Some("Db-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("dynamodb:GetItem"), "unexpected body: {body}");

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("ses:SendEmail"), "unexpected body: {body}");
    }

    /// End-to-end authorization checks for `PutUserPolicy` through `serve_request` against an
    /// embedded PostgreSQL database. A single test function is used because the database is
    /// stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_put_user_policy_authorization() {
        /// The document the tests first write under a policy name.
        const FIRST_DOCUMENT: &str =
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;

        /// The document the tests then write under the same policy name, replacing the first.
        const SECOND_DOCUMENT: &str =
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}]}"#;

        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(PUT_USER_POLICY_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:PutUserPolicy on any user adds an inline policy to one.
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<PutUserPolicyResponse"), "unexpected body: {body}");

        // The write was committed rather than rolled back, so the policy can be read back.
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("New-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("s3:ListBucket"), "unexpected body: {body}");

        // Writing the same policy name again replaces the document rather than failing.
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), Some(SECOND_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("New-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");
        assert!(!decoded_policy_document(&body).contains("s3:ListBucket"), "unexpected body: {body}");

        // A document that does not parse as a policy is rejected. The caller is allowed the
        // action, so it learns the document is malformed rather than that it was denied.
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("Bad-Access"), Some("this is not a policy")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedPolicyDocument</Code>"), "unexpected body: {body}");

        // A caller with no grant at all is denied, and is told what it was denied.
        let (principal, session_data) = user_identity("SVCPUPNOGRANTWR1", "No-Grant-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("Denied-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Writer is not authorized to perform: \
                 iam:PutUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Policy-Target"
            )),
            "unexpected body: {body}"
        );

        // The denial rolled the transaction back, so nothing was written.
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("Denied-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCPUPPATHWTR001", "Path-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Division-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCPUPPATHWTR001", "Path-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("Division-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
        let (principal, session_data) = user_identity("SVCPUPTAGWTR0001", "Tag-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCPUPTAGWTR0001", "Tag-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // An inline policy is part of the user carrying it rather than a resource of its own, so
        // PolicyName narrows nothing: a grant naming just the user allows replacing the policies
        // that user already carries as well as adding new ones.
        let (principal, session_data) = user_identity("SVCPUPNARROWWTR1", "Narrow-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Policy-Target"), Some("Existing-Access"), Some(SECOND_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("Existing-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("sqs:SendMessage"), "unexpected body: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:PutUserPolicy on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("No-Such-User"), Some("New-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCPUPNARROWWTR1", "Narrow-Writer");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("No-Such-User"), Some("New-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // All three parameters are required; none defaults to anything.
        for parameters in [
            put_user_policy_parameters(None, Some("New-Access"), Some(FIRST_DOCUMENT)),
            put_user_policy_parameters(Some("Policy-Target"), None, Some(FIRST_DOCUMENT)),
            put_user_policy_parameters(Some("Policy-Target"), Some("New-Access"), None),
        ] {
            let (principal, session_data) = user_identity("SVCPUPBROADWTR01", "Broad-Writer");
            let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
            assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
        }

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &put_user_policy_parameters(Some("Root-Target"), Some("Root-Access"), Some(FIRST_DOCUMENT)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    /// End-to-end authorization checks for `DeleteUserPolicy` through `serve_request` against an
    /// embedded PostgreSQL database. A single test function is used because the database is
    /// stateful and expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_delete_user_policy_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(DELETE_USER_POLICY_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:DeleteUserPolicy on any user removes an inline policy from one.
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<DeleteUserPolicyResponse"), "unexpected body: {body}");

        // The delete was committed rather than rolled back, so the policy is gone. The same
        // caller is allowed iam:GetUserPolicy, so it is told the policy no longer exists.
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // Deleting it a second time reports that it no longer exists rather than succeeding
        // silently.
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Policy-Target"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // A caller with no grant at all is denied, and is told what it was denied.
        let (principal, session_data) = user_identity("SVCDUPNOGRANTDL1", "No-Grant-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Deleter is not authorized to perform: \
                 iam:DeleteUserPolicy on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Policy-Target"
            )),
            "unexpected body: {body}"
        );

        // The denial rolled the transaction back, so the policy is still there.
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &get_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(decoded_policy_document(&body).contains("sns:Publish"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCDUPPATHDEL001", "Path-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Division-Target"), Some("Division-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCDUPPATHDEL001", "Path-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Policy-Target"), Some("Keep-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags on the user the policy is embedded in back the aws:ResourceTag condition keys.
        let (principal, session_data) = user_identity("SVCDUPTAGDEL0001", "Tag-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Engineering-Target"), Some("Eng-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCDUPTAGDEL0001", "Tag-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Sales-Target"), Some("Sales-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // An inline policy is part of the user carrying it rather than a resource of its own, so
        // PolicyName narrows nothing: a grant naming just the user reaches every inline policy on
        // it.
        let (principal, session_data) = user_identity("SVCDUPNARROWDEL1", "Narrow-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Policy-Target"), Some("Db-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:DeleteUserPolicy on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCDUPNARROWDEL1", "Narrow-Deleter");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("No-Such-User"), Some("App-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Both names are required; neither defaults to anything.
        for parameters in [
            delete_user_policy_parameters(Some("Policy-Target"), None),
            delete_user_policy_parameters(None, Some("Keep-Access")),
        ] {
            let (principal, session_data) = user_identity("SVCDUPBROADDEL01", "Broad-Deleter");
            let (status, body) = call(&svc_state, principal, session_data, &parameters).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
            assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");
        }

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &delete_user_policy_parameters(Some("Root-Target"), Some("Root-Access")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    /// End-to-end authorization checks for `TagUser` through `serve_request` against an embedded
    /// PostgreSQL database. A single test function is used because the database is stateful and
    /// expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_tag_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(TAG_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:TagUser on any user adds a tag to one.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Tag-Target"), &[("Team", "Platform")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<TagUserResponse"), "unexpected body: {body}");

        // The write was committed rather than rolled back, and it added the tag alongside the one
        // the user was already carrying rather than replacing the lot.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<Key>Team</Key><Value>Platform</Value>"), "unexpected body: {body}");
        assert!(body.contains("<Key>Env</Key><Value>Staging</Value>"), "unexpected body: {body}");

        // A tag whose key is already on the user replaces that tag's value.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Tag-Target"), &[("Env", "Production")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<Key>Env</Key><Value>Production</Value>"), "unexpected body: {body}");
        assert!(!body.contains("<Value>Staging</Value>"), "unexpected body: {body}");

        // A caller with no grant at all is denied, and is told what it was denied.
        let (principal, session_data) = user_identity("SVCTUSNOGRANTTG1", "No-Grant-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Denied", "Yes")]))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Tagger is not authorized to perform: \
                 iam:TagUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Tag-Target"
            )),
            "unexpected body: {body}"
        );

        // The denial rolled the transaction back, so the tag was not applied.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(&svc_state, principal, session_data, &get_user_parameters(Some("Tag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(!body.contains("<Key>Denied</Key>"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCTUSPATHTAG001", "Path-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Division-Target"), &[("Team", "Division")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCTUSPATHTAG001", "Path-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Team", "Other")]))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags the request asks to apply back the aws:RequestTag condition keys. The policy
        // spells the tag key in lower case while the request spells it "Department", confirming
        // that tag keys are matched case-insensitively.
        let (principal, session_data) = user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Request-Target"), &[("Department", "Engineering")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A request asking for the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Request-Target"), &[("Department", "Sales")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Neither does a request naming some other tag entirely: the condition key is absent, so
        // the grant does not apply rather than matching an empty value. The tag the user is
        // already carrying is a different condition key and does not stand in for it.
        let (principal, session_data) = user_identity("SVCTUSREQTAG0001", "Request-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Request-Target"), &[("Team", "Platform")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A grant conditioned on aws:TagKeys limits which tags the request may name at all,
        // whatever values it asks to give them.
        let (principal, session_data) = user_identity("SVCTUSKEYSTAG001", "Tag-Key-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Keys-Target"), &[("Department", "Engineering"), ("Project", "Scratchstack")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // One tag key outside the set the policy lists is enough to fail, even alongside keys
        // that are in it.
        let (principal, session_data) = user_identity("SVCTUSKEYSTAG001", "Tag-Key-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Keys-Target"), &[("Department", "Engineering"), ("CostCenter", "1234")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags the target user already carries back the aws:ResourceTag condition keys, which
        // is a different question from what the request asks to apply: this grant limits which
        // users may be tagged rather than what they may be tagged with.
        let (principal, session_data) = user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Engineering-Target"), &[("Team", "Platform")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user carrying the tag with a different value does not satisfy the condition, and
        // neither does one carrying no such tag at all.
        for user_name in ["Sales-Target", "Tag-Target"] {
            let (principal, session_data) = user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
            let (status, body) =
                call(&svc_state, principal, session_data, &tag_user_parameters(Some(user_name), &[("Team", "Other")]))
                    .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
            assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");
        }

        // Being allowed to tag a user carries being allowed to overwrite the tags that grant is
        // conditioned on: the request is authorized against the tags as they stand, so the caller
        // can move the user out of its own grant's reach...
        let (principal, session_data) = user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Engineering-Target"), &[("Department", "Sales")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and cannot reach it afterwards.
        let (principal, session_data) = user_identity("SVCTUSRESTAG0001", "Resource-Tag-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Engineering-Target"), &[("Team", "Other")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A grant naming a single user reaches every tag on it: the tag key narrows nothing.
        let (principal, session_data) = user_identity("SVCTUSNARROWTAG1", "Narrow-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[("Narrow", "Yes")]))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:TagUser on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("No-Such-User"), &[("Team", "Platform")]),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCTUSNARROWTAG1", "Narrow-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("No-Such-User"), &[("Team", "Platform")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // Two tags with the same key ask for two values for one tag, which is the caller's error
        // rather than a silent last-one-wins. The keys here differ only in case, which IAM treats
        // as the same key.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &tag_user_parameters(Some("Tag-Target"), &[("Department", "Engineering"), ("department", "Sales")]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(
            body.contains(
                "<Code>InvalidInput</Code><Message>Duplicate tag keys found. \
                 Please note that Tag keys are case insensitive.</Message>"
            ),
            "unexpected body: {body}"
        );

        // A request naming no tags at all has nothing to apply and is rejected rather than
        // succeeding silently.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some("Tag-Target"), &[])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

        // UserName is required; it does not default to the calling user.
        let (principal, session_data) = user_identity("SVCTUSBROADTAG01", "Broad-Tagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(None, &[("Team", "Platform")])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) =
            call(&svc_state, principal, session_data, &tag_user_parameters(Some("Root-Target"), &[("Root", "Tag")]))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }

    /// End-to-end authorization checks for `UntagUser` through `serve_request` against an embedded
    /// PostgreSQL database. A single test function is used because the database is stateful and
    /// expensive to start.
    #[test_log::test(tokio::test)]
    async fn test_untag_user_authorization() {
        let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
        database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
        let pool = database
            .get_scratchstack_pool()
            .await
            .expect("Failed to get PostgreSQL connection pool for scratchstack user");

        let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
        MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
        raw_sql(UNTAG_USER_TEST_DATA).execute(&mut *c).await.expect("Failed to load test data into database");
        drop(c);

        let svc_state = ServiceState::builder().db(Arc::new(pool)).secure_transport(true).build();

        // A caller allowed iam:UntagUser on any user removes a tag from one.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Department"]))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<UntagUserResponse"), "unexpected body: {body}");

        // The delete was committed rather than rolled back, and it removed the tag the request
        // named and no others.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(!body.contains("<Key>Department</Key>"), "unexpected body: {body}");
        assert!(body.contains("<Key>Project</Key><Value>Scratchstack</Value>"), "unexpected body: {body}");
        assert!(body.contains("<Key>Keep</Key><Value>Yes</Value>"), "unexpected body: {body}");

        // A key the user is not carrying is not an error: the request asks for the user to be left
        // without that tag, and it already is.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["No-Such-Tag"]))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A caller with no grant at all is denied, and is told what it was denied.
        let (principal, session_data) = user_identity("SVCUTSNOGRANTUT1", "No-Grant-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(
            body.contains(&format!(
                "User: arn:aws:iam::{TEST_ACCOUNT_ID}:user/No-Grant-Untagger is not authorized to perform: \
                 iam:UntagUser on resource: arn:aws:iam::{TEST_ACCOUNT_ID}:user/Untag-Target"
            )),
            "unexpected body: {body}"
        );

        // The denial rolled the transaction back, so the tag is still there.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(body.contains("<Key>Keep</Key><Value>Yes</Value>"), "unexpected body: {body}");

        // The resource ARN carries the target user's path, so a grant scoped to a path prefix
        // reaches users under that path...
        let (principal, session_data) = user_identity("SVCUTSPATHUTG001", "Path-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Division-Target"), &["Project"]))
                .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and no further.
        let (principal, session_data) = user_identity("SVCUTSPATHUTG001", "Path-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The request names tag keys and no values, so aws:TagKeys is the condition key that
        // governs which tags a caller may remove.
        let (principal, session_data) = user_identity("SVCUTSKEYSUTG001", "Tag-Key-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Project"])).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &get_user_parameters(Some("Untag-Target"))).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
        assert!(!body.contains("<Key>Project</Key>"), "unexpected body: {body}");

        // One tag key outside the set the policy lists is enough to fail, even alongside keys
        // that are in it.
        let (principal, session_data) = user_identity("SVCUTSKEYSUTG001", "Tag-Key-Untagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &untag_user_parameters(Some("Engineering-Target"), &["Project", "CostCenter"]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags the target user carries back the aws:ResourceTag condition keys, which limits
        // which users a caller may untag rather than which tags it may take off them.
        let (principal, session_data) = user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &untag_user_parameters(Some("Engineering-Target"), &["CostCenter"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user carrying the tag with a different value does not satisfy the condition.
        let (principal, session_data) = user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Sales-Target"), &["Department"]))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // The tags are the ones the user carries before the removal, so a grant conditioned on a
        // tag reaches the request that takes that very tag off...
        let (principal, session_data) = user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &untag_user_parameters(Some("Engineering-Target"), &["Department"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // ...and does not reach the user afterwards.
        let (principal, session_data) = user_identity("SVCUTSRESUTG0001", "Resource-Tag-Untagger");
        let (status, body) = call(
            &svc_state,
            principal,
            session_data,
            &untag_user_parameters(Some("Engineering-Target"), &["No-Such-Tag"]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A grant naming a single user reaches every tag on it: the tag key narrows nothing.
        let (principal, session_data) = user_identity("SVCUTSNARROWUTG1", "Narrow-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &["Keep"])).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");

        // A user that does not exist is still authorized against the ARN the request names, so a
        // caller allowed iam:UntagUser on any user is told the user is missing...
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("No-Such-User"), &["Department"]))
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unexpected response: {body}");
        assert!(body.contains("<Code>NoSuchEntity</Code>"), "unexpected body: {body}");

        // ...while a caller allowed it only on a specific user learns nothing about it.
        let (principal, session_data) = user_identity("SVCUTSNARROWUTG1", "Narrow-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("No-Such-User"), &["Department"]))
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "unexpected response: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "unexpected body: {body}");

        // A request naming no tag keys at all has nothing to remove and is rejected rather than
        // succeeding silently.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Untag-Target"), &[])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>ValidationError</Code>"), "unexpected body: {body}");

        // UserName is required; it does not default to the calling user.
        let (principal, session_data) = user_identity("SVCUTSBROADUTG01", "Broad-Untagger");
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(None, &["Department"])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected response: {body}");
        assert!(body.contains("<Code>MalformedInput</Code>"), "unexpected body: {body}");

        // The account root user is implicitly allowed.
        let (principal, session_data) = root_identity();
        let (status, body) =
            call(&svc_state, principal, session_data, &untag_user_parameters(Some("Root-Target"), &["Root"])).await;
        assert_eq!(status, StatusCode::OK, "unexpected response: {body}");
    }
}
