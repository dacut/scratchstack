use {
    crate::{Condition, Context, PolicyVersion},
    chrono::DateTime,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, PrincipalIdentity, Service, SessionData, SessionValue},
    std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    },
};

fn session_matches(cmap: &Condition, session_data: &SessionData) -> bool {
    let context = make_context(session_data);
    cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap()
}

fn make_context(session_data: &SessionData) -> Context {
    let principal: Principal =
        vec![PrincipalIdentity::from(Service::new("example", None, "amazonaws.com").unwrap())].into();
    Context::builder()
        .action("service:action")
        .actor(principal)
        .resources(vec![Arn::new("aws", "s3", "", "", "example").unwrap()])
        .session_data(session_data.clone())
        .service("service")
        .build()
        .unwrap()
}

#[test_log::test]
fn test_arn_equals() {
    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": ["arn:aw*:ec?:us-*-1:*:instance/i-*", "arn:not:valid", "this:is:also:not:a:valid:arn"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not an arn"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:not:valid"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this:is:also:not:a:valid:arn"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(3));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"ArnEqualsIfExists": {"hello": ["arn:aw*:ec?:us-*-1:*:instance/i-*", "arn:not:valid", "this:is:also:not:a:valid:arn"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not an arn"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:not:valid"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this:is:also:not:a:valid:arn"));
    assert!(!session_matches(&cmap, &session_data));

    let _ = format!("{:?}", cmap);
}

#[test_log::test]
fn test_arn_equals_variables() {
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/bob/object"));

    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": ["arn:aws:s3:::bucket/${aws:username}/*"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/bob/object"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:username", SessionValue::from("bob"));
    assert!(session_matches(&cmap, &session_data));

    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());

    session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/${aws:username}/object"));
    let context = make_context(&session_data);
    assert!(cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
    assert!(cmap.matches(&context, PolicyVersion::None).unwrap());

    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": "arn:${not_allowed}:s3:::bucket/bob/*"}}"#).unwrap();
    session_data.insert("not_allowed", SessionValue::from("s3"));
    session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/bob/object"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_arn_equals_bad_variables() {
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("arn:aws:s3:::bucket/bob/object"));
    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": ["arn:aws:s3:::bucket/${unterminated"]}}"#).unwrap();
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: bucket/${unterminated");

    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": ["arn:aws:s3:::bucket/$"]}}"#).unwrap();
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: bucket/$");

    let cmap = Condition::from_str(r#"{"ArnEquals": {"hello": ["arn:aws:s3:::bucket/$[]"]}}"#).unwrap();
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: bucket/$[]");
}

#[test_log::test]
fn test_arn_not_equals() {
    let cmap = Condition::from_str(r#"{"ArnNotEquals": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#).unwrap();
    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not an arn"));
    assert!(session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"ArnNotEqualsIfExists": {"hello": "arn:aw*:ec?:us-*-1:*:instance/i-*"}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:foo:ec2:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:us-east-1:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-west-2:123456789012:instance/i-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("hello", SessionValue::from("arn:aws:ec2:us-east-1:123456789012:security-group/sg-01234567890abcdef0"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not an arn"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_binary() {
    let cmap =
        Condition::from_str(r#"{"BinaryEquals": {"hello": ["d29ybGQ=", "YmFy", ":::illegal-base-64!!@#"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'w', b'o', b'r', b'l', b'd']));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'b', b'a', b'r']));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("world".to_string()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("bar".to_string()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'x', b'y', b'z']));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("xyz".to_string()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Integer(123));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"BinaryEqualsIfExists": {"hello": ["d29ybGQ=", "YmFy"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'w', b'o', b'r', b'l', b'd']));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'b', b'a', b'r']));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("world".to_string()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("bar".to_string()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Binary(vec![b'x', b'y', b'z']));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::String("xyz".to_string()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::Integer(123));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_bool() {
    let cmap = Condition::from_str(r#"{"Bool": {"hello": ["false"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("hello world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(7));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"Bool": {"hello": ["true"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"Bool": {"hello": []}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"BoolIfExists": {"hello": "false"}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"BoolIfExists": {"hello": "true"}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"BoolIfExists": {"hello": []}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_bool_variable() {
    let cmap = Condition::from_str(r#"{"Bool": {"hello": ["${valid}"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("valid", SessionValue::from("false"));
    session_data.insert("hello", SessionValue::from(false));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("valid", SessionValue::from("true"));
    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("valid", SessionValue::from("neither"));
    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("valid", SessionValue::from("true"));
    session_data.insert("hello", SessionValue::from(false));
    let context = make_context(&session_data);

    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
}

#[test_log::test]
fn test_bool_bad_variable() {
    let cmap = Condition::from_str(r#"{"Bool": {"hello": ["${invalid"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from(true));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${invalid");
}

#[test_log::test]
fn test_date_equals() {
    let cmap = Condition::from_str(r#"{"DateEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from(30));
    assert!(!session_matches(&cmap, &session_data));

    // Unix timestamp
    let cmap = Condition::from_str(r#"{"DateEquals": {"aws:CurrentDate": ["1350432000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"DateEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_not_equals() {
    let cmap = Condition::from_str(r#"{"DateNotEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"DateNotEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_less_than() {
    let cmap = Condition::from_str(r#"{"DateLessThan": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"DateLessThanIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_less_than_equals() {
    let cmap = Condition::from_str(r#"{"DateLessThanEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"DateLessThanEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
        .unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_greater_than() {
    let cmap = Condition::from_str(r#"{"DateGreaterThan": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"DateGreaterThanIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_greater_than_equals() {
    let cmap =
        Condition::from_str(r#"{"DateGreaterThanEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"DateGreaterThanEqualsIfExists": {"aws:CurrentDate": ["2012-10-17T00:00:00Z"]}}"#)
            .unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-16T00:00:00Z"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-17T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("2012-10-18T00:00:00Z"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:CurrentDate", SessionValue::from("not a date"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_date_variable() {
    let cmap = Condition::from_str(r#"{"DateEquals": {"aws:CurrentDate": ["${hello}"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("2012-10-17T00:00:00Z"));
    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-17T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    // Bad policy version.
    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
}

#[test_log::test]
fn test_date_bad_variable() {
    // Unterminated variable
    let cmap = Condition::from_str(r#"{"DateEquals": {"aws:CurrentDate": ["${hello"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("2012-10-17T00:00:00Z"));
    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));

    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${hello");
}

#[test_log::test]
fn test_ip_address() {
    let cmap = Condition::from_str(
        r#"{"IpAddress": {"aws:SourceIp": ["invalid-ip-addr", "1.2.3.4", "fe80::1", "10.0.0.0/8", "fe80::/10"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(11, 1, 2, 3)));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0x0100, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from("Hello World"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(6));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"IpAddressIfExists": {"aws:SourceIp": ["10.0.0.0/8", "fe80::/10"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(11, 1, 2, 3)));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0x0100, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_not_ip_address() {
    let cmap = Condition::from_str(r#"{"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(11, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0x0100, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NotIpAddress": {"aws:SourceIp": ["fe80::/10"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(11, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0x0100, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_ip_address_variable() {
    let cmap = Condition::from_str(r#"{"IpAddress": {"aws:SourceIp": ["${ipv4}", "${ipv6}"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("ipv4", SessionValue::from("10.0.0.0/8"));
    session_data.insert("ipv6", SessionValue::from("fe80::/10"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0xfe80, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(11, 1, 2, 3)));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:SourceIp", SessionValue::from(Ipv6Addr::new(0x0100, 0x0, 0x0, 0x0, 0x0, 0x0, 0xdead, 0xbeef)));
    assert!(!session_matches(&cmap, &session_data));

    // Version that doesn't support variables
    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));

    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
}

#[test_log::test]
fn test_ip_address_bad_variable() {
    let cmap = Condition::from_str(r#"{"IpAddress": {"aws:SourceIp": ["${ipv4", "${ipv6"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(10, 1, 2, 3)));
    session_data.insert("ipv4", SessionValue::from("10.0.0.0/8"));
    session_data.insert("ipv6", SessionValue::from("fe80::/10"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${ipv4");
}

#[test_log::test]
fn test_null() {
    let cmap = Condition::from_str(r#"{"Null": {"hello": ["true"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"Null": {"hello": ["false"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"Null": {"hello": []}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"Null": {"hello": ["true", "false"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_null_variable() {
    let cmap = Condition::from_str(r#"{"Null": {"hello": ["${value}"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("value", SessionValue::from("true"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("value", SessionValue::from("false"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("value", SessionValue::from("true"));
    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("value", SessionValue::from("false"));
    assert!(session_matches(&cmap, &session_data));

    // Version that doesn't support variables
    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
}

#[test_log::test]
fn test_null_bad_variable() {
    let cmap = Condition::from_str(r#"{"Null": {"hello": ["${value"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("value", SessionValue::from("true"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${value");
}

#[test_log::test]
fn test_numeric_equals() {
    let cmap = Condition::from_str(r#"{"NumericEquals": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-not-a-number"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(false));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericEqualsIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_numeric_equals_variable() {
    let cmap = Condition::from_str(r#"{"NumericEquals": {"hello": ["${value}"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("value", SessionValue::from(1000));
    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));

    // Version that doesn't support variables
    session_data.insert("hello", SessionValue::from(1000));
    session_data.insert("value", SessionValue::from(1000));
    let context = make_context(&session_data);

    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());

    session_data.insert("hello", SessionValue::from("1000"));
    session_data.insert("value", SessionValue::from("1000"));
    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
}

#[test_log::test]
fn test_numeric_bad_variable() {
    let cmap = Condition::from_str(r#"{"NumericEquals": {"hello": ["${value"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from(1000));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${value");

    session_data.insert("hello", SessionValue::from("1000"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${value");
}

#[test_log::test]
fn test_numeric_not_equals() {
    let cmap = Condition::from_str(r#"{"NumericNotEquals": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericNotEqualsIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_numeric_less_than() {
    let cmap = Condition::from_str(r#"{"NumericLessThan": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericLessThanIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_numeric_less_than_equals() {
    let cmap = Condition::from_str(r#"{"NumericLessThanEquals": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericLessThanEqualsIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_numeric_greater_than() {
    let cmap = Condition::from_str(r#"{"NumericGreaterThan": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericGreaterThanIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_numeric_greater_than_equals() {
    let cmap = Condition::from_str(r#"{"NumericGreaterThanEquals": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericGreaterThanEqualsIfExists": {"hello": ["1000"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(999));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1000));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1001));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("999"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1000"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1001"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_like() {
    let cmap =
        Condition::from_str(r#"{"StringLike": {"hello": ["w*ld", "b?r", "this-is-a-**", "e${*}a${$}t", "huh${?}"]}}"#)
            .unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("wld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world1"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("br"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("huh", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(
        r#"{"StringLikeIfExists": {"hello": ["w*ld", "b?r", "this-is-a-**", "e${*}a${$}t", "huh${?}"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("wld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world1"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("br"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("huh", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_like_variables() {
    let cmap = Condition::from_str(r#"{"StringLike": {"hello": ["${test_match}"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("test_match", SessionValue::from("w*ld"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    let context = make_context(&session_data);
    assert!(!cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
    assert!(!cmap.matches(&context, PolicyVersion::None).unwrap());

    session_data.insert("hello", SessionValue::from("${test_match}"));
    let context = make_context(&session_data);
    assert!(cmap.matches(&context, PolicyVersion::V2008_10_17).unwrap());
    assert!(cmap.matches(&context, PolicyVersion::None).unwrap());
}

#[test_log::test]
fn test_string_like_bad_variables() {
    let cmap = Condition::from_str(r#"{"StringLike": {"hello": ["${test_match"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("test_match", SessionValue::from("w*ld"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${test_match");
}

#[test_log::test]
fn test_string_not_like() {
    let cmap = Condition::from_str(r#"{"StringNotLike": {"hello": ["w*ld"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("wld"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world1"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotLikeIfExists": {"hello": ["w*ld"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("wld"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world1"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("br"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_equals() {
    let cmap = Condition::from_str(
        r#"{"StringEquals": {"hello": ["w*ld", "b?r", "this-is-a-**", "e${*}a${$}t", "huh${?}"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-**"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("?", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(true));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(
        r#"{"StringEqualsIfExists": {"hello": ["w*ld", "b?r", "this-is-a-**", "e${*}a${$}t", "huh${?}"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-**"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("?", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_equals_bad_variables() {
    let cmap = Condition::from_str(r#"{"StringEquals": {"hello": ["${test_match"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("test_match", SessionValue::from("w*ld"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${test_match");
}

#[test_log::test]
fn test_string_not_equals() {
    let cmap = Condition::from_str(r#"{"StringNotEquals": {"hello": ["w*ld"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotEquals": {"hello": ["${expr}"]}}"#).unwrap();
    session_data.insert("expr", SessionValue::from("b?r"));
    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotEqualsIfExists": {"hello": ["w*ld"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotEqualsIfExists": {"hello": ["${expr}"]}}"#).unwrap();
    session_data.insert("expr", SessionValue::from("b?r"));
    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_equals_ignore_case() {
    let cmap = Condition::from_str(
        r#"{"StringEqualsIgnoreCase": {"hello": ["W*lD", "B?r", "This-is-a-**", "E${*}a${$}t", "Huh${?}"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-**"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("?", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(
        r#"{"StringEqualsIgnoreCaseIfExists": {"hello": ["W*lD", "B?r", "This-is-a-**", "E${*}a${$}t", "Huh${?}"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("w*ld"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("b?r"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-**"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e*a$t"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("huh?"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("bar"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("this-is-a-test"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("not-valid-world"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${*}a${$}t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("e${1234}a$t"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("?", SessionValue::from("1"));
    session_data.insert("hello", SessionValue::from("huh1"));
    assert!(!session_matches(&cmap, &session_data));
}

#[test_log::test]
fn test_string_equals_ignore_case_bad_variables() {
    let cmap = Condition::from_str(r#"{"StringEqualsIgnoreCase": {"hello": ["${test_match"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("test_match", SessionValue::from("w*ld"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: ${test_match");

    let cmap = Condition::from_str(r#"{"StringEqualsIgnoreCase": {"hello": ["$"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("test_match", SessionValue::from("w*ld"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: $");

    let cmap = Condition::from_str(r#"{"StringEqualsIgnoreCase": {"hello": ["$!"]}}"#).unwrap();
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("test_match", SessionValue::from("w*ld"));
    let context = make_context(&session_data);
    let e = cmap.matches(&context, PolicyVersion::V2012_10_17).unwrap_err();
    assert_eq!(e.to_string(), "Invalid variable substitution: $!");
}
