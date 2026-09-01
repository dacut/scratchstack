use {
    crate::{Condition, Context, PolicyVersion, condop},
    chrono::DateTime,
    scratchstack_arn::Arn,
    scratchstack_aws_principal::{Principal, Service, SessionData, SessionValue},
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
    let principal =
        Principal::from(Service::builder().service_name("example").dns_suffix("amazonaws.com").build().unwrap());
    Context::builder()
        .api("action")
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

    let _ = format!("{cmap:?}");
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

/// `ForAllValues:` matches when every value a multivalued key holds matches one of the values the
/// policy lists. A key holding no values matches vacuously.
#[test_log::test]
fn test_for_all_values() {
    let cmap = Condition::from_str(r#"{"ForAllValues:StringEquals": {"hello": ["red", "green", "blue"]}}"#).unwrap();

    // An absent key holds no values, so every one of them matches.
    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    // So does a key supplied with an empty set of values.
    session_data.insert("hello", SessionValue::list(Vec::<String>::new()));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["red"]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["blue", "red"]));
    assert!(session_matches(&cmap, &session_data));

    // One value outside the policy's set is enough to fail.
    session_data.insert("hello", SessionValue::list(["red", "purple"]));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["purple"]));
    assert!(!session_matches(&cmap, &session_data));

    // A single-valued key is a set of one.
    session_data.insert("hello", SessionValue::from("green"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("purple"));
    assert!(!session_matches(&cmap, &session_data));

    // A value of a type the comparison cannot compare matches nothing.
    session_data.insert("hello", SessionValue::list([SessionValue::from("red"), SessionValue::from(3)]));
    assert!(!session_matches(&cmap, &session_data));
}

/// `ForAnyValue:` matches when at least one value a multivalued key holds matches one of the
/// values the policy lists. A key holding no values has nothing to match.
#[test_log::test]
fn test_for_any_value() {
    let cmap = Condition::from_str(r#"{"ForAnyValue:StringEquals": {"hello": ["red", "green", "blue"]}}"#).unwrap();

    // An absent key holds no value that could match.
    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    // Neither does a key supplied with an empty set of values.
    session_data.insert("hello", SessionValue::list(Vec::<String>::new()));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["red"]));
    assert!(session_matches(&cmap, &session_data));

    // One value inside the policy's set is enough to match, whatever the others are.
    session_data.insert("hello", SessionValue::list(["purple", "green"]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["purple", "orange"]));
    assert!(!session_matches(&cmap, &session_data));

    // A single-valued key is a set of one.
    session_data.insert("hello", SessionValue::from("blue"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("purple"));
    assert!(!session_matches(&cmap, &session_data));
}

/// The `IfExists` variant passes over a key the request did not supply, which for `ForAnyValue:`
/// is the only case its answer differs in. (`ForAllValues:` already matches such a key.)
#[test_log::test]
fn test_set_operators_if_exists() {
    let cmap =
        Condition::from_str(r#"{"ForAnyValue:StringEqualsIfExists": {"hello": ["red", "green", "blue"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(Vec::<String>::new()));
    assert!(session_matches(&cmap, &session_data));

    // Once the key holds values, they are compared like any others.
    session_data.insert("hello", SessionValue::list(["purple"]));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["purple", "red"]));
    assert!(session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"ForAllValues:StringEqualsIfExists": {"hello": ["red", "green", "blue"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["red", "purple"]));
    assert!(!session_matches(&cmap, &session_data));
}

/// A negated comparison is applied to each value of the key in turn, so `ForAllValues:` requires
/// every value to match none of the policy's values and `ForAnyValue:` requires only one to.
#[test_log::test]
fn test_set_operators_negated() {
    let cmap = Condition::from_str(r#"{"ForAllValues:StringNotEquals": {"hello": ["red", "green"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["blue", "purple"]));
    assert!(session_matches(&cmap, &session_data));

    // "red" is one of the values the policy lists, so it does not differ from all of them just
    // because it differs from "green".
    session_data.insert("hello", SessionValue::list(["blue", "red"]));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["red"]));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"ForAnyValue:StringNotEquals": {"hello": ["red", "green"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["blue", "red"]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["red", "green"]));
    assert!(!session_matches(&cmap, &session_data));
}

/// The set operators are not tied to string comparisons: they distribute any comparison over the
/// values a key holds.
#[test_log::test]
fn test_set_operators_over_other_comparisons() {
    let cmap = Condition::from_str(r#"{"ForAllValues:NumericLessThan": {"hello": ["10"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::list([SessionValue::from(1), SessionValue::from(9)]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list([SessionValue::from(1), SessionValue::from(10)]));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"ForAnyValue:ArnLike": {"hello": ["arn:aws:s3:::example/*"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::list(["arn:aws:s3:::other/file", "arn:aws:s3:::example/file"]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["arn:aws:s3:::other/file"]));
    assert!(!session_matches(&cmap, &session_data));

    // Variables are substituted in the values the policy lists, as they are without a set
    // operator.
    let cmap = Condition::from_str(r#"{"ForAllValues:StringLike": {"hello": ["${prefix}-*"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("prefix", SessionValue::from("team"));
    session_data.insert("hello", SessionValue::list(["team-a", "team-b"]));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::list(["team-a", "other-b"]));
    assert!(!session_matches(&cmap, &session_data));
}

/// A multivalued key compared without a set operator matches nothing: the comparison has no
/// notion of a set of values to compare against.
#[test_log::test]
fn test_multivalued_key_without_set_operator() {
    let cmap = Condition::from_str(r#"{"StringEquals": {"hello": ["red"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::list(["red"]));
    assert!(!session_matches(&cmap, &session_data));

    // The key is present, so the IfExists variant has nothing to pass over.
    let cmap = Condition::from_str(r#"{"StringEqualsIfExists": {"hello": ["red"]}}"#).unwrap();
    assert!(!session_matches(&cmap, &session_data));

    // A key holding no values is the same as an absent key, which IfExists does pass over.
    session_data.insert("hello", SessionValue::list(Vec::<String>::new()));
    assert!(session_matches(&cmap, &session_data));
}

/// `Null` asks whether the key is present rather than comparing the values it holds, so a set
/// operator has nothing to distribute over and the answer is the same with or without one. A key
/// holding no values counts as absent.
#[test_log::test]
fn test_null_with_multivalued_key() {
    for op in ["Null", "ForAllValues:Null", "ForAnyValue:Null"] {
        let present = Condition::from_str(&format!(r#"{{"{op}": {{"hello": ["false"]}}}}"#)).unwrap();
        let absent = Condition::from_str(&format!(r#"{{"{op}": {{"hello": ["true"]}}}}"#)).unwrap();

        let mut session_data = SessionData::new();
        assert!(!session_matches(&present, &session_data), "{op} with an absent key");
        assert!(session_matches(&absent, &session_data), "{op} with an absent key");

        session_data.insert("hello", SessionValue::list(["red", "green"]));
        assert!(session_matches(&present, &session_data), "{op} with a multivalued key");
        assert!(!session_matches(&absent, &session_data), "{op} with a multivalued key");

        session_data.insert("hello", SessionValue::list(Vec::<String>::new()));
        assert!(!session_matches(&present, &session_data), "{op} with an empty multivalued key");
        assert!(session_matches(&absent, &session_data), "{op} with an empty multivalued key");
    }
}

/// A condition clause naming several operators requires all of them to match, set operators
/// included.
#[test_log::test]
fn test_set_operators_alongside_other_operators() {
    let cmap = Condition::from_str(
        r#"{"ForAllValues:StringEquals": {"tags": ["red", "green"]}, "StringEquals": {"hello": ["world"]}}"#,
    )
    .unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("tags", SessionValue::list(["red"]));
    session_data.insert("hello", SessionValue::from("world"));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("mars"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("world"));
    session_data.insert("tags", SessionValue::list(["red", "purple"]));
    assert!(!session_matches(&cmap, &session_data));
}

/// An operator written with a set operator prefix survives a round trip through the policy
/// document it was read from.
#[test_log::test]
fn test_set_operator_serialization() {
    let source = r#"{"ForAnyValue:StringLike":{"hello":["w*ld"]}}"#;
    let cmap = Condition::from_str(source).unwrap();

    assert!(cmap.contains_key(&condop::StringLike.for_any_value()));
    assert!(!cmap.contains_key(&condop::StringLike));
    assert_eq!(serde_json::to_string(&cmap).unwrap(), source);
}

/// A negated operator with several values in the policy requires the request value to match none
/// of them. AWS evaluates multiple values with a logical OR, which negation turns into a logical
/// AND over the clause -- not into a per-value test that any one of them differs.
#[test_log::test]
fn test_negated_operators_require_no_value_to_match() {
    let cmap = Condition::from_str(r#"{"StringNotEquals": {"hello": ["red", "green"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("red"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("green"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("blue"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotEqualsIgnoreCase": {"hello": ["Red", "Green"]}}"#).unwrap();
    session_data.insert("hello", SessionValue::from("RED"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("blue"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"StringNotLike": {"hello": ["re*", "gr*"]}}"#).unwrap();
    session_data.insert("hello", SessionValue::from("green"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("blue"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericNotEquals": {"hello": ["1000", "2000"]}}"#).unwrap();
    session_data.insert("hello", SessionValue::from(2000));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(1500));
    assert!(session_matches(&cmap, &session_data));

    // The same holds for a numeric value the request supplies as a string.
    session_data.insert("hello", SessionValue::from("2000"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("1500"));
    assert!(session_matches(&cmap, &session_data));

    let cmap =
        Condition::from_str(r#"{"ArnNotEquals": {"hello": ["arn:aws:s3:::example/*", "arn:aws:s3:::other/*"]}}"#)
            .unwrap();
    session_data.insert("hello", SessionValue::from("arn:aws:s3:::other/file"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:::third/file"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"ArnNotLike": {"hello": ["arn:aws:s3:::example/*", "arn:aws:s3:::other/*"]}}"#)
        .unwrap();
    session_data.insert("hello", SessionValue::from("arn:aws:s3:::example/file"));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from("arn:aws:s3:::third/file"));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}}"#).unwrap();
    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!session_matches(&cmap, &session_data));

    session_data.insert("aws:SourceIp", SessionValue::from(Ipv4Addr::new(172, 16, 1, 1)));
    assert!(session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(
        r#"{"DateNotEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z", "2012-10-18T00:00:00Z"]}}"#,
    )
    .unwrap();
    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-19T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));
}

/// The ordering operators are spelled with a negated variant internally -- GreaterThanEquals is
/// LessThan negated -- but they are operators in their own right, not negated clauses. Several
/// values are OR-ed like any other operator's, so matching the loosest of them is enough.
#[test_log::test]
fn test_ordering_operators_or_their_values() {
    let cmap = Condition::from_str(r#"{"NumericGreaterThanEquals": {"hello": ["10", "20"]}}"#).unwrap();

    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from(15));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(5));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(r#"{"NumericGreaterThan": {"hello": ["10", "20"]}}"#).unwrap();
    session_data.insert("hello", SessionValue::from(15));
    assert!(session_matches(&cmap, &session_data));

    session_data.insert("hello", SessionValue::from(10));
    assert!(!session_matches(&cmap, &session_data));

    let cmap = Condition::from_str(
        r#"{"DateGreaterThanEquals": {"aws:CurrentDate": ["2012-10-17T00:00:00Z", "2012-10-19T00:00:00Z"]}}"#,
    )
    .unwrap();
    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-18T00:00:00Z").unwrap()));
    assert!(session_matches(&cmap, &session_data));

    session_data
        .insert("aws:CurrentDate", SessionValue::from(DateTime::parse_from_rfc3339("2012-10-16T00:00:00Z").unwrap()));
    assert!(!session_matches(&cmap, &session_data));
}

/// A condition key holding a string that spells no number, and no timestamp, is answered the same
/// way by the numeric and date comparisons.
///
/// The two are structurally the same function, so they have to agree. Only the `NotEquals` form has
/// an answer -- a value that is not a number differs from every number the policy lists -- and the
/// ordering comparisons match in neither direction.
#[test_log::test]
fn test_unparsable_string_answers_agree_across_comparisons() {
    let mut session_data = SessionData::new();
    session_data.insert("hello", SessionValue::from("not-a-number-or-a-date"));

    // The NotEquals forms match: the value does differ from everything listed.
    for op in ["NumericNotEquals", "DateNotEquals", "StringNotEquals"] {
        let cmap = Condition::from_str(&format!(r#"{{"{op}": {{"hello": ["5", "2012-10-17T00:00:00Z"]}}}}"#)).unwrap();
        assert!(session_matches(&cmap, &session_data), "{op} did not match an unparsable value");
    }

    // The plain Equals forms do not.
    for op in ["NumericEquals", "DateEquals"] {
        let cmap = Condition::from_str(&format!(r#"{{"{op}": {{"hello": ["5", "2012-10-17T00:00:00Z"]}}}}"#)).unwrap();
        assert!(!session_matches(&cmap, &session_data), "{op} matched an unparsable value");
    }

    // Nor do the ordering comparisons, in either direction: an unparsable value is neither below
    // nor above a number, so the negated form is not simply the opposite of the plain one.
    for op in [
        "NumericLessThan",
        "NumericGreaterThanEquals",
        "NumericLessThanEquals",
        "NumericGreaterThan",
        "DateLessThan",
        "DateGreaterThanEquals",
        "DateLessThanEquals",
        "DateGreaterThan",
    ] {
        let cmap = Condition::from_str(&format!(r#"{{"{op}": {{"hello": ["5", "2012-10-17T00:00:00Z"]}}}}"#)).unwrap();
        assert!(!session_matches(&cmap, &session_data), "{op} matched an unparsable value");
    }
}
