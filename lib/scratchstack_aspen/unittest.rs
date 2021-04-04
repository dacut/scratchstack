use crate::Policy;
use std::str::FromStr;

#[test]
fn test_blank_policy_import() {
    let policy = Policy::from_str(
        r#"{
    "Version": "2012-10-17",
    "Statement": []
}"#,
    )
    .unwrap();
    assert_eq!(policy.version, Some("2012-10-17".to_string()));
    assert!(policy.id.is_none());

    let policy_str = policy.to_string();
    assert_eq!(
        policy_str,
        r#"{
    "Version": "2012-10-17",
    "Statement": []
}"#
    );
}
