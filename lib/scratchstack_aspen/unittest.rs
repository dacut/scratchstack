use crate::{Action, ActionList, Effect, Policy, StatementList};
use std::str::FromStr;

#[test_env_log::test]
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

#[test_env_log::test]
fn test_typical_policy_import() {
    let policy_str = r#"{
    "Version": "2012-10-17",
    "Id": "PolicyId",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Action": [
                "ec2:Get*",
                "ecs:*"
            ],
            "Resource": "*",
            "Principal": {
                "AWS": "123456789012"
            },
            "Condition": {
                "StringEquals": {
                    "ec2:Region": [
                        "us-west-2",
                        "us-west-1",
                        "us-east-2",
                        "us-east-1"
                    ]
                }
            }
        },
        {
            "Sid": "2",
            "Effect": "Deny",
            "Action": "*",
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ],
            "Principal": "*"
        }
    ]
}"#;
    let policy = Policy::from_str(policy_str).unwrap();

    assert_eq!(policy.version, Some("2012-10-17".to_string()));
    assert_eq!(policy.id, Some("PolicyId".to_string()));

    if let StatementList::List(ref statements) = policy.statement {
        let s = &statements[0];
        assert_eq!(s.effect, Effect::Allow);
        match &s.action {
            None | Some(ActionList::Single(_)) => {
                panic!("Expected a list of actions")
            }
            Some(ActionList::List(ref a_list)) => {
                match &a_list[0] {
                    Action::Specific { service, action } => {
                        assert_eq!(service, "ec2");
                        assert_eq!(action, "Get*");
                    }
                    _ => {
                        panic!("Expected a specific action");
                    }
                }
                match &a_list[1] {
                    Action::Specific { service, action } => {
                        assert_eq!(service, "ecs");
                        assert_eq!(action, "*");
                    }
                    _ => {
                        panic!("Expected a specific action");
                    }
                }
            }
        }
        assert!(s.condition.as_ref().is_some());
        assert!(s.condition.as_ref().unwrap().string_equals.is_some());
    } else {
        panic!("Expected single statement: {:?}", policy.statement);
    }

    let new_policy_str = policy.to_string();
    assert_eq!(new_policy_str, policy_str);
}
