# scratchstack-aspen

AWS IAM policy language (Aspen) parser, representation, and evaluator.

Aspen is the language IAM policy documents are written in. This crate parses such a document into a
typed representation, serializes one back, and evaluates a request against a set of them —
resolving allows, explicit denies, permissions boundaries, condition operators, and policy
variables.

```rust
use scratchstack_aspen::{authorize, Context, Decision, Policy, PolicySet, PolicySource};
use scratchstack_arn::Arn;
use scratchstack_aws_principal::{Principal, SessionData, User};
use std::str::FromStr;

let policy = Policy::from_str(
    r#"{"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::examplebucket/*"}
    ]}"#,
)?;

let mut policy_set = PolicySet::new();
policy_set.add_policy(
    PolicySource::new_entity_inline("arn:aws:iam::123456789012:user/exampleuser", "AIDAEXAMPLE", "ReadObjects"),
    policy,
);

let context = Context::builder()
    .service("s3")
    .api("GetObject")
    .actor(Principal::from(User::from_str("arn:aws:iam::123456789012:user/exampleuser")?))
    .resources(vec![Arn::from_str("arn:aws:s3:::examplebucket/hello.txt")?])
    .session_data(SessionData::new())
    .build()?;

assert_eq!(authorize(&context, &policy_set)?.decision(), Decision::Allow);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

`sensitive-logging` emits log records carrying the contents of an authorization request — policy
documents, principals, resources, and session data. It is off by default, and the records are not
compiled in at all without it. It forwards to the feature of the same name in `scratchstack-core`,
which provides the `sensitive_log` family of macros.
