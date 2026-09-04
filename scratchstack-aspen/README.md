# scratchstack-aspen

AWS IAM policy language (Aspen) parser, representation, and evaluator.

Aspen is the language IAM policy documents are written in. This crate parses such a document into a
typed representation, serializes one back, and evaluates a request against a set of them —
resolving allows, explicit denies, permissions boundaries, condition operators, and policy
variables.

## Usage

```rust
use scratchstack_aspen::{authorize, Context, Decision, Policy, PolicySet, PolicySource};
use scratchstack_arn::Arn;
use scratchstack_aws_principal::{Principal, SessionData, User};
use std::str::FromStr;

let policy = Policy::from_str(
    r#"{"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::examplebucket/*"}
    ]}"#,
)
.unwrap();

let mut policy_set = PolicySet::new();
policy_set.add_policy(
    PolicySource::new_entity_inline("arn:aws:iam::123456789012:user/exampleuser", "AIDAEXAMPLE", "ReadObjects"),
    policy,
);

let actor = Principal::from(User::from_str("arn:aws:iam::123456789012:user/exampleuser").unwrap());
let context = Context::builder()
    .service("s3")
    .api("GetObject")
    .actor(actor)
    .resources(vec![Arn::from_str("arn:aws:s3:::examplebucket/hello.txt").unwrap()])
    .session_data(SessionData::new())
    .build()
    .unwrap();

let result = authorize(&context, &policy_set).unwrap();
assert_eq!(result.decision(), Decision::Allow);
assert_eq!(result.sources().len(), 1);
```

## The shape of a policy

A `Policy` carries a `PolicyVersion`, an optional id, and a `StatementList`. Each `Statement` pairs
an `Effect` — allow or deny — with the clauses that decide whether it applies to a request:

| Clause | What it covers |
|---|---|
| `Action` / `NotAction` | The `service:Api` patterns the statement covers |
| `Resource` / `NotResource` | The ARN patterns it covers. Required, except on a statement carrying a principal clause |
| `Principal` / `NotPrincipal` | Who it covers. Identity-based policies leave this out; resource-based policies carry it |
| `Condition` | A two-level map from a `ConditionOp` to the condition keys it constrains and the values allowed for each |

A resource-based policy usually carries a resource clause as well — a bucket policy names both. The
resource clause may be omitted only where the attachment already identifies the resource, as a role
trust policy does: a principal clause *relaxes* the requirement rather than standing in for the
clause.

### Round-tripping

Aspen lets a one-element list be written as the bare element, so `"Action": "s3:GetObject"` and
`"Action": ["s3:GetObject"]` both parse. Which spelling the document used is recorded (`JsonRep`),
so serializing reproduces the original rather than normalizing it — which matters when a policy has
to be handed back to a caller byte-for-byte as they wrote it.

## Evaluating a request

A request is a `Context`: the service and API being invoked, the actor, the resources named, and the
session data condition keys are drawn from. `authorize` evaluates it against a `PolicySet`, applying
AWS request-evaluation semantics — one resource at a time, an explicit deny beating any allow,
permissions boundaries constraining what an identity policy may grant — and reports which policies
decided the outcome via `AuthorizationResult::sources`.

`Decision` distinguishes three outcomes: `Allow`, `Deny` (unconditional, from an explicit deny), and
`DefaultDeny` (nothing allowed it).

**One exception comes first:** the account root user is allowed without any policy in the set being
evaluated, so an explicit deny never reaches it. That is not the whole of what AWS does, and
`authorize`'s own documentation says where the two part company.

`Policy::evaluate` and `Statement::evaluate` evaluate a single document or clause. They do *not*
apply per-resource semantics; use `authorize` when that matters.

### Where a policy came from

`PolicySource` records the attachment a policy arrived through, and `authorize` reports the sources
behind a decision in those terms — entity inline and attached policies, group inline and attached
policies, resource policies, permissions boundaries, organization service control policies, and
session policies.

## Condition operators

`ConditionOp` covers the operator families AWS defines — `String`, `Numeric`, `Date`, `Bool`,
`Binary`, `IpAddress`, `Arn`, and `Null` — each with its own comparison enum (`StringCmp`,
`NumericCmp`, `DateCmp`, `ArnCmp`).

Two modifiers apply on top, matching the way AWS spells them:

* **`IfExists`** — the condition passes over a key the request did not supply, rather than failing.
  Combined with negation as needed (`Variant::Negated`, `Variant::IfExistsNegated`).
* **Set operators** — `ForAllValues:` matches if every value of a multivalued key matches (a key
  with no values matches vacuously); `ForAnyValue:` matches if at least one does (a key with no
  values does not match, unless the operator also carries `IfExists`).

## Related crates

* [`scratchstack-arn`](../scratchstack-arn) — the ARN type this crate matches resource patterns
  against.
* [`scratchstack-aws-principal`](../scratchstack-aws-principal) — the *actor* principals a `Context`
  carries. Note that the `Principal` in this crate is the *policy* principal: it may contain
  wildcards, and it is a different type from the one in that crate.

## Features

`sensitive-logging` *(off by default)* emits log records carrying the contents of an authorization
request — policy documents, principals, resources, and session data. Without it the records are not
merely filtered by log level; they are not compiled in at all. The `sensitive_log` family of macros
comes from [`scratchstack-core`](../scratchstack-core), but the gate is this crate's own feature:
enabling it here does not switch on any other crate's sensitive records, and vice versa.

## Documentation

Published to [docs.rs](https://docs.rs/scratchstack-aspen/).
