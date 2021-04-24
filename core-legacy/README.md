# scratchstack-aws-principal

Principals for AWS and AWS-like services.

Principals come in two "flavors": actors and policies. A policy-based prinicpal can be completely specified via
an ARN in an Identity and Access Management (IAM) Aspen policy, e.g.,
`arn:aws:iam::123456789012:user/Sales/Bob`. This is what most people think of when they refer to principals
when talking about AWS. In this example:
* The partition (cloud instance) is `aws` (the AWS commercial cloud);
* The AWS account in the partition is `123456789012`.
* This refers to an IAM user.
* The path to the user is `/Sales/`.
* The user name is `Bob`.

On the service implementation side, however, there are additional details attached to a principal actor. Groups,
roles, and users have a
[universally unique ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
If the `/Sales/Bob` user is deleted and another is created, these users will have the same ARN but different unique
IDs. While not part of the principal itself, this can be referred to in Aspen policies via the
[`\${aws:username}`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html) policy
variable. Assumed roles carry a token issue time, access via the `\${aws:TokenIssueTime}` variable, as well as
an expiration time on or after which the assumed role is no longer valid.
