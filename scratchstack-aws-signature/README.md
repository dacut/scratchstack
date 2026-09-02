# AWS signature verification routines for Rust
## Crate: [scratchstack-aws-signature](https://crates.io/crates/scratchstack-aws-signature)

![GitHub Actions](https://github.com/dacut/scratchstack/workflows/Rust/badge.svg)

The `scratchstack-aws-signature` crate (formerly known as `aws_sig_verify`) provides
AWS SigV4 _verification_ routines.
This *is not* the library you want if you just want to call AWS services
or other services that use AWS SigV4 signatures. To sign outgoing requests,
use the [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust) or, for
signing alone, [aws-sigv4](https://docs.rs/aws-sigv4/).

If you are attempting to perform AWS SigV4 verification using AWS-vended
credentials, this library also ___will not work for you___. You need the
caller's secret key (or a derivative), and AWS does not allow this for
obvious reasons. Instead, you should be using [API Gateway with IAM
authentication](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html).

On the other hand, if you have your own ecosystem of AWS-like credentials
and are developing mock-AWS services or just really like AWS SigV4 but
can't run within AWS, this library _might_ be for you.

Documentation for this package is published automatically to [docs.rs](https://docs.rs/scratchstack-aws-signature/).
