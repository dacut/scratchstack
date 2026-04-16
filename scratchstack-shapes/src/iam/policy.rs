use {
    crate::Arn,
    anyhow::{Result as AnyResult, bail},
    derive_builder::Builder,
    serde::{Deserialize, Serialize},
};

/// Ensure that the given ARN is a valid policy ARN.
pub fn validate_policy_arn(arn: &Arn) -> AnyResult<()> {
    let resource = arn.resource();
    if arn.service() != "iam" || !resource.starts_with("policy/") {
        bail!(
            "Permissions boundary must be an IAM policy ARN with the format arn:<partition>:iam::<account-id>:policy/<policy-name>"
        );
    }

    Ok(())
}

/// Parse and validate a policy ARN for Clap.
pub(crate) fn clap_parse_policy_arn(arn: &str) -> Result<Arn, String> {
    use std::str::FromStr as _;
    let arn = Arn::from_str(arn).map_err(|e| format!("Invalid ARN syntax for permissions boundary: {e}"))?;
    validate_policy_arn(&arn).map_err(|e| format!("Invalid permissions boundary ARN: {e}"))?;
    Ok(arn)
}

/// Information about an attached permissions boundary.
///
/// ## References
/// * [AWS AttachedPermissionsBoundary data type](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachedPermissionsBoundary.html)
/// * [Archived](https://web.archive.org/web/20251012215013/https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachedPermissionsBoundary.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[builder(build_fn(validate = "AttachedPermissionsBoundaryBuilder::validate"))]
pub struct AttachedPermissionsBoundary {
    /// The ARN of the policy used to set the permissions boundary.
    #[cfg_attr(feature = "clap", clap(long, value_parser = AttachedPermissionsBoundary::parse_permissions_boundary_arn))]
    permissions_boundary_arn: Arn,

    /// The type of IAM resource defining the permissions boundary. This is always `Policy` currently.
    #[cfg_attr(feature = "clap", clap(long))]
    permissions_boundary_type: PermissionsBoundaryType,
}

impl AttachedPermissionsBoundary {
    /// Create a new [`AttachedPermissionsBoundaryBuilder`] for programmatically constructing an `AttachedPermissionsBoundary`.
    #[inline(always)]
    pub fn builder() -> AttachedPermissionsBoundaryBuilder {
        AttachedPermissionsBoundaryBuilder::default()
    }

    /// Returns the ARN of the policy used to set the permissions boundary.
    #[inline(always)]
    pub fn permissions_boundary_arn(&self) -> &Arn {
        &self.permissions_boundary_arn
    }

    /// Returns the type of IAM resource type defining the permissions boundary.
    #[inline(always)]
    pub fn permissions_boundary_type(&self) -> PermissionsBoundaryType {
        self.permissions_boundary_type
    }
}

#[cfg(feature = "clap")]
impl AttachedPermissionsBoundary {
    /// Parse a boundary ARN from the command line.
    fn parse_permissions_boundary_arn(s: &str) -> Result<Arn, String> {
        let arn = s.parse::<Arn>().map_err(|e| e.to_string())?;
        validate_policy_arn(&arn).map_err(|e| e.to_string())?;
        Ok(arn)
    }
}

impl AttachedPermissionsBoundaryBuilder {
    fn validate(&self) -> Result<(), String> {
        let Some(permissions_boundary_arn) = &self.permissions_boundary_arn else {
            return Err("Permissions boundary ARN is required".to_string());
        };

        if self.permissions_boundary_type.is_none() {
            return Err("Permissions boundary type is required".to_string());
        };

        validate_policy_arn(permissions_boundary_arn).map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// The type of IAM resource defining the permissions boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum PermissionsBoundaryType {
    /// Policy boundary type.
    Policy,
}

#[cfg(test)]
mod tests {
    use {super::*, crate::Arn, pretty_assertions::assert_eq, std::str::FromStr as _};

    const POLICY_ARN: &str = "arn:aws:iam::123456789012:policy/MyPolicy";
    const USER_ARN: &str = "arn:aws:iam::123456789012:user/Alice";
    const S3_ARN: &str = "arn:aws:s3:::my-bucket";

    fn policy_arn() -> Arn {
        Arn::from_str(POLICY_ARN).unwrap()
    }

    // ── validate_policy_arn ──────────────────────────────────────────────────

    #[test_log::test]
    fn validate_policy_arn_valid() {
        assert!(validate_policy_arn(&policy_arn()).is_ok());
    }

    #[test_log::test]
    fn validate_policy_arn_rejects_user_arn() {
        assert!(validate_policy_arn(&Arn::from_str(USER_ARN).unwrap()).is_err());
    }

    #[test_log::test]
    fn validate_policy_arn_rejects_non_iam_service() {
        assert!(validate_policy_arn(&Arn::from_str(S3_ARN).unwrap()).is_err());
    }

    // ── AttachedPermissionsBoundaryBuilder ───────────────────────────────────

    #[test_log::test]
    fn builder_valid() {
        let apb = AttachedPermissionsBoundary::builder()
            .permissions_boundary_arn(policy_arn())
            .permissions_boundary_type(PermissionsBoundaryType::Policy)
            .build()
            .unwrap();
        assert_eq!(apb.permissions_boundary_arn(), &policy_arn());
        assert!(matches!(apb.permissions_boundary_type(), PermissionsBoundaryType::Policy));
    }

    #[test_log::test]
    fn builder_missing_arn() {
        assert!(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_type(PermissionsBoundaryType::Policy)
                .build()
                .is_err()
        );
    }

    #[test_log::test]
    fn builder_missing_type() {
        assert!(AttachedPermissionsBoundary::builder().permissions_boundary_arn(policy_arn()).build().is_err());
    }

    #[test_log::test]
    fn builder_invalid_arn_not_policy() {
        assert!(
            AttachedPermissionsBoundary::builder()
                .permissions_boundary_arn(Arn::from_str(USER_ARN).unwrap())
                .permissions_boundary_type(PermissionsBoundaryType::Policy)
                .build()
                .is_err()
        );
    }

    // ── Clap parsing ─────────────────────────────────────────────────────────

    #[cfg(feature = "clap")]
    mod clap_parsing {
        use {super::*, clap::Parser, pretty_assertions::assert_eq};

        #[derive(Parser)]
        struct ApbCmd {
            #[command(flatten)]
            apb: AttachedPermissionsBoundary,
        }

        #[test_log::test]
        fn parse_valid() {
            let cmd = ApbCmd::try_parse_from([
                "cmd",
                "--permissions-boundary-arn",
                POLICY_ARN,
                "--permissions-boundary-type",
                "policy",
            ])
            .unwrap();
            assert_eq!(cmd.apb.permissions_boundary_arn(), &policy_arn());
            assert!(matches!(cmd.apb.permissions_boundary_type(), PermissionsBoundaryType::Policy));
        }

        #[test_log::test]
        fn parse_invalid_arn_syntax() {
            assert!(
                ApbCmd::try_parse_from([
                    "cmd",
                    "--permissions-boundary-arn",
                    "not-an-arn",
                    "--permissions-boundary-type",
                    "policy",
                ])
                .is_err()
            );
        }

        #[test_log::test]
        fn parse_invalid_type() {
            assert!(
                ApbCmd::try_parse_from([
                    "cmd",
                    "--permissions-boundary-arn",
                    POLICY_ARN,
                    "--permissions-boundary-type",
                    "role",
                ])
                .is_err()
            );
        }

        /// Clap has no value_parser on `--permissions-boundary-arn`, so a syntactically valid
        /// but non-policy ARN passes clap parsing. This documents the missing validation.
        #[test_log::test]
        fn parse_non_policy_arn_rejected() {
            assert!(
                ApbCmd::try_parse_from([
                    "cmd",
                    "--permissions-boundary-arn",
                    USER_ARN,
                    "--permissions-boundary-type",
                    "policy",
                ])
                .is_err()
            );
        }
    }
}
