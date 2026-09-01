use {
    crate::{
        ArnError,
        utils::{validate_account_id, validate_partition, validate_region, validate_service},
    },
    serde::{Deserialize, Serialize, de},
    std::{
        cmp::Ordering,
        fmt::{Display, Formatter, Result as FmtResult},
        hash::Hash,
        str::FromStr,
    },
};

const PARTITION_START: usize = 4;

/// An Amazon Resource Name (ARN) representing an exact resource.
///
/// This is used to represent a known resource, such as an S3 bucket, EC2 instance, assumed role instance, etc. This is
/// _not_ used to represent resource _statements_ in the IAM Aspen policy language, which may contain wildcards.
///
/// `Arn` objects are immutable.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Arn {
    arn: String,
    service_start: usize,
    region_start: usize,
    account_id_start: usize,
    resource_start: usize,
}

/// A builder for programmatically constructing [`Arn`] values.
///
/// [`partition`][ArnBuilder::partition] and [`service`][ArnBuilder::service] are required; the region, account ID, and
/// resource default to the empty string. Obtain one from [`Arn::builder`] and finish with
/// [`build`][ArnBuilder::build].
#[derive(Clone, Debug, Default)]
pub struct ArnBuilder {
    partition: Option<String>,
    service: Option<String>,
    region: String,
    account_id: String,
    resource: String,
}

impl Arn {
    /// Create a new ARN from the specified components.
    ///
    /// * `partition` - The partition the resource is in (required). This is usually `aws`, `aws-cn`, or `aws-us-gov`
    ///   for actual AWS resources, but may be any string meeting the rules specified in [`validate_partition`] for
    ///   non-AWS resources.
    /// * `service` - The service the resource belongs to (required). This is a service name like `ec2` or `s3`.
    ///   Non-AWS resources must conform to the naming rules specified in [`validate_service`].
    /// * `region` - The region the resource is in (optional). If the resource is regional (so that other regions may
    ///   hold different resources with the same name), this is the region name; if the resource is global, this is
    ///   empty. This is usually a region name like `us-east-1` or `us-west-2`, but may be any string meeting the
    ///   rules specified in [`validate_region`].
    /// * `account_id` - The account ID the resource belongs to (optional). This is the 12-digit account ID or the
    ///   string `aws` for certain AWS-owned resources. Some resources (such as S3 buckets and objects) do not need
    ///   the account ID (the bucket name is globally unique within a partition), so this may be empty.
    /// * `resource` - The resource name (required). The formatting is service-specific, so it is not validated here
    ///   beyond being a Rust string (and therefore valid UTF-8). It may contain colons; everything after the fifth
    ///   colon of an ARN is part of the resource.
    ///
    /// # Errors
    ///
    /// * If the partition is invalid, [`ArnError::InvalidPartition`] is returned.
    /// * If the service is invalid, [`ArnError::InvalidService`] is returned.
    /// * If the region is non-empty and invalid, [`ArnError::InvalidRegion`] is returned.
    /// * If the account ID is non-empty and invalid, [`ArnError::InvalidAccountId`] is returned.
    pub fn new(
        partition: &str,
        service: &str,
        region: &str,
        account_id: &str,
        resource: &str,
    ) -> Result<Self, ArnError> {
        validate_partition(partition)?;
        validate_service(service)?;
        if !region.is_empty() {
            validate_region(region)?
        }
        if !account_id.is_empty() {
            validate_account_id(account_id)?
        }

        // Safety: We have met the preconditions specified for new_unchecked above.
        unsafe { Ok(Self::new_unchecked(partition, service, region, account_id, resource)) }
    }

    /// Create a new ARN from the specified components, bypassing any validation.
    ///
    /// This is the unvalidated counterpart to [`Arn::new`]. Component boundaries are recorded from the lengths of the
    /// arguments rather than by searching the formatted string, so [`Arn::partition`] and the other accessors return
    /// exactly what was passed here even when it violates the constraints below.
    ///
    /// What an invalid component costs is the ARN string itself. A component containing a `:` formats into a string
    /// that [`Arn::from_str`] splits at different boundaries, so the value no longer round-trips through its own
    /// [`Display`] output: `new_unchecked("a:b", "ec2", ...)` renders as `arn:a:b:ec2:...`, which reparses with
    /// `partition` of `a` and `service` of `b`. Components that are merely ill-formed (uppercase, say) round-trip as
    /// text but produce an ARN that [`Arn::from_str`] rejects outright.
    ///
    /// # Safety
    ///
    /// The following constraints must be met:
    ///
    /// * `partition` - Must meet the rules specified in [`validate_partition`].
    /// * `service` - Must meet the rules specified in [`validate_service`].
    /// * `region` - Must be empty or meet the rules specified in [`validate_region`].
    /// * `account_id` - Must be empty, a 12 ASCII digit account ID, or the string `aws`.
    /// * `resource` - A valid UTF-8 string.
    pub unsafe fn new_unchecked(
        partition: &str,
        service: &str,
        region: &str,
        account_id: &str,
        resource: &str,
    ) -> Self {
        let arn = format!("arn:{partition}:{service}:{region}:{account_id}:{resource}");
        let service_start = PARTITION_START + partition.len() + 1;
        let region_start = service_start + service.len() + 1;
        let account_id_start = region_start + region.len() + 1;
        let resource_start = account_id_start + account_id.len() + 1;

        Self {
            arn,
            service_start,
            region_start,
            account_id_start,
            resource_start,
        }
    }

    /// Create a new [`ArnBuilder`] for programmatically constructing an ARN.
    pub fn builder() -> ArnBuilder {
        ArnBuilder::default()
    }

    /// Return the partition the resource is in.
    #[inline(always)]
    pub fn partition(&self) -> &str {
        &self.arn[PARTITION_START..self.service_start - 1]
    }

    /// Return the service the resource belongs to.
    #[inline(always)]
    pub fn service(&self) -> &str {
        &self.arn[self.service_start..self.region_start - 1]
    }

    /// Return the region the resource is in.
    #[inline(always)]
    pub fn region(&self) -> &str {
        &self.arn[self.region_start..self.account_id_start - 1]
    }

    /// Return the account ID the resource belongs to.
    #[inline(always)]
    pub fn account_id(&self) -> &str {
        &self.arn[self.account_id_start..self.resource_start - 1]
    }

    /// Return the resource name.
    #[inline(always)]
    pub fn resource(&self) -> &str {
        &self.arn[self.resource_start..]
    }
}

impl Display for Arn {
    /// Return the ARN.
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.arn)
    }
}

/// Parse a string into an [`Arn`].
impl FromStr for Arn {
    /// [`ArnError`] is returned if the string is not a valid ARN.
    type Err = ArnError;

    /// Parse an ARN of the form `arn:partition:service:region:account-id:resource`.
    ///
    /// The string is split into at most 6 colon-separated components, so any additional colons become part of the
    /// resource.
    ///
    /// # Errors
    ///
    /// * If the ARN has fewer than 6 colon-separated components, [`ArnError::InvalidArn`] is returned.
    /// * If the first component is not `arn`, [`ArnError::InvalidScheme`] is returned.
    /// * If the partition is invalid, [`ArnError::InvalidPartition`] is returned.
    /// * If the service is invalid, [`ArnError::InvalidService`] is returned.
    /// * If the region is non-empty and invalid, [`ArnError::InvalidRegion`] is returned.
    /// * If the account ID is non-empty and invalid, [`ArnError::InvalidAccountId`] is returned.
    fn from_str(s: &str) -> Result<Self, ArnError> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() != 6 {
            return Err(ArnError::InvalidArn(s.to_string()));
        }

        if parts[0] != "arn" {
            return Err(ArnError::InvalidScheme(parts[0].to_string()));
        }

        Self::new(parts[1], parts[2], parts[3], parts[4], parts[5])
    }
}

/// Orders ARNs by partition, service, region, account ID, and resource.
impl PartialOrd for Arn {
    /// Returns the relative ordering between this and another ARN.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Orders ARNs by partition, service, region, account ID, and resource.
impl Ord for Arn {
    /// Returns the relative ordering between this and another ARN.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.partition().cmp(other.partition()) {
            Ordering::Equal => match self.service().cmp(other.service()) {
                Ordering::Equal => match self.region().cmp(other.region()) {
                    Ordering::Equal => match self.account_id().cmp(other.account_id()) {
                        Ordering::Equal => self.resource().cmp(other.resource()),
                        x => x,
                    },
                    x => x,
                },
                x => x,
            },
            x => x,
        }
    }
}

impl<'de> Deserialize<'de> for Arn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for Arn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.arn)
    }
}

impl ArnBuilder {
    /// Set the partition of the ARN being built. Required.
    pub fn partition(mut self, partition: impl Into<String>) -> Self {
        self.partition = Some(partition.into());
        self
    }

    /// Set the service of the ARN being built. Required.
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the region of the ARN being built. Defaults to empty, for global resources.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Set the account ID of the ARN being built. Defaults to empty, for resources that do not need one.
    pub fn account_id(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = account_id.into();
        self
    }

    /// Set the resource of the ARN being built. Defaults to empty.
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = resource.into();
        self
    }

    /// Build the ARN, validating the components as [`Arn::new`] does.
    ///
    /// # Errors
    ///
    /// * If the partition was never set, [`ArnError::MissingPartition`] is returned.
    /// * If the service was never set, [`ArnError::MissingService`] is returned.
    /// * Otherwise, any validation failure from [`Arn::new`] is returned unchanged.
    pub fn build(self) -> Result<Arn, ArnError> {
        let Some(partition) = self.partition else {
            return Err(ArnError::MissingPartition);
        };

        let Some(service) = self.service else {
            return Err(ArnError::MissingService);
        };

        Arn::new(&partition, &service, &self.region, &self.account_id, &self.resource)
    }
}

#[cfg(test)]
mod test {
    use {
        super::Arn,
        crate::{
            ArnError,
            utils::{validate_account_id, validate_region},
        },
        pretty_assertions::assert_eq,
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test]
    fn check_arn_derived() {
        let arn1a = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn1b = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn2 = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef1").unwrap();
        let arn3 = Arn::from_str("arn:aws:ec2:us-east-1:123456789013:instance/i-1234567890abcdef0").unwrap();
        let arn4 = Arn::from_str("arn:aws:ec2:us-east-2:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn5 = Arn::from_str("arn:aws:ec3:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        let arn6 = Arn::from_str("arn:awt:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();

        assert_eq!(arn1a, arn1b);
        assert!(arn1a < arn2);
        assert!(arn2 < arn3);
        assert!(arn3 < arn4);
        assert!(arn4 < arn5);
        assert!(arn5 < arn6);

        assert_eq!(arn1a, arn1a.clone());

        // Ensure ordering is logical.
        assert!(arn1a <= arn1b);
        assert!(arn1a < arn2);
        assert!(arn2 > arn1a);
        assert!(arn2 < arn3);
        assert!(arn1a < arn3);
        assert!(arn3 > arn2);
        assert!(arn3 > arn1a);
        assert!(arn3 < arn4);
        assert!(arn4 > arn3);
        assert!(arn4 < arn5);
        assert!(arn5 > arn4);
        assert!(arn5 < arn6);
        assert!(arn6 > arn5);

        assert!(arn3.clone().min(arn4.clone()) == arn3);
        assert!(arn4.clone().max(arn3) == arn4);

        // Ensure we can derive a hash for the arn.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        arn1a.hash(&mut h1a);
        arn1b.hash(&mut h1b);
        assert_eq!(h1a.finish(), h1b.finish());

        let mut h2 = DefaultHasher::new();
        arn2.hash(&mut h2);

        // Ensure we can debug print the arn.
        _ = format!("{arn1a:?}");

        assert_eq!(arn1a.to_string(), "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string());
    }

    #[test]
    fn check_arn_components() {
        let arn = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "instance/i-1234567890abcdef0");
    }

    #[test]
    fn check_arn_empty() {
        let arn1 = Arn::from_str("arn:aws:s3:::bucket").unwrap();
        let arn2 = Arn::from_str("arn:aws:s3:us-east-1::bucket").unwrap();
        let arn3 = Arn::from_str("arn:aws:s3:us-east-1:123456789012:bucket").unwrap();

        assert!(arn1 < arn2);
        assert!(arn2 < arn3);
        assert!(arn1 < arn3);
    }

    #[test]
    fn check_unicode_rejected() {
        // Partition, service, and region are ASCII-only; see the scratchstack_arn::utils module docs.
        let err = Arn::from_str("arn:aws-中国:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err, ArnError::InvalidPartition("aws-中国".to_string()));

        let err = Arn::from_str("arn:aws:één:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err, ArnError::InvalidService("één".to_string()));

        let err = Arn::from_str("arn:aws:ec2:日本-東京-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err, ArnError::InvalidRegion("日本-東京-1".to_string()));

        // The resource is service-specific and is not validated, so it may still hold non-ASCII text.
        let arn = Arn::from_str("arn:aws:s3:::bucket/日本").unwrap();
        assert_eq!(arn.resource(), "bucket/日本");
    }

    #[test]
    fn check_malformed_arns() {
        let wrong_parts =
            vec!["arn", "arn:aws", "arn:aws:ec2", "arn:aws:ec2:us-east-1", "arn:aws:ec2:us-east-1:123456789012"];
        for wrong_part in wrong_parts {
            assert_eq!(Arn::from_str(wrong_part).unwrap_err(), ArnError::InvalidArn(wrong_part.to_string()));
        }
    }

    #[test]
    fn check_invalid_scheme() {
        let err = Arn::from_str("http:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid scheme: "http""#.to_string());
    }

    #[test]
    fn check_invalid_partition() {
        let err = Arn::from_str("arn:Aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "Aws""#.to_string());

        let err = Arn::from_str("arn:local-:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "local-""#.to_string());

        let err = Arn::from_str("arn::ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: """#.to_string());

        let err = Arn::from_str("arn:-local:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "-local""#.to_string());

        let err = Arn::from_str("arn:aws--1:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "aws--1""#.to_string());

        let err = Arn::from_str(
            "arn:this-partition-has-too-many-chars:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        )
        .unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "this-partition-has-too-many-chars""#.to_string());

        let err = Arn::from_str("arn:🦀:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid partition: "🦀""#.to_string());
    }

    #[test]
    fn check_invalid_services() {
        let err = Arn::from_str("arn:aws:ec2-:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "ec2-""#.to_string());

        let err = Arn::from_str("arn:aws:-ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "-ec2""#.to_string());

        let err = Arn::from_str("arn:aws:Ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "Ec2""#.to_string());

        let err = Arn::from_str("arn:aws:ec--2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "ec--2""#.to_string());

        let err = Arn::from_str("arn:aws:🦀:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: "🦀""#.to_string());

        let err = Arn::from_str("arn:aws::us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid service name: """#.to_string());
    }

    #[test]
    fn check_valid_regions() {
        let arn = Arn::from_str("arn:aws:ec2:local:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.region(), "local");

        let arn = Arn::from_str("arn:aws:ec2:us-east-1-bos-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.region(), "us-east-1-bos-1");
    }

    #[test]
    fn check_invalid_region() {
        let err = Arn::from_str("arn:aws:ec2:us-east-1-:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1-""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1a:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1a""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:-us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "-us-east-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:Us-East-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "Us-East-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east--1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east--1""#.to_string());

        let err =
            Arn::from_str("arn:aws:ec2:us-east-1-bos-1-lax-1:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-1-bos-1-lax-1""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-🦀:123456789012:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid region: "us-east-🦀""#.to_string());

        let err = validate_region("").unwrap_err();
        assert_eq!(err, ArnError::InvalidRegion("".to_string()));
    }

    #[test]
    fn check_valid_account_ids() {
        let arn = Arn::from_str("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.account_id(), "123456789012");

        let arn = Arn::from_str("arn:aws:ec2:us-east-1:aws:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.account_id(), "aws");
    }

    #[test]
    fn check_invalid_account_ids() {
        let err = Arn::from_str("arn:aws:ec2:us-east-1:1234567890123:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "1234567890123""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1:12345678901:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "12345678901""#.to_string());

        let err = Arn::from_str("arn:aws:ec2:us-east-1:12345678901a:instance/i-1234567890abcdef0").unwrap_err();
        assert_eq!(err.to_string(), r#"Invalid account id: "12345678901a""#.to_string());

        let err = validate_account_id("").unwrap_err();
        assert_eq!(err, ArnError::InvalidAccountId("".to_string()));
    }

    #[test]
    fn check_serialization() {
        let arn: Arn =
            serde_json::from_str(r#""arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0""#).unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "instance/i-1234567890abcdef0");

        let arn_str = serde_json::to_string(&arn).unwrap();
        assert_eq!(arn_str, r#""arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0""#);

        let arn_err = serde_json::from_str::<Arn>(r#""arn:aws:ec2:us-east-1""#).unwrap_err();
        assert_eq!(arn_err.to_string(), r#"Invalid ARN: "arn:aws:ec2:us-east-1""#);

        let arn_err = serde_json::from_str::<Arn>(r#"{}"#);
        assert_eq!(arn_err.unwrap_err().to_string(), "invalid type: map, expected a string at line 1 column 0");
    }

    // ── new_unchecked ────────────────────────────────────────────────────────

    #[test]
    fn new_unchecked_preserves_components() {
        // Boundaries are recorded from the argument lengths rather than by splitting the formatted
        // string, so the accessors return exactly what was passed, colons and all.
        let arn = unsafe { Arn::new_unchecked("a:b", "ec2", "us-east-1", "123456789012", "res:with:colons") };
        assert_eq!(arn.partition(), "a:b");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "res:with:colons");
    }

    #[test]
    fn new_unchecked_invalid_component_breaks_round_trip() {
        // What an invalid component costs is the ARN string: it no longer denotes those components.
        let arn = unsafe { Arn::new_unchecked("a:b", "ec2", "us-east-1", "123456789012", "res") };
        assert_eq!(arn.to_string(), "arn:a:b:ec2:us-east-1:123456789012:res");
        assert_ne!(Arn::from_str(&arn.to_string()).ok().as_ref(), Some(&arn));

        // A merely ill-formed component round-trips as text, but the ARN is rejected on reparse.
        let arn = unsafe { Arn::new_unchecked("AWS", "ec2", "us-east-1", "123456789012", "res") };
        assert_eq!(arn.partition(), "AWS");
        assert_eq!(Arn::from_str(&arn.to_string()), Err(ArnError::InvalidPartition("AWS".to_string())));
    }

    #[test]
    fn colons_in_resource_round_trip() {
        // Colons are legitimate in a resource; validated ARNs carrying them round-trip fine.
        let arn = Arn::new("aws", "ec2", "us-east-1", "123456789012", "res:with:colons").unwrap();
        assert_eq!(arn.resource(), "res:with:colons");
        assert_eq!(Arn::from_str(&arn.to_string()).unwrap(), arn);
    }

    // ── ArnBuilder ───────────────────────────────────────────────────────────

    #[test]
    fn builder_full() {
        let arn = Arn::builder()
            .partition("aws")
            .service("ec2")
            .region("us-east-1")
            .account_id("123456789012")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap();
        assert_eq!(arn.partition(), "aws");
        assert_eq!(arn.service(), "ec2");
        assert_eq!(arn.region(), "us-east-1");
        assert_eq!(arn.account_id(), "123456789012");
        assert_eq!(arn.resource(), "instance/i-1234567890abcdef0");
        assert_eq!(arn.to_string(), "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0");
    }

    #[test]
    fn builder_global_resource() {
        // Region and account_id default to empty (global resource, e.g. IAM).
        let arn = Arn::builder()
            .partition("aws")
            .service("iam")
            .account_id("123456789012")
            .resource("user/alice")
            .build()
            .unwrap();
        assert_eq!(arn.region(), "");
        assert_eq!(arn.to_string(), "arn:aws:iam::123456789012:user/alice");
    }

    #[test]
    fn builder_no_account_id() {
        // S3 buckets are globally unique and don't need an account ID.
        let arn = Arn::builder().partition("aws").service("s3").resource("my-bucket").build().unwrap();
        assert_eq!(arn.region(), "");
        assert_eq!(arn.account_id(), "");
        assert_eq!(arn.to_string(), "arn:aws:s3:::my-bucket");
    }

    #[test]
    fn builder_missing_partition() {
        let err = Arn::builder()
            .service("ec2")
            .region("us-east-1")
            .account_id("123456789012")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::MissingPartition);
        assert_eq!(err.to_string(), "Missing partition");
    }

    #[test]
    fn builder_missing_service() {
        let err = Arn::builder()
            .partition("aws")
            .region("us-east-1")
            .account_id("123456789012")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::MissingService);
        assert_eq!(err.to_string(), "Missing service");
    }

    #[test]
    fn builder_invalid_partition() {
        let err = Arn::builder()
            .partition("Aws")
            .service("ec2")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::InvalidPartition("Aws".to_string()));
    }

    #[test]
    fn builder_invalid_service() {
        let err = Arn::builder()
            .partition("aws")
            .service("Ec2")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::InvalidService("Ec2".to_string()));
    }

    #[test]
    fn builder_invalid_region() {
        let err = Arn::builder()
            .partition("aws")
            .service("ec2")
            .region("us-east-1-")
            .account_id("123456789012")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::InvalidRegion("us-east-1-".to_string()));
    }

    #[test]
    fn builder_invalid_account_id() {
        let err = Arn::builder()
            .partition("aws")
            .service("ec2")
            .region("us-east-1")
            .account_id("bad-account")
            .resource("instance/i-1234567890abcdef0")
            .build()
            .unwrap_err();
        assert_eq!(err, ArnError::InvalidAccountId("bad-account".to_string()));
    }
}
