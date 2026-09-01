use {
    crate::{PrincipalError, utils::validate_dns},
    bon::bon,
    scratchstack_arn::utils::validate_region,
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS or AWS-like service.
///
/// `Service` structs are immutable. They are created using the [`ServiceBuilder`] returned by [`Service::builder`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Service {
    /// Name of the service.
    service_name: String,

    /// The region the service is running in. If None, the service is global.
    region: Option<String>,

    /// The DNS suffix of the service. This is usually amazonaws.com.
    dns_suffix: String,
}

#[bon]
impl Service {
    /// Create a [`ServiceBuilder`] for building a [`Service`] representing an AWS(-ish) service.
    ///
    /// # Fields
    ///
    /// * `service_name`: The name of the service, validated as a DNS name by [`validate_dns`]. This must meet the
    ///   following requirements or a [`PrincipalError::InvalidService`] error will be returned:
    ///   * The name must contain between 1 and 32 characters.
    ///   * The name is split into `.`-separated components, each of which must be between 1 and 63 characters and
    ///     contain only ASCII alphanumeric characters, hyphens (`-`), or underscores (`_`).
    ///   * A component may not begin or end with a hyphen, nor contain two consecutive hyphens.
    /// * `region`: The region the service is running in. If unset, the service is global. When set, it must meet the
    ///   rules of [`validate_region`][scratchstack_arn::utils::validate_region] or a
    ///   [`PrincipalError::InvalidRegion`] error will be returned.
    /// * `dns_suffix`: The DNS suffix of the service, usually `amazonaws.com`. This is validated by [`validate_dns`]
    ///   under the same rules as `service_name` but with a maximum length of 128; a failure is reported as
    ///   [`PrincipalError::InvalidService`], not as a suffix-specific error.
    ///
    /// # Example
    /// ```
    /// # use scratchstack_aws_principal::Service;
    /// let service = Service::builder()
    ///     .service_name("s3")
    ///     .region("us-east-1")
    ///     .dns_suffix("amazonaws.com")
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(service.service_name(), "s3");
    /// assert_eq!(service.region(), Some("us-east-1"));
    /// assert_eq!(service.dns_suffix(), "amazonaws.com");
    /// assert_eq!(service.regional_dns_name(), "s3.us-east-1.amazonaws.com");
    /// assert_eq!(service.global_dns_name(), "s3.amazonaws.com");
    ///
    /// // Omitting the region creates a global service.
    /// let global = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
    /// assert_eq!(global.region(), None);
    /// ```
    #[builder(builder_type = ServiceBuilder, finish_fn = build)]
    pub fn builder(
        /// Name of the service.
        #[builder(into)]
        service_name: String,

        /// The region the service is running in. If unset, the service is global.
        #[builder(into)]
        region: Option<String>,

        /// The DNS suffix of the service. This is usually amazonaws.com.
        #[builder(into)]
        dns_suffix: String,
    ) -> Result<Self, PrincipalError> {
        Self::validate_parts(&service_name, region.as_deref(), &dns_suffix)?;

        Ok(Self {
            service_name,
            region,
            dns_suffix,
        })
    }

    /// Create a [`Service`] object representing an AWS(-ish) service.
    ///
    /// # Arguments
    ///
    /// * `service_name`: The name of the service, validated as a DNS name by [`validate_dns`]. This must meet the
    ///   following requirements or a [`PrincipalError::InvalidService`] error will be returned:
    ///   * The name must contain between 1 and 32 characters.
    ///   * The name is split into `.`-separated components, each of which must be between 1 and 63 characters and
    ///     contain only ASCII alphanumeric characters, hyphens (`-`), or underscores (`_`).
    ///   * A component may not begin or end with a hyphen, nor contain two consecutive hyphens.
    /// * `region`: The region the service is running in. If `None`, the service is global. When `Some`, it must meet
    ///   the rules of [`validate_region`][scratchstack_arn::utils::validate_region] or a
    ///   [`PrincipalError::InvalidRegion`] error will be returned.
    /// * `dns_suffix`: The DNS suffix of the service, usually `amazonaws.com`. This is validated by [`validate_dns`]
    ///   under the same rules as `service_name` but with a maximum length of 128; a failure is reported as
    ///   [`PrincipalError::InvalidService`], not as a suffix-specific error.
    ///
    /// If all of the requirements are met, a [`Service`] object is returned. Otherwise, a [`PrincipalError`] error is
    /// returned.
    #[deprecated(since = "0.12.0", note = "Use Service::builder() instead.")]
    pub fn new(service_name: &str, region: Option<String>, dns_suffix: &str) -> Result<Self, PrincipalError> {
        Self::validate_parts(service_name, region.as_deref(), dns_suffix)?;

        Ok(Self {
            service_name: service_name.to_string(),
            region,
            dns_suffix: dns_suffix.into(),
        })
    }

    /// Validate the components of a [`Service`].
    ///
    /// This is shared by [`Service::new`] and [`ServiceBuilder::build`] so both enforce identical requirements.
    fn validate_parts(service_name: &str, region: Option<&str>, dns_suffix: &str) -> Result<(), PrincipalError> {
        validate_dns(service_name, 32, PrincipalError::InvalidService)?;
        validate_dns(dns_suffix, 128, PrincipalError::InvalidService)?;

        if let Some(region) = region {
            validate_region(region)?;
        }

        Ok(())
    }

    /// The name of the service.
    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// The region of the service. If the service is global, this will be `None`.
    #[inline]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The DNS suffix of the service.
    #[inline]
    pub fn dns_suffix(&self) -> &str {
        &self.dns_suffix
    }

    /// The regional DNS name of the service. If the service is global, this will be the same as the global DNS name.
    pub fn regional_dns_name(&self) -> String {
        match &self.region {
            None => format!("{}.{}", self.service_name, self.dns_suffix),
            Some(region) => format!("{}.{}.{}", self.service_name, region, self.dns_suffix),
        }
    }

    /// The global DNS name of the service (omitting the regional component, if any).
    pub fn global_dns_name(&self) -> String {
        format!("{}.{}", self.service_name, self.dns_suffix)
    }
}

impl Display for Service {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.region {
            None => write!(f, "{}.{}", self.service_name, self.dns_suffix),
            Some(region) => write!(f, "{}.{}.{}", self.service_name, region, self.dns_suffix),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::Service,
        crate::{Principal, PrincipalError, PrincipalSource},
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_service_name_is_validated_as_dns() {
        // service_name goes through validate_dns, not validate_name: ',', '=' and '@' are rejected,
        // and hyphens may not lead, trail, or repeat. The docs previously described validate_name's
        // rules, which promised all three of those characters.
        for good in ["s3", "s3.foo", "s3_foo", "a-b", "execute-api"] {
            Service::builder()
                .service_name(good)
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_or_else(|e| panic!("rejected {good:?}: {e}"));
        }

        for bad in ["s3,foo", "s3=foo", "s3@foo", "s3-", "-s3", "s3--foo", "", "s3..foo"] {
            let err = Service::builder()
                .service_name(bad)
                .dns_suffix("amazonaws.com")
                .build()
                .expect_err(&format!("accepted {bad:?}"));
            assert_eq!(err, PrincipalError::InvalidService(bad.to_string()));
        }
    }

    #[test]
    fn check_dns_suffix_is_validated() {
        // The suffix is validated too, and reports InvalidService rather than a suffix-specific error.
        let err = Service::builder()
            .service_name("s3")
            .dns_suffix("trailing-.com")
            .build()
            .expect_err("accepted a trailing hyphen in the suffix");
        assert_eq!(err, PrincipalError::InvalidService("trailing-.com".to_string()));

        // 128 characters is the suffix limit, versus 32 for the service name. Each component is
        // separately capped at 63, so the limit has to be reached across several of them.
        let at_limit = format!("{}.{}.com", "a".repeat(60), "b".repeat(63));
        assert_eq!(at_limit.len(), 128);
        Service::builder().service_name("s3").dns_suffix(&at_limit).build().unwrap();

        let over = format!("{}.{}.com", "a".repeat(61), "b".repeat(63));
        assert_eq!(over.len(), 129);
        Service::builder().service_name("s3").dns_suffix(&over).build().expect_err("accepted a 129-byte suffix");

        // A single component longer than 63 fails regardless of the total length.
        let long_component = format!("{}.com", "a".repeat(64));
        assert!(long_component.len() < 128);
        Service::builder()
            .service_name("s3")
            .dns_suffix(&long_component)
            .build()
            .expect_err("accepted a 64-character component");
    }

    #[test]
    fn check_region_is_validated() {
        let err = Service::builder()
            .service_name("s3")
            .region("us-east-1-")
            .dns_suffix("amazonaws.com")
            .build()
            .expect_err("accepted a trailing dash in the region");
        assert_eq!(err, PrincipalError::InvalidRegion("us-east-1-".to_string()));
    }

    #[test]
    fn check_components() {
        let s1 = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
        let s2 = Service::builder().service_name("s3").region("us-east-1").dns_suffix("amazonaws.com").build().unwrap();

        assert_eq!(s1.service_name(), "s3");
        assert_eq!(s1.region(), None);
        assert_eq!(s1.dns_suffix(), "amazonaws.com");

        assert_eq!(s2.service_name(), "s3");
        assert_eq!(s2.region(), Some("us-east-1"));
        assert_eq!(s2.dns_suffix(), "amazonaws.com");

        let p = Principal::from(s1);
        let source = p.source();
        assert_eq!(source, PrincipalSource::Service);
        assert_eq!(source.to_string(), "Service".to_string());
    }

    #[test]
    fn check_derived() {
        let s1a = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
        let s1b = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
        let s2 = Service::builder().service_name("s3").dns_suffix("amazonaws.net").build().unwrap();
        let s3 = Service::builder().service_name("s3").region("us-east-1").dns_suffix("amazonaws.net").build().unwrap();
        let s4 = Service::builder().service_name("s3").region("us-east-2").dns_suffix("amazonaws.net").build().unwrap();
        let s5 = Service::builder().service_name("s4").dns_suffix("amazonaws.net").build().unwrap();
        let s6 = Service::builder().service_name("s4").region("us-east-1").dns_suffix("amazonaws.net").build().unwrap();

        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_eq!(s1a, s1a);
        assert_ne!(s1a, s3);
        assert_ne!(s2, s3);
        assert_ne!(s3, s4);
        assert_ne!(s4, s5);
        assert_ne!(s5, s6);

        // Ensure we can hash a service.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        s1a.hash(&mut h1a);
        s1b.hash(&mut h1b);
        s2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(s1a <= s1b);
        assert!(s1a < s2);
        assert!(s2 > s1a);
        assert!(s1a < s3);
        assert!(s2 < s3);
        assert!(s1a < s4);
        assert!(s2 < s4);
        assert!(s3 < s4);
        assert!(s1a < s5);
        assert!(s2 < s5);
        assert!(s3 < s5);
        assert!(s4 < s5);
        assert!(s1a < s6);
        assert!(s2 < s6);
        assert!(s3 < s6);
        assert!(s4 < s6);
        assert!(s5 < s6);
        assert_eq!(s1a.clone().max(s2.clone()), s2);
        assert_eq!(s1a.clone().min(s3), s1a);

        // Ensure formatting is correct to the DNS name.
        assert_eq!(s1a.to_string(), "s3.amazonaws.com");
        assert_eq!(s6.to_string(), "s4.us-east-1.amazonaws.net");

        // Ensure we can debug print a service.
        let _ = format!("{s1a:?}");
    }

    #[test]
    fn check_valid_services() {
        let s1a = Service::builder().service_name("service-name").dns_suffix("amazonaws.com").build().unwrap();
        let s1b = Service::builder().service_name("service-name").dns_suffix("amazonaws.com").build().unwrap();
        let s2 = Service::builder().service_name("service-name2").dns_suffix("amazonaws.com").build().unwrap();
        let s3 = Service::builder()
            .service_name("service-name")
            .region("us-east-1")
            .dns_suffix("amazonaws.com")
            .build()
            .unwrap();
        let s4 = Service::builder()
            .service_name("aservice-name-with-32-characters")
            .dns_suffix("amazonaws.com")
            .build()
            .unwrap();

        assert_eq!(s1a, s1b);
        assert_ne!(s1a, s2);
        assert_eq!(s1a, s1a.clone());

        assert_eq!(s1a.to_string(), "service-name.amazonaws.com");
        assert_eq!(s2.to_string(), "service-name2.amazonaws.com");
        assert_eq!(s3.to_string(), "service-name.us-east-1.amazonaws.com");
        assert_eq!(s4.to_string(), "aservice-name-with-32-characters.amazonaws.com");

        assert_eq!(s1a.regional_dns_name(), "service-name.amazonaws.com");
        assert_eq!(s1a.global_dns_name(), "service-name.amazonaws.com");

        assert_eq!(s3.regional_dns_name(), "service-name.us-east-1.amazonaws.com");
        assert_eq!(s3.global_dns_name(), "service-name.amazonaws.com");
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            Service::builder()
                .service_name("service name")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::builder()
                .service_name("service name")
                .region("us-east-1")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::builder()
                .service_name("service!name")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::builder()
                .service_name("service!name")
                .region("us-east-1")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::builder().service_name("").dns_suffix("amazonaws.com").build().unwrap_err().to_string(),
            r#"Invalid service name: """#
        );

        assert_eq!(
            Service::builder()
                .service_name("a-service-name-with-33-characters")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "a-service-name-with-33-characters""#
        );

        assert_eq!(
            Service::builder()
                .service_name("service-name")
                .region("us-east-")
                .dns_suffix("amazonaws.com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid region: "us-east-""#
        );

        assert_eq!(
            Service::builder()
                .service_name("service-name")
                .region("us-east-1")
                .dns_suffix("amazonaws..com")
                .build()
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "amazonaws..com""#
        );
    }

    #[test]
    fn check_builder_region() {
        // An unset region yields a global service.
        let global = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
        assert_eq!(global.region(), None);

        let regional =
            Service::builder().service_name("s3").region("us-east-1").dns_suffix("amazonaws.com").build().unwrap();
        assert_eq!(regional.region(), Some("us-east-1"));

        let err =
            Service::builder().service_name("s3").region("us-east-1-").dns_suffix("amazonaws.com").build().unwrap_err();
        assert_eq!(err, PrincipalError::InvalidRegion("us-east-1-".to_string()));
    }

    #[test]
    #[allow(deprecated)]
    fn check_deprecated_new() {
        let expected =
            Service::builder().service_name("s3").region("us-east-1").dns_suffix("amazonaws.com").build().unwrap();
        assert_eq!(Service::new("s3", Some("us-east-1".to_string()), "amazonaws.com").unwrap(), expected);

        let expected = Service::builder().service_name("s3").dns_suffix("amazonaws.com").build().unwrap();
        assert_eq!(Service::new("s3", None, "amazonaws.com").unwrap(), expected);

        assert_eq!(
            Service::new("s3", Some("us-east-1-".to_string()), "amazonaws.com").unwrap_err(),
            PrincipalError::InvalidRegion("us-east-1-".to_string())
        );
        assert_eq!(
            Service::new("service name", None, "amazonaws.com").unwrap_err(),
            PrincipalError::InvalidService("service name".to_string())
        );
    }
}
// end tests -- do not delete; needed for coverage.
