use {
    anyhow::{Result as AnyResult, bail},
    derive_builder::Builder,
    regex::Regex,
    serde::{Deserialize, Serialize},
    std::sync::LazyLock,
};

/// Ensure that the given tag key is valid according to AWS IAM rules.
pub fn validate_tag_key(key: impl AsRef<str>) -> AnyResult<()> {
    // Regular expression for tag keys. Don't check the length here; it results in an overly large
    // regex.
    static TAG_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$").unwrap());

    let key = key.as_ref();

    if !TAG_KEY_REGEX.is_match(key) {
        bail!("Tag key contains invalid characters");
    }

    let char_count = key.chars().count();
    if char_count < 1 || char_count > 128 {
        bail!("Tag key must be between 1 and 128 characters long");
    }

    Ok(())
}

/// Ensure that the given tag value is valid according to AWS IAM rules.
pub fn validate_tag_value(value: impl AsRef<str>) -> AnyResult<()> {
    // Regular expression for tag values. Don't check the length here; it results in an overly large
    // regex.
    static TAG_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$").unwrap());

    let value = value.as_ref();

    if !TAG_VALUE_REGEX.is_match(value) {
        bail!("Tag value contains invalid characters");
    }

    let char_count = value.chars().count();
    if char_count > 256 {
        bail!("Tag value must be between 0 and 256 characters long");
    }

    Ok(())
}

/// User-provided metadata associated with an IAM resource.
///
/// ## References
/// * [AWS Tag data type](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Tag.html)
/// * [Archived](https://web.archive.org/web/20251201154605/https://docs.aws.amazon.com/IAM/latest/APIReference/API_Tag.html)
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
#[builder(build_fn(validate = "TagBuilder::validate"))]
pub struct Tag {
    /// The key used to identify or look up the tag.
    key: String,

    /// The value associated with this tag.
    value: String,
}

impl Tag {
    /// Create a new [`TagBulder`] for programmatically constructing a `Tag`.
    pub fn builder() -> TagBuilder {
        TagBuilder::default()
    }

    /// Create a new tag with the given key and value.
    ///
    /// If the key or value are invalid according to AWS IAM rules, an error is returned.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> AnyResult<Self> {
        let key = key.into();
        let value = value.into();

        validate_tag_key(&key)?;
        validate_tag_value(&value)?;

        Ok(Self {
            key,
            value,
        })
    }

    /// Create a new tag with the given key and value, skipping validation.
    ///
    /// # Safety
    /// The caller must ensure that the key and value are valid according to AWS IAM rules. This
    /// can be performed using the [`validate_tag_key`] and [`validate_tag_value`] functions.
    pub unsafe fn new_unchecked(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Returns the key of this tag.
    #[inline(always)]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the value of this tag.
    #[inline(always)]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Parse a single `Tag` from AWS shorthand syntax.
///
/// This allows `Vec<Tag>` to be specified on a CLI using Clap as shorthand in the form
/// `--tag Key=Foo,Value=Bar --tag Key=Hello,Value=World`.
#[cfg(feature = "clap")]
impl std::str::FromStr for Tag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_tag_shorthand(s.trim())
    }
}

impl TagBuilder {
    fn validate(&self) -> Result<(), String> {
        let key = self.key.as_ref().ok_or("Tag key is required".to_string())?;
        let value = self.value.as_ref().ok_or("Tag value is required".to_string())?;

        validate_tag_key(key).map_err(|e| e.to_string())?;
        validate_tag_value(value).map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// Parse a [`Tag`] from AWS shorthand syntax (`Key=...,Value=...`).
#[cfg(feature = "clap")]
fn parse_tag_shorthand(s: &str) -> Result<Tag, String> {
    let value = crate::shorthand::parse(s).map_err(|e| format!("Invalid shorthand tag syntax: {e}"))?;
    let map = value.as_map().ok_or("Expected shorthand key=value pairs")?;
    let get = |field: &str| -> Result<String, String> {
        map.get(field)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("Missing '{field}' in tag shorthand (expected Key=...,Value=...)"))
    };
    Tag::new(get("Key")?, get("Value")?).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_eq};

    mod tag_builder {
        use {crate::iam::tag::*, pretty_assertions::assert_eq};

        #[test_log::test]
        fn builder_valid() {
            let tag = Tag::builder().key("Environment".to_string()).value("Production".to_string()).build().unwrap();
            assert_eq!(tag.key(), "Environment");
            assert_eq!(tag.value(), "Production");
        }

        #[test_log::test]
        fn builder_empty_value() {
            let tag = Tag::builder().key("Marker".to_string()).value("".to_string()).build().unwrap();
            assert_eq!(tag.key(), "Marker");
            assert_eq!(tag.value(), "");
        }

        #[test_log::test]
        fn builder_missing_key() {
            assert!(Tag::builder().value("prod".to_string()).build().is_err());
        }

        #[test_log::test]
        fn builder_missing_value() {
            assert!(Tag::builder().key("Environment".to_string()).build().is_err());
        }

        #[test_log::test]
        fn builder_invalid_key_empty() {
            assert!(Tag::builder().key("".to_string()).value("prod".to_string()).build().is_err());
        }

        #[test_log::test]
        fn builder_invalid_key_too_long() {
            assert!(Tag::builder().key("a".repeat(129)).value("prod".to_string()).build().is_err());
        }

        #[test_log::test]
        fn builder_invalid_key_emoji() {
            assert!(Tag::builder().key("env_😀".to_string()).value("prod".to_string()).build().is_err());
        }

        #[test_log::test]
        fn builder_invalid_value_too_long() {
            assert!(Tag::builder().key("Environment".to_string()).value("a".repeat(257)).build().is_err());
        }

        #[test_log::test]
        fn builder_invalid_value_emoji() {
            assert!(Tag::builder().key("Environment".to_string()).value("prod_😀".to_string()).build().is_err());
        }
    }

    #[test_log::test]
    fn new_valid() {
        let tag = Tag::new("Team", "Engineering").unwrap();
        assert_eq!(tag.key(), "Team");
        assert_eq!(tag.value(), "Engineering");
    }

    #[test_log::test]
    fn new_unchecked() {
        let tag = unsafe { Tag::new_unchecked("Team😀", "Engineering😀") };
        assert_eq!(tag.key(), "Team😀");
        assert_eq!(tag.value(), "Engineering😀");
    }

    #[test_log::test]
    fn new_invalid_key() {
        assert!(Tag::new("bad key!", "value").is_err());
    }

    #[test_log::test]
    fn new_invalid_value() {
        assert!(Tag::new("key", "bad value!").is_err());
    }

    #[test_log::test]
    fn check_tag_validation() {
        assert!(validate_tag_key("valid_tag_key").is_ok());
        assert!(validate_tag_value("valid_tag_value").is_ok());

        assert!(validate_tag_key("").is_err());
        assert!(validate_tag_key("a".repeat(129)).is_err());
        assert!(validate_tag_value("a".repeat(257)).is_err());

        assert!(validate_tag_key("emoji_tag_key_😀").is_err());
        assert!(validate_tag_value("emoji_tag_value_😀").is_err());
    }

    #[cfg(feature = "clap")]
    mod clap_parsing {
        use {super::super::*, pretty_assertions::assert_eq};

        #[test_log::test]
        fn parse_shorthand() {
            let tag: Tag = "Key=Foo,Value=Bar".parse().unwrap();
            assert_eq!(tag.key(), "Foo");
            assert_eq!(tag.value(), "Bar");
        }

        #[test_log::test]
        fn parse_shorthand_empty_value() {
            let tag: Tag = "Key=Foo,Value=".parse().unwrap();
            assert_eq!(tag.key(), "Foo");
            assert_eq!(tag.value(), "");
        }

        #[test_log::test]
        fn parse_shorthand_rejects_emoji_key() {
            assert!("Key=😀,Value=bar".parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_rejects_emoji_value() {
            assert!("Key=foo,Value=😀".parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_missing_key_field() {
            assert!("Value=bar".parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_missing_value_field() {
            assert!("Key=foo".parse::<Tag>().is_err());
        }

        // Shorthand edge cases
        #[test_log::test]
        fn parse_shorthand_empty_string() {
            assert!("".parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_only_whitespace() {
            assert!("   ".parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_key_at_max_length() {
            let key = "a".repeat(128);
            let input = format!("Key={key},Value=bar");
            let tag: Tag = input.parse().unwrap();
            assert_eq!(tag.key(), key);
        }

        #[test_log::test]
        fn parse_shorthand_key_one_over_max_length() {
            let key = "a".repeat(129);
            let input = format!("Key={key},Value=bar");
            assert!(input.parse::<Tag>().is_err());
        }

        #[test_log::test]
        fn parse_shorthand_value_at_max_length() {
            let value = "a".repeat(256);
            let input = format!("Key=foo,Value={value}");
            let tag: Tag = input.parse().unwrap();
            assert_eq!(tag.value(), value);
        }

        #[test_log::test]
        fn parse_shorthand_value_one_over_max_length() {
            let value = "a".repeat(257);
            let input = format!("Key=foo,Value={value}");
            assert!(input.parse::<Tag>().is_err());
        }
    }
}
