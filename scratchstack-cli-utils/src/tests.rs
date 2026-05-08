use {
    crate::{ShorthandValue, parse_shorthand},
    anyhow::{Result as AnyResult, anyhow},
    clap::Parser,
    pretty_assertions::assert_eq,
    serde::{Deserialize, Serialize},
    std::{ffi::OsString, str::FromStr},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Tag {
    #[serde(rename = "Key")]
    key: String,

    #[serde(rename = "Value")]
    value: String,
}

impl Tag {
    fn from_args(args: &[impl AsRef<str>]) -> AnyResult<Vec<Self>> {
        let mut tags = Vec::new();

        for arg in args {
            let s = arg.as_ref();
            if s.starts_with('[') {
                tags = serde_json::from_str(s)?;
            } else {
                tags.push(Tag::from_str(s).map_err(|e| anyhow!("Failed to parse tag from '{s}': {e}"))?);
            }
        }
        Ok(tags)
    }
}

impl FromStr for Tag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = parse_shorthand(s).map_err(|e| format!("Failed to parse tag from '{s}': {e}"))?;

        let ShorthandValue::Map(val) = val else {
            return Err(format!(
                "Invalid tag format: '{s}'. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
            ));
        };

        let key = val
            .get("Key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Missing 'Key' field in tag: '{s}'"))?
            .to_string();
        if key.is_empty() {
            return Err("Tag key cannot be empty".to_string());
        }

        let value = val
            .get("Value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Missing 'Value' field in tag: '{s}'"))?
            .to_string();

        if val.len() != 2 {
            return Err(format!("Invalid tag format: '{s}'. Tags must only contain 'Key' and 'Value' fields"));
        }

        Ok(Tag {
            key,
            value,
        })
    }
}

#[test]
fn test_tags() {
    // Clap's value_parser returns one value per token, so a single JSON array
    // argument can't expand directly into multiple Vec<Tag> entries. Instead,
    // we collect raw strings via a helper struct and post-process them.
    #[derive(Debug, Parser)]
    struct RawArgs {
        #[clap(long, num_args = 0..=50)]
        tags: Vec<String>,
    }

    struct Args {
        tags: Vec<Tag>,
    }

    impl Args {
        fn parse_from<I, S>(itr: I) -> AnyResult<Self>
        where
            I: IntoIterator<Item = S>,
            S: Into<OsString> + Clone,
        {
            let raw = RawArgs::parse_from(itr);
            let tags = Tag::from_args(&raw.tags)?;
            Ok(Self {
                tags,
            })
        }
    }

    let args = Args::parse_from(["test", "--tags", "Key=k1,Value=v1", "--tags", "Key=k2,Value=v2"]).unwrap();
    assert_eq!(args.tags.len(), 2);

    let args =
        Args::parse_from(["test", "--tags", r#"[{"Key":"k1","Value":"v1"},{"Key":"k2","Value":"v2"}]"#]).unwrap();
    assert_eq!(args.tags.len(), 2);
}
