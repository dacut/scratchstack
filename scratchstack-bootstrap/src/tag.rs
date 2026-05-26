//! Tag parsing utilities
use {
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::{Tag, error::ValidationError},
    },
    std::collections::{HashMap, HashSet},
};

/// Convert a list of shorthand values to a `Vec<Tag>`.
pub(crate) fn tags_from_shorthand(values: &[impl AsRef<str>]) -> Result<Vec<Tag>, IamError> {
    let mut tags = Vec::with_capacity(values.len());
    let mut tag_keys_lower = HashSet::with_capacity(values.len());

    for value in values {
        let value = value.as_ref();
        let parsed = parse_shorthand(value).map_err(|e| {
            IamError::from(ValidationError::builder().message(format!("Invalid tag format: {value:?}: {e}")).build())
        })?;
        match parsed {
            ShorthandValue::List(values) => {
                for value in values {
                    let ShorthandValue::Map(map) = value else {
                        return Err(ValidationError::builder()
                            .message(format!(
                                "Invalid tag format: {value:?}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                            ))
                            .build()
                            .into());
                    };
                    let tag = tag_from_shorthand(&map)?;
                    let tag_key_lower = tag.key.to_lowercase();
                    if tag_keys_lower.contains(&tag_key_lower) {
                        return Err(ValidationError::builder()
                            .message(format!("Duplicate tag key {}. Note that tag keys are case-insensitive.", tag.key))
                            .build()
                            .into());
                    }
                    tag_keys_lower.insert(tag_key_lower);
                    tags.push(tag);
                }
            }
            ShorthandValue::Map(map) => {
                let tag = tag_from_shorthand(&map)?;
                let tag_key_lower = tag.key.to_lowercase();
                if tag_keys_lower.contains(&tag_key_lower) {
                    return Err(ValidationError::builder()
                        .message(format!("Duplicate tag key {}. Note that tag keys are case-insensitive.", tag.key))
                        .build()
                        .into());
                }
                tag_keys_lower.insert(tag_key_lower);
                tags.push(tag);
            }
            _ => {
                return Err(ValidationError::builder()
                    .message(format!(
                        "Invalid tag format: {value:?}. Tags must be in the format 'Key=k,Value=v' or a JSON object with 'Key' and 'Value' fields"
                    ))
                    .build()
                    .into());
            }
        }
    }
    Ok(tags)
}

/// Convert a map of keys to shorthand values to a [`Tag`].
fn tag_from_shorthand(map: &HashMap<String, ShorthandValue>) -> Result<Tag, IamError> {
    Tag::try_from(map).map_err(|e| {
        IamError::from(ValidationError::builder().message(format!("Invalid tag format: {map:?}: {e}")).build())
    })
}
