//! Tag parsing utilities
use {
    scratchstack_cli_utils::{ShorthandValue, parse_shorthand},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        types::{Tag, error::ValidationError},
    },
    std::collections::HashMap,
};

/// Convert a list of shorthand values to a `Vec<Tag>`.
pub(crate) fn tags_from_shorthand(values: &[impl AsRef<str>]) -> Result<Vec<Tag>, IamError> {
    let mut tags = Vec::with_capacity(values.len());
    let mut tag_keys_lower = Vec::with_capacity(values.len());

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
                    tag_keys_lower.push(tag_key_lower);
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
                tag_keys_lower.push(tag_key_lower);
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
    let mut tag_key = None;
    let mut tag_value = None;

    for (key, value) in map {
        match key.as_str() {
            "Key" => {
                tag_key = Some(value.as_str().ok_or_else(|| {
                    IamError::from(
                        ValidationError::builder()
                            .message(format!("Invalid tag format: {map:?}. 'Key' must be a string"))
                            .build(),
                    )
                })?);
            }
            "Value" => {
                tag_value = Some(value.as_str().ok_or_else(|| {
                    IamError::from(
                        ValidationError::builder()
                            .message(format!("Invalid tag format: {map:?}. 'Value' must be a string"))
                            .build(),
                    )
                })?);
            }
            _ => {
                return Err(ValidationError::builder()
                    .message(format!("Invalid tag format: {map:?}. Tags must only contain 'Key' and 'Value' fields"))
                    .build()
                    .into());
            }
        }
    }

    let Some(tag_key) = tag_key else {
        return Err(ValidationError::builder()
            .message(format!("Invalid tag format: {map:?}. Missing 'Key' field"))
            .build()
            .into());
    };

    let Some(tag_value) = tag_value else {
        return Err(ValidationError::builder()
            .message(format!("Invalid tag format: {map:?}. Missing 'Value' field"))
            .build()
            .into());
    };

    Ok(Tag {
        key: tag_key.to_string(),
        value: tag_value.to_string(),
    })
}
