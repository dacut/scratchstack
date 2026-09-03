//! Tag validation utilities.
use {
    crate::constants::{TAG_KEY_REGEX, TAG_VALUE_REGEX},
    scratchstack_core::RequestId,
    scratchstack_shapes_iam::types::error::{InvalidInputException, ValidationError},
    std::collections::HashSet,
};

/// The longest tag key IAM accepts, in characters. The regexes carry the character set; neither
/// encodes a length, so the bounds live here.
const MAX_TAG_KEY_CHARS: usize = 128;

/// The longest tag value IAM accepts, in characters.
const MAX_TAG_VALUE_CHARS: usize = 256;

/// Validate that the tag key is valid according to AWS IAM rules.
///
/// A key is 1 to 128 characters drawn from [`TAG_KEY_REGEX`]: Unicode letters, separators and
/// numbers, plus `_.:/=+-@`. The length is counted in characters rather than bytes, as IAM counts
/// it, so a key of 128 CJK characters fits where its 384 bytes would not.
///
/// Note that tag key rules vary between AWS services. Note also that the generated `Tag` shape
/// validates its own key against the same pattern but bounds the length in *bytes*, so a long
/// non-ASCII key can be refused there, with a different message, before reaching this.
pub fn validate_tag_key(tag_key: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    validate_tag_key_inner(tag_key.as_ref(), request_id)
}

fn validate_tag_key_inner(tag_key: &str, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Tag key must contain only letters, digits, spaces, or the symbols _.:/=+-@ and must be between 1 and 128 characters long.";

    // The regex is anchored and one-or-more, so it rejects an empty key on its own; only the
    // upper bound is left to apply, and the character count runs first as the cheaper test.
    if tag_key.chars().count() > MAX_TAG_KEY_CHARS || !TAG_KEY_REGEX.is_match(tag_key) {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}

/// Validate that no tag key appears more than once in `keys`.
///
/// IAM compares tag keys case-insensitively -- the tag tables key each row on a lower-cased copy
/// of the key -- so keys differing only in case are the same key, and a request naming both is
/// asking for two values for one tag.
///
/// The code and message here are what the live service returns, verbatim. `InvalidInput` rather
/// than the `ValidationError` the per-value checks report: a member constraint is caught by IAM's
/// request-validation framework, which reports it with its own "N validation errors detected"
/// wording, while a duplicate key is a semantic check on the request as a whole and gets its own
/// sentence.
pub fn validate_tag_keys_unique<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    request_id: RequestId,
) -> Result<(), InvalidInputException> {
    const MESSAGE: &str = "Duplicate tag keys found. Please note that Tag keys are case insensitive.";

    let mut seen = HashSet::new();

    for key in keys {
        if !seen.insert(key.to_ascii_lowercase()) {
            return Err(InvalidInputException::builder().message(MESSAGE).request_id(request_id).build());
        }
    }

    Ok(())
}

/// Validate that the tag value is valid according to AWS IAM rules.
///
/// A value is at most 256 characters drawn from [`TAG_VALUE_REGEX`], which is [`TAG_KEY_REGEX`]
/// permitting the empty string, since IAM lets a tag carry a key with no value. The length is
/// counted in characters rather than bytes, as IAM counts it.
///
/// Note that tag value rules vary between AWS services.
pub fn validate_tag_value(tag_value: impl AsRef<str>, request_id: RequestId) -> Result<(), ValidationError> {
    validate_tag_value_inner(tag_value.as_ref(), request_id)
}

fn validate_tag_value_inner(tag_value: &str, request_id: RequestId) -> Result<(), ValidationError> {
    const MESSAGE: &str = "Tag value must contain only letters, digits, spaces, or the symbols _.:/=+-@ and must be at most 256 characters long.";

    if tag_value.chars().count() > MAX_TAG_VALUE_CHARS || !TAG_VALUE_REGEX.is_match(tag_value) {
        Err(ValidationError::builder().message(MESSAGE).request_id(request_id).build())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_ok(s: &str) -> bool {
        validate_tag_key(s, RequestId::new()).is_ok()
    }

    fn value_ok(s: &str) -> bool {
        validate_tag_value(s, RequestId::new()).is_ok()
    }

    #[test_log::test]
    fn tag_key_accepts_the_documented_character_set() {
        for s in ["Dept", "cost-center", "_.:/=+-@", "a1", "Cost Center", "Ünïcödé", "部門", "Δelta", "٣"] {
            assert!(key_ok(s), "key {s:?} should be accepted");
        }
    }

    #[test_log::test]
    fn tag_key_rejects_characters_outside_it() {
        // The backslash is the one this used to admit: the old character set was a regex class's
        // escaped hyphen, `\-`, carried into a Rust string literal, where it means a real one.
        for s in ["", "a\\b", "a!b", "a#b", "a,b", "a\"b", "a'b", "a%b", "a\tb", "a\u{0}b"] {
            assert!(!key_ok(s), "key {s:?} should be rejected");
        }
    }

    /// A newline must not pass, including a trailing one -- some regex dialects let `$` match
    /// before a final newline, which would admit a key that spans lines in a log.
    #[test_log::test]
    fn tag_key_rejects_newlines_anywhere() {
        for s in ["a\nb", "abc\n", "\nabc", "abc\r\n", "a\r\nb"] {
            assert!(!key_ok(s), "key {s:?} should be rejected");
        }
    }

    #[test_log::test]
    fn tag_key_length_is_counted_in_characters() {
        assert!(key_ok(&"a".repeat(MAX_TAG_KEY_CHARS)));
        assert!(!key_ok(&"a".repeat(MAX_TAG_KEY_CHARS + 1)));

        // 128 CJK characters occupy 384 bytes. IAM counts characters, so this is a legal key and
        // a byte-length bound would wrongly reject it.
        let cjk = "部".repeat(MAX_TAG_KEY_CHARS);
        assert_eq!(cjk.len(), MAX_TAG_KEY_CHARS * 3, "sanity: three bytes per character");
        assert!(key_ok(&cjk));
        assert!(!key_ok(&"部".repeat(MAX_TAG_KEY_CHARS + 1)));
    }

    #[test_log::test]
    fn tag_value_accepts_the_documented_character_set_and_the_empty_string() {
        for s in ["", "Engineering", "_.:/=+-@", "Cost Center", "部門"] {
            assert!(value_ok(s), "value {s:?} should be accepted");
        }
    }

    #[test_log::test]
    fn tag_value_rejects_characters_outside_it() {
        for s in ["a\\b", "a!b", "a\tb", "a\nb", "abc\n"] {
            assert!(!value_ok(s), "value {s:?} should be rejected");
        }
    }

    #[test_log::test]
    fn tag_value_length_is_counted_in_characters() {
        assert!(value_ok(&"a".repeat(MAX_TAG_VALUE_CHARS)));
        assert!(!value_ok(&"a".repeat(MAX_TAG_VALUE_CHARS + 1)));
        assert!(value_ok(&"部".repeat(MAX_TAG_VALUE_CHARS)));
        assert!(!value_ok(&"部".repeat(MAX_TAG_VALUE_CHARS + 1)));
    }
}
