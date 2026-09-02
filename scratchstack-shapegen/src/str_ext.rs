//! Extensions on string types.

/// Rust keywords a generated identifier must be escaped past, by writing it `r#name`.
///
/// Every strict and reserved keyword of the 2015 through 2024 editions *except* the four in
/// [`UNESCAPABLE_RUST_IDENTS`], which cannot be raw identifiers at all.
const RUST_IDENTS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "do", "dyn", "else", "enum",
    "extern", "false", "final", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "macro", "match", "mod", "move",
    "mut", "override", "priv", "pub", "ref", "return", "static", "struct", "trait", "true", "try", "type", "typeof",
    "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

/// Keywords that `r#` cannot escape -- `r#self` and its three companions are rejected by the parser.
///
/// A member with one of these names gets a trailing underscore instead. No IAM or STS member hits
/// this today, but the previous list had all four among the escapable keywords, so one would have
/// produced code that does not compile. The reserved words above were missing entirely.
const UNESCAPABLE_RUST_IDENTS: &[&str] = &["Self", "crate", "self", "super"];

/// Escapes an identifier that collides with a Rust keyword.
fn escape_rust_ident(ident: String) -> String {
    if UNESCAPABLE_RUST_IDENTS.contains(&ident.as_str()) {
        format!("{ident}_")
    } else if RUST_IDENTS.contains(&ident.as_str()) {
        format!("r#{ident}")
    } else {
        ident
    }
}

pub trait StrExt {
    /// Indicates whether this Smithy identifier is a builtin type.
    fn is_smithy_builtin(&self) -> bool;

    /// Indicates whether this string is in SCREAMING_SNAKE_CASE.
    fn is_screaming_snake_case(&self) -> bool;

    /// Convert an identifier to Pascal case.
    ///
    /// This is used to convert Smithy shape names to Rust type names.
    fn to_pascal_case(&self) -> String;

    /// Convert a string identifier to a Rust identifier in snake case. This is used to convert
    /// Smithy member names to Rust field names.
    fn to_rust_ident(&self) -> String {
        self.to_rust_ident_affixed("", "")
    }

    /// Convert a string identifier to a Rust identifier in snake case, with an optional prefix and
    /// suffix.
    ///
    /// The affixes are applied before the keyword check, so a member named `Type` yields `r#type`
    /// on its own but `set_type` when prefixed -- `set_r#type` is not a valid identifier.
    fn to_rust_ident_affixed(&self, prefix: &str, suffix: &str) -> String;
}

impl StrExt for str {
    fn is_smithy_builtin(&self) -> bool {
        self.starts_with("smithy.api#")
    }

    fn is_screaming_snake_case(&self) -> bool {
        // Digits count: `SSH_KEY_2` is SCREAMING_SNAKE_CASE, and rejecting it would send the name
        // down the path that preserves inner capitals, yielding `SSHKEY2` rather than `SshKey2`.
        !self.is_empty() && self.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    fn to_pascal_case(&self) -> String {
        let mut result = String::new();
        let mut capitalize_next = true;

        if self.is_screaming_snake_case() {
            // Change SCREAMING_SNAKE_CASE to ScreamingSnakeCase.
            for c in self.chars() {
                if c == '_' {
                    capitalize_next = true;
                } else if capitalize_next {
                    result.push(c.to_ascii_uppercase());
                    capitalize_next = false;
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            }
        } else {
            for c in self.chars() {
                if c == '_' {
                    capitalize_next = true;
                } else if capitalize_next {
                    result.push(c.to_ascii_uppercase());
                    capitalize_next = false;
                } else {
                    result.push(c);
                }
            }
        }

        escape_rust_ident(result)
    }

    fn to_rust_ident_affixed(&self, prefix: &str, suffix: &str) -> String {
        let mut result = String::with_capacity(prefix.len() + self.len() + suffix.len());
        result.push_str(prefix);
        let mut prev_char_was_uppercase = false;

        for (i, c) in self.chars().enumerate() {
            if c.is_uppercase() {
                if i > 0 && !prev_char_was_uppercase {
                    result.push('_');
                }
                result.push(c.to_ascii_lowercase());
                prev_char_was_uppercase = true;
            } else {
                result.push(c);
                prev_char_was_uppercase = false;
            }
        }

        result.push_str(suffix);

        escape_rust_ident(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pascal_case_folds_screaming_snake_but_keeps_mixed_case() {
        assert_eq!("SSH_PUBLIC_KEY".to_pascal_case(), "SshPublicKey");
        assert_eq!("SSH_KEY_2".to_pascal_case(), "SshKey2");
        assert_eq!("accountIdType".to_pascal_case(), "AccountIdType");
        assert_eq!("ListAccounts".to_pascal_case(), "ListAccounts");
    }

    #[test]
    fn rust_idents_are_snake_case() {
        assert_eq!("UserName".to_rust_ident(), "user_name");
        assert_eq!("MaxItems".to_rust_ident(), "max_items");
        assert_eq!("SAMLMetadataDocument".to_rust_ident(), "samlmetadata_document");
    }

    #[test]
    fn keywords_are_escaped() {
        assert_eq!("Type".to_rust_ident(), "r#type");
        assert_eq!("Match".to_rust_ident(), "r#match");
        assert_eq!("Yield".to_rust_ident(), "r#yield");
    }

    #[test]
    fn keywords_that_cannot_be_raw_get_an_underscore() {
        // `r#self` and friends are rejected by the parser, so these must not be escaped with `r#`.
        for keyword in UNESCAPABLE_RUST_IDENTS {
            let escaped = escape_rust_ident((*keyword).to_string());
            assert_eq!(escaped, format!("{keyword}_"), "{keyword} must not become a raw identifier");
        }
    }

    #[test]
    fn affixes_are_applied_before_the_keyword_check() {
        // `set_r#type` is not a valid identifier; prefixing removes the collision entirely.
        assert_eq!("Type".to_rust_ident_affixed("set_", ""), "set_type");
        assert_eq!("Self".to_rust_ident_affixed("set_", ""), "set_self");
    }

    #[test]
    fn screaming_snake_case_detection() {
        assert!("SSH_PUBLIC_KEY".is_screaming_snake_case());
        assert!("SSH_KEY_2".is_screaming_snake_case());
        assert!(!"accountIdType".is_screaming_snake_case());
        assert!(!"".is_screaming_snake_case());
    }
}
