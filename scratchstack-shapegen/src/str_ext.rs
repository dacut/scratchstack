//! Extensions on string types.

/// Rust keywords that cannot be used as identifiers. These are used to determine when to use raw
/// identifiers in the generated code.
const RUST_IDENTS: &[&str] = &[
    "abstract", "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
];

pub trait StrExt {
    /// Indicates whether this Smithy identifier is a builtin type.
    fn is_smithy_builtin(&self) -> bool;

    /// Indicates whether this string is in SCREAMING_SNAKE_CASE.
    fn is_screaming_snake_case(&self) -> bool;

    /// Convert an identifier to Pascal case.
    ///
    /// This is used to convert Smithy shape names to Rust type names.
    fn to_pascal_case(&self) -> String;

    /// Convert a string identifier to snake case. This is used to convert Smithy member names to Rust field names.
    fn to_snake_case(&self) -> String;
}

impl StrExt for str {
    fn is_smithy_builtin(&self) -> bool {
        self.starts_with("smithy.api#")
    }

    fn is_screaming_snake_case(&self) -> bool {
        self.chars().all(|c| c.is_ascii_uppercase() || c == '_')
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

        if RUST_IDENTS.contains(&result.as_str()) {
            result = format!("r#{result}");
        }

        result
    }

    fn to_snake_case(&self) -> String {
        let mut result = String::new();
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

        if RUST_IDENTS.contains(&result.as_str()) {
            result = format!("r#{result}");
        }

        result
    }
}

impl StrExt for String {
    fn is_smithy_builtin(&self) -> bool {
        self.as_str().is_smithy_builtin()
    }

    fn is_screaming_snake_case(&self) -> bool {
        self.as_str().is_screaming_snake_case()
    }

    fn to_pascal_case(&self) -> String {
        self.as_str().to_pascal_case()
    }

    fn to_snake_case(&self) -> String {
        self.as_str().to_snake_case()
    }
}
