//! A Rust port of the AWS CLI shorthand syntax parser.
//!
//! Parses expressions like:
//!   `Key=Value,Foo=Bar`             -> {"Key": "Value", "Foo": "Bar"}
//!   `Key="hello, world",Foo=bar`    -> {"Key": "hello, world", "Foo": "bar"}
//!   `Tags=[a,b,c]`                  -> {"Tags": ["a", "b", "c"]}
//!   `Config={A=1,B=2}`              -> {"Config": {"A": "1", "B": "2"}}
//!
//! The grammar (from the original Python source comments):
//! ```text
//! parameter       = keyval *("," keyval)
//! keyval          = key "=" [values]  /  key "@=" [values]
//! key             = 1*(ALPHA / DIGIT / "-" / "_" / "." / "#" / "/" / ":")
//! values          = csv-list / explicit-list / hash-literal
//! csv-list        = first-value *("," second-value)
//! first-value     = single-quoted / double-quoted / unquoted
//! explicit-list   = "[" [value *("," value)] "]"
//! hash-literal    = "{" keyval *("," keyval) "}"
//! ```
//!
//! This is a port of the original AWS CLI shorthand parser, which is implemented in Python and can
//! be found here: https://github.com/aws/aws-cli/blob/develop/awscli/shorthand.py
//!
//! Original is Copyright 2012-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//! Licensed under the Apache License, Version 2.0.

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Position within the input where an error occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLocation {
    pub input: String,
    pub index: usize,
}

impl Display for ErrorLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Replicate the Python caret-based error location display.
        let consumed = &self.input[..self.index.min(self.input.len())];
        let num_spaces = match consumed.rfind('\n') {
            Some(pos) => self.index - pos - 1,
            None => self.index,
        };
        // Show up to the next newline (if any) on the first line.
        let line_end = self.input[self.index..].find('\n').map(|p| self.index + p).unwrap_or(self.input.len());
        let visible = &self.input[..line_end];
        let remaining = &self.input[line_end..];
        write!(f, "{}\n{}^", visible, " ".repeat(num_spaces))?;
        if !remaining.is_empty() {
            write!(f, "{remaining}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    SyntaxError {
        expected: String,
        actual: String,
        location: ErrorLocation,
    },
    DuplicateKey {
        key: String,
        location: ErrorLocation,
    },
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ParseError::SyntaxError {
                expected,
                actual,
                location,
            } => {
                write!(f, "Expected: '{expected}', received: '{actual}' for input:\n{location}")
            }
            ParseError::DuplicateKey {
                key,
                location,
            } => {
                write!(
                    f,
                    "Second instance of key \"{key}\" encountered for input:\n\
                     {location}\n\
                     This is often because there is a preceding \",\" instead of a space."
                )
            }
        }
    }
}

impl Error for ParseError {}

// ---------------------------------------------------------------------------
// Parsed value type
// ---------------------------------------------------------------------------

/// Represents a parsed shorthand value.
///
/// The AWS CLI shorthand parser produces:
/// - Scalars (strings — type coercion to int/bool happens in BackCompatVisitor)
/// - Lists (explicit `[a,b]` or implicit csv `a,b`)
/// - Maps (top-level `Key=Val,...` or nested `{Key=Val,...}`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Scalar(String),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
}

impl Value {
    /// Convenience: get a scalar string reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// Convenience: get a list reference.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v),
            _ => None,
        }
    }

    /// Convenience: get a map reference.
    pub fn as_map(&self) -> Option<&HashMap<String, Value>> {
        match self {
            Value::Map(v) => Some(v),
            _ => None,
        }
    }

    /// Look up a key in a Map value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.get(key),
            _ => None,
        }
    }
}

impl FromStr for Value {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ShorthandParser::new(s).parse()
    }
}

// ---------------------------------------------------------------------------
// Character classes (ported from the Python regexes)
// ---------------------------------------------------------------------------

/// Characters valid in a key: `[a-zA-Z0-9\-_.#/:]`
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '#' | '/' | ':')
}

/// Characters valid at the start of an unquoted value.
/// Corresponds to `_START_WORD` in the Python source.
fn is_start_word(c: char) -> bool {
    // The Python regex character class covers a wide Unicode range.
    // Simplified: not a control char, not a quote, not `,=[]{}` delimiters.
    !matches!(c, ',' | '=' | '[' | ']' | '{' | '}' | '\'' | '"') && !c.is_ascii_control() && c != ' '
}

/// Characters that can follow the start of a "first" value.
/// `_FIRST_FOLLOW_CHARS` — notably includes `=` (so `foo=bar=baz` works for the
/// first value in a csv list).
fn is_first_follow(c: char) -> bool {
    // Includes whitespace (will be rstripped), includes `=`.
    !matches!(c, ',' | '[' | ']' | '{' | '}' | '\'' | '"') && !c.is_ascii_control()
}

/// Characters that can follow the start of a "second" value.
/// `_SECOND_FOLLOW_CHARS` — excludes `=` to prevent eating into the next keyval.
fn is_second_follow(c: char) -> bool {
    !matches!(c, ',' | '=' | '[' | ']' | '{' | '}' | '\'' | '"') && !c.is_ascii_control()
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// A recursive-descent parser for AWS CLI shorthand syntax.
pub struct ShorthandParser<'a> {
    input: &'a str,
    index: usize,
}

impl<'a> ShorthandParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            index: 0,
        }
    }

    /// Parse the input and return the top-level map.
    ///
    /// ```
    /// use scratchstack_shapes::shorthand::ShorthandParser;
    /// let result = ShorthandParser::new("Key=Value,Foo=Bar").parse().unwrap();
    /// ```
    pub fn parse(mut self) -> Result<Value, ParseError> {
        let result = self.parameter()?;
        Ok(result)
    }

    // -- Helpers ------------------------------------------------------------

    fn at_eof(&self) -> bool {
        self.index >= self.input.len()
    }

    fn current(&self) -> Option<char> {
        self.input[self.index..].chars().next()
    }

    fn current_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.index).copied()
    }

    fn location(&self) -> ErrorLocation {
        ErrorLocation {
            input: self.input.to_string(),
            index: self.index,
        }
    }

    fn syntax_error(&self, expected: &str, actual: &str) -> ParseError {
        ParseError::SyntaxError {
            expected: expected.to_string(),
            actual: actual.to_string(),
            location: self.location(),
        }
    }

    fn consume_whitespace(&mut self) {
        while let Some(c) = self.current() {
            if c.is_ascii_whitespace() {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, ch: char, consume_ws: bool) -> Result<(), ParseError> {
        if consume_ws {
            self.consume_whitespace();
        }
        if self.at_eof() {
            return Err(self.syntax_error(&ch.to_string(), "EOF"));
        }
        let actual = self.current().unwrap();
        if actual != ch {
            return Err(self.syntax_error(&ch.to_string(), &actual.to_string()));
        }
        self.index += ch.len_utf8();
        if consume_ws {
            self.consume_whitespace();
        }
        Ok(())
    }

    fn backtrack_to(&mut self, ch: u8) {
        while self.index > 0 && self.input.as_bytes().get(self.index) != Some(&ch) {
            self.index -= 1;
        }
    }

    // -- Grammar productions ------------------------------------------------

    /// `parameter = keyval *("," keyval)`
    fn parameter(&mut self) -> Result<Value, ParseError> {
        let mut entries = HashMap::new();
        let (key, val) = self.keyval()?;
        entries.insert(key, val);

        let mut last_index = self.index;
        while !self.at_eof() {
            self.expect(',', true)?;
            let (key, val) = self.keyval()?;
            // Check for duplicate keys.
            if entries.contains_key(&key) {
                return Err(ParseError::DuplicateKey {
                    key,
                    location: ErrorLocation {
                        input: self.input.to_string(),
                        index: last_index + 1,
                    },
                });
            }
            entries.insert(key, val);
            last_index = self.index;
        }

        Ok(Value::Map(entries))
    }

    /// `keyval = key ("=" / "@=") [values]`
    fn keyval(&mut self) -> Result<(String, Value), ParseError> {
        let key = self.key()?;
        let mut is_paramfile = false;

        // Try consuming `@=` (paramfile syntax). If `@` isn't there, fall
        // through to plain `=`.
        if self.current() == Some('@') {
            let saved = self.index;
            self.index += 1;
            if self.current() == Some('=') {
                is_paramfile = true;
            } else {
                self.index = saved;
            }
        }

        self.expect('=', true)?;
        let val = self.values(is_paramfile)?;
        Ok((key, val))
    }

    /// `key = 1*(ALPHA / DIGIT / "-" / "_" / "." / "#" / "/" / ":")`
    fn key(&mut self) -> Result<String, ParseError> {
        let start = self.index;
        while let Some(c) = self.current() {
            if is_key_char(c) {
                self.index += c.len_utf8();
            } else {
                break;
            }
        }
        Ok(self.input[start..self.index].to_string())
    }

    /// `values = csv-list / explicit-list / hash-literal`
    fn values(&mut self, _is_paramfile: bool) -> Result<Value, ParseError> {
        if self.at_eof() {
            return Ok(Value::Scalar(String::new()));
        }
        match self.current() {
            Some('[') => self.explicit_list(),
            Some('{') => self.hash_literal(),
            _ => self.csv_value(),
        }
    }

    /// Parse a csv value, which may be a single scalar or a list.
    ///
    /// ```text
    /// foo=bar       -> Scalar("bar")
    /// foo=bar,baz   -> List(["bar", "baz"])  (if baz isn't key=val)
    /// foo=a,b,c=d   -> Scalar("a")  (b,c=d backtracks — the , after a is
    ///                                part of the top-level parameter separator)
    /// ```
    fn csv_value(&mut self) -> Result<Value, ParseError> {
        let first = self.first_value()?;
        self.consume_whitespace();

        if self.at_eof() || self.current_byte() != Some(b',') {
            return Ok(Value::Scalar(first));
        }

        // Speculatively consume the comma.
        self.expect(',', true)?;
        let mut csv_list = vec![first.clone()];

        loop {
            let saved = self.index;
            match self.second_value() {
                Ok(current) => {
                    self.consume_whitespace();
                    // If '=' follows, the token we just consumed is actually a
                    // key for the next top-level keyval. Backtrack to the comma.
                    if self.current() == Some('=') {
                        self.index = saved;
                        self.backtrack_to(b',');
                        break;
                    }
                    csv_list.push(current);
                    if self.at_eof() {
                        break;
                    }
                    match self.expect(',', true) {
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }
                Err(_) => {
                    // Backtrack to the previous comma.
                    if self.at_eof() {
                        return Err(self.syntax_error("<value>", "EOF"));
                    }
                    self.index = saved;
                    self.backtrack_to(b',');
                    break;
                }
            }
        }

        if csv_list.len() == 1 {
            // foo=bar,  then backtracked: return the scalar.
            Ok(Value::Scalar(first))
        } else {
            Ok(Value::List(csv_list.into_iter().map(Value::Scalar).collect()))
        }
    }

    /// `explicit-list = "[" [value *("," value)] "]"`
    fn explicit_list(&mut self) -> Result<Value, ParseError> {
        self.expect('[', true)?;
        let mut values = Vec::new();
        while self.current() != Some(']') {
            let val = self.explicit_values()?;
            values.push(val);
            self.consume_whitespace();
            if self.current() != Some(']') {
                self.expect(',', false)?;
                self.consume_whitespace();
            }
        }
        self.expect(']', false)?;
        Ok(Value::List(values))
    }

    /// Values inside `[...]` — same as top-level values but no csv ambiguity.
    fn explicit_values(&mut self) -> Result<Value, ParseError> {
        match self.current() {
            Some('[') => self.explicit_list(),
            Some('{') => self.hash_literal(),
            _ => {
                let v = self.first_value()?;
                Ok(Value::Scalar(v))
            }
        }
    }

    /// `hash-literal = "{" keyval *("," keyval) "}"`
    fn hash_literal(&mut self) -> Result<Value, ParseError> {
        self.expect('{', true)?;
        let mut entries = HashMap::new();
        while self.current() != Some('}') {
            let key = self.key()?;
            // Handle @= inside hash literals too.
            let mut _is_paramfile = false;
            if self.current() == Some('@') {
                let saved = self.index;
                self.index += 1;
                if self.current() == Some('=') {
                    _is_paramfile = true;
                } else {
                    self.index = saved;
                }
            }
            self.expect('=', true)?;
            let val = self.explicit_values()?;
            self.consume_whitespace();
            if self.current() != Some('}') {
                self.expect(',', false)?;
                self.consume_whitespace();
            }
            entries.insert(key, val);
        }
        self.expect('}', false)?;
        Ok(Value::Map(entries))
    }

    // -- Value terminals ----------------------------------------------------

    /// `first-value = single-quoted / double-quoted / unquoted-first`
    fn first_value(&mut self) -> Result<String, ParseError> {
        match self.current() {
            Some('\'') => self.single_quoted_value(),
            Some('"') => self.double_quoted_value(),
            _ => self.unquoted_first_value(),
        }
    }

    /// Second and subsequent values in a csv list — unquoted variant excludes `=`.
    fn second_value(&mut self) -> Result<String, ParseError> {
        match self.current() {
            Some('\'') => self.single_quoted_value(),
            Some('"') => self.double_quoted_value(),
            _ => self.unquoted_second_value(),
        }
    }

    fn single_quoted_value(&mut self) -> Result<String, ParseError> {
        self.consume_quoted('\'')
    }

    fn double_quoted_value(&mut self) -> Result<String, ParseError> {
        self.consume_quoted('"')
    }

    /// Consume a quoted string, stripping outer quotes and handling escapes.
    fn consume_quoted(&mut self, quote: char) -> Result<String, ParseError> {
        let start = self.index;
        self.index += quote.len_utf8(); // skip opening quote

        let mut result = String::new();
        loop {
            if self.at_eof() {
                return Err(ParseError::SyntaxError {
                    expected: quote.to_string(),
                    actual: "EOF".to_string(),
                    location: ErrorLocation {
                        input: self.input.to_string(),
                        index: start,
                    },
                });
            }
            let c = self.current().unwrap();
            if c == '\\' {
                // Peek at next char.
                let next_index = self.index + 1;
                if next_index < self.input.len() {
                    let next = self.input[next_index..].chars().next().unwrap();
                    if next == quote {
                        // Escaped quote: \' or \"
                        result.push(quote);
                        self.index = next_index + next.len_utf8();
                        continue;
                    } else if next == '\\' {
                        // Escaped backslash: \\
                        result.push('\\');
                        self.index = next_index + 1;
                        continue;
                    }
                }
                result.push(c);
                self.index += 1;
            } else if c == quote {
                self.index += quote.len_utf8(); // skip closing quote
                return Ok(result);
            } else {
                result.push(c);
                self.index += c.len_utf8();
            }
        }
    }

    /// Unquoted value with "first" follow characters (includes `=`).
    fn unquoted_first_value(&mut self) -> Result<String, ParseError> {
        if self.at_eof() {
            return Ok(String::new());
        }
        let c = self.current().unwrap();

        // Check for escaped comma at start, or a valid start-word char.
        #[allow(clippy::nonminimal_bool)]
        if !is_start_word(c) && !(c == '\\' && self.peek_byte(1) == Some(b',')) {
            return Ok(String::new());
        }
        self.consume_unquoted_value(is_first_follow)
    }

    /// Unquoted value with "second" follow characters (excludes `=`).
    fn unquoted_second_value(&mut self) -> Result<String, ParseError> {
        if self.at_eof() {
            return Err(self.syntax_error("<second value>", "EOF"));
        }
        let c = self.current().unwrap();
        #[allow(clippy::nonminimal_bool)]
        if !is_start_word(c) && !(c == '\\' && self.peek_byte(1) == Some(b',')) {
            return Err(self.syntax_error("<second value>", &c.to_string()));
        }
        self.consume_unquoted_value(is_second_follow)
    }

    /// Shared unquoted value consumption with a configurable follow-char predicate.
    fn consume_unquoted_value(&mut self, is_follow: fn(char) -> bool) -> Result<String, ParseError> {
        let start = self.index;

        // Consume first char (already validated by caller).
        if let Some(c) = self.current() {
            self.index += c.len_utf8();
        }

        // Consume follow chars, handling escaped commas.
        while !self.at_eof() {
            let c = self.current().unwrap();
            if c == '\\' && self.peek_byte(1) == Some(b',') {
                // Escaped comma: consume both chars.
                self.index += 2;
            } else if is_follow(c) {
                self.index += c.len_utf8();
            } else {
                break;
            }
        }

        let raw = &self.input[start..self.index];
        // Rstrip whitespace (the Python version does .rstrip()).
        let trimmed = raw.trim_end();
        // Adjust index back if we consumed trailing whitespace.
        self.index = start + trimmed.len();

        // Unescape `\,` -> `,`
        let result = trimmed.replace("\\,", ",");
        Ok(result)
    }

    fn peek_byte(&self, offset: usize) -> Option<u8> {
        self.input.as_bytes().get(self.index + offset).copied()
    }
}

// ---------------------------------------------------------------------------
// Convenience function
// ---------------------------------------------------------------------------

/// Parse a shorthand expression, returning the top-level value.
///
/// ```
/// use scratchstack_shapes::shorthand::{parse, Value};
///
/// let val = parse("Key=Hello,Foo=Bar").unwrap();
/// assert_eq!(val.get("Key").unwrap().as_str(), Some("Hello"));
/// assert_eq!(val.get("Foo").unwrap().as_str(), Some("Bar"));
/// ```
pub fn parse(input: &str) -> Result<Value, ParseError> {
    ShorthandParser::new(input).parse()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers for building expected values concisely.
    fn s(v: &str) -> Value {
        Value::Scalar(v.to_string())
    }
    fn list(vs: Vec<Value>) -> Value {
        Value::List(vs)
    }
    fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    // -- Basic key=value pairs ----------------------------------------------

    #[test]
    fn single_keyval() {
        assert_eq!(parse("foo=bar").unwrap(), map(vec![("foo", s("bar"))]));
    }

    #[test]
    fn multiple_keyvals() {
        assert_eq!(parse("foo=bar,baz=qux").unwrap(), map(vec![("foo", s("bar")), ("baz", s("qux"))]));
    }

    #[test]
    fn three_keyvals() {
        assert_eq!(parse("a=b,c=d,e=f").unwrap(), map(vec![("a", s("b")), ("c", s("d")), ("e", s("f"))]));
    }

    #[test]
    fn empty_value() {
        assert_eq!(parse("foo=").unwrap(), map(vec![("foo", s(""))]));
    }

    // -- Quoting ------------------------------------------------------------

    #[test]
    fn double_quoted_value() {
        assert_eq!(parse("foo=\"bar\"").unwrap(), map(vec![("foo", s("bar"))]));
    }

    #[test]
    fn single_quoted_value() {
        assert_eq!(parse("foo='bar'").unwrap(), map(vec![("foo", s("bar"))]));
    }

    #[test]
    fn quoted_value_with_comma() {
        assert_eq!(
            parse("Key=\"hello, world\",Value=test").unwrap(),
            map(vec![("Key", s("hello, world")), ("Value", s("test"))])
        );
    }

    #[test]
    fn quoted_value_with_spaces() {
        assert_eq!(
            parse("Key=\"Hello\",Value=\"World 1 2 3\"").unwrap(),
            map(vec![("Key", s("Hello")), ("Value", s("World 1 2 3"))])
        );
    }

    #[test]
    fn escaped_quote_inside_double_quoted() {
        assert_eq!(parse(r#"foo="say \"hi\"""#).unwrap(), map(vec![("foo", s("say \"hi\""))]));
    }

    #[test]
    fn escaped_quote_inside_single_quoted() {
        assert_eq!(parse(r"foo='it\'s'").unwrap(), map(vec![("foo", s("it's"))]));
    }

    // -- CSV values (implicit lists) ----------------------------------------

    #[test]
    fn csv_value_becomes_list() {
        // foo=a,b (where b is not key=val)-> list
        // But at top level, comma separates keyvals, so this actually
        // tries to parse b as a key. The Python parser backtracks here.
        // foo=a,b -> foo=a (scalar), then b is next keyval (error if no =).
        // This matches the Python behavior where csv lists only work if the
        // model expects a list (handled by BackCompatVisitor).
        //
        // For purely syntactic parsing, foo=a,b,c=d parses as:
        //   foo="a", c="d"  (b is part of the backtrack)
        //
        // But foo=a,b (no more keyvals) -> foo=["a","b"]
        let result = parse("foo=a,b").unwrap();
        // The parser sees a,b — first value "a", comma, tries second value "b".
        // "b" is valid but then there's no "=" after, so at top level this is
        // actually foo=["a","b"] since it's only two values with no = in sight.
        assert_eq!(result, map(vec![("foo", list(vec![s("a"), s("b")]))]));
    }

    // -- Explicit lists -----------------------------------------------------

    #[test]
    fn explicit_list_simple() {
        assert_eq!(parse("foo=[a,b,c]").unwrap(), map(vec![("foo", list(vec![s("a"), s("b"), s("c")]))]));
    }

    #[test]
    fn explicit_list_with_quotes() {
        assert_eq!(parse("foo=[\"a b\",c]").unwrap(), map(vec![("foo", list(vec![s("a b"), s("c")]))]));
    }

    // -- Hash literals ------------------------------------------------------

    #[test]
    fn hash_literal() {
        assert_eq!(parse("foo={a=1,b=2}").unwrap(), map(vec![("foo", map(vec![("a", s("1")), ("b", s("2"))]))]));
    }

    // -- Nested structures --------------------------------------------------

    #[test]
    fn nested_list_in_hash() {
        assert_eq!(
            parse("foo={a=[1,2],b=3}").unwrap(),
            map(vec![("foo", map(vec![("a", list(vec![s("1"), s("2")])), ("b", s("3")),]))])
        );
    }

    // -- Escaped commas -----------------------------------------------------

    #[test]
    fn escaped_comma_in_value() {
        assert_eq!(parse("foo=a\\,b").unwrap(), map(vec![("foo", s("a,b"))]));
    }

    // -- Duplicate key detection --------------------------------------------

    #[test]
    fn duplicate_key_error() {
        let err = parse("Key=a,Key=b").unwrap_err();
        assert!(matches!(err, ParseError::DuplicateKey { .. }));
    }

    // -- Keys with special chars --------------------------------------------

    #[test]
    fn key_with_dots_and_colons() {
        assert_eq!(parse("aws:tag/Name=hello").unwrap(), map(vec![("aws:tag/Name", s("hello"))]));
    }

    // -- Paramfile syntax (@=) ---------------------------------------------

    #[test]
    fn paramfile_marker_parsed() {
        // We parse @= but don't resolve files — just pass through the value.
        assert_eq!(parse("data@=file://config.json").unwrap(), map(vec![("data", s("file://config.json"))]));
    }

    // -- Value with equals sign in it ---------------------------------------

    #[test]
    fn value_containing_equals() {
        // First value can contain `=`.
        assert_eq!(parse("foo=a=b").unwrap(), map(vec![("foo", s("a=b"))]));
    }
}
