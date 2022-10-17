use {
    regex::Regex,
    regex_syntax::escape_into,
    std::{
        convert::Infallible,
        fmt::{Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
        str::FromStr,
    },
};

/// A glob-style pattern matcher used in various Aspen policy elements.
#[derive(Debug, Clone)]
pub enum GlobPattern {
    /// Empty match.
    Empty,

    /// Wildcard match.
    Any,

    /// Exact string match.
    Exact(Box<String>),

    /// StartsWith is a simple prefix match.
    StartsWith(Box<String>),

    /// Regex pattern contains the original Arn glob-like pattern followed by the compiled regex.
    Regex(Box<(String, Regex)>),
}

impl Display for GlobPattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            GlobPattern::Empty => Ok(()),
            GlobPattern::Any => write!(f, "*"),
            GlobPattern::Exact(s) => f.write_str(s),
            GlobPattern::StartsWith(s) => write!(f, "{}*", s),
            GlobPattern::Regex(sr) => f.write_str(sr.0.as_str()),
        }
    }
}

impl PartialEq for GlobPattern {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (Self::Any, Self::Any) => true,
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::StartsWith(a), Self::StartsWith(b)) => a == b,
            (Self::Regex(sr_a), Self::Regex(sr_b)) => sr_a.0 == sr_b.0,
            _ => false,
        }
    }
}

impl Eq for GlobPattern {}

impl Hash for GlobPattern {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        match self {
            Self::Empty => hasher.write_u8(0),
            Self::Any => hasher.write_u8(1),
            Self::Exact(s) => {
                hasher.write_u8(2);
                s.hash(hasher);
            }
            Self::StartsWith(s) => {
                hasher.write_u8(3);
                s.hash(hasher);
            }
            Self::Regex(sr) => {
                hasher.write_u8(4);
                sr.0.hash(hasher);
            }
        }
    }
}

impl<T: AsRef<str>> From<T> for GlobPattern {
    fn from(s: T) -> Self {
        Self::new(s.as_ref())
    }
}

impl FromStr for GlobPattern {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Infallible> {
        Ok(Self::new(s))
    }
}

impl GlobPattern {
    /// Indicate whether the specified string from an [Arn] segment matches this pattern.
    pub fn matches(&self, segment: &str) -> bool {
        match self {
            Self::Empty => segment.is_empty(),
            Self::Any => true,
            Self::Exact(value) => segment == value.as_str(),
            Self::StartsWith(prefix) => segment.starts_with(prefix.as_str()),
            Self::Regex(sr) => sr.1.is_match(segment),
        }
    }

    /// Create a new [ArnSegmentPattern] from a string.
    pub fn new(s: &str) -> Self {
        if s.is_empty() {
            return GlobPattern::Empty;
        }

        if s == "*" {
            return GlobPattern::Any;
        }

        let mut regex_pattern = String::with_capacity(s.len() + 2);
        let mut must_use_regex = false;
        let mut wildcard_seen = false;

        regex_pattern.push('^');

        for c in s.chars() {
            match c {
                '*' => {
                    wildcard_seen = true;
                    regex_pattern.push_str(".*");
                }

                '?' => {
                    must_use_regex = true;
                    regex_pattern.push('.');
                }

                _ => {
                    // Escape any special Regex characters
                    let c_s = c.to_string();
                    escape_into(c_s.as_str(), &mut regex_pattern);

                    if wildcard_seen {
                        must_use_regex = true;
                        wildcard_seen = false;
                    }
                }
            }
        }

        if must_use_regex {
            regex_pattern.push('$');
            Self::Regex(Box::new((
                s.to_string(),
                Regex::new(regex_pattern.as_str()).expect("Regex should always compile"),
            )))
        } else if wildcard_seen {
            // If we saw a wildcard but didn't need to use a regex, then the wildcard was at the end
            Self::StartsWith(Box::new(s[..s.len() - 1].to_string()))
        } else {
            Self::Exact(Box::new(s.to_string()))
        }
    }
}
