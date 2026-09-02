//! Policy for which shapes get CLI shorthand parsers.

use serde::{Deserialize, Serialize};

/// Which shapes get the `#[cfg(feature = "clap")]` shorthand parsers.
///
/// AWS CLI shorthand -- `Key=k,Value=v` -- is how a command line supplies a *nested value* to a
/// flag, so the shapes that need a parser are the value types: tags, filters, and the like. An
/// operation's request structure is assembled from individual flags, never handed over as one
/// shorthand string, so parsers for those are dead weight. For the IAM model that is not a small
/// amount of weight: 858 of the 1,041 generated clap-gated impls are on request structures, and
/// they account for most of a fifth of the crate's LLVM output.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum CliShorthand {
    /// Every eligible shape, including operation request structures.
    All,

    /// No shapes at all.
    None,

    /// Value types only -- structures and enums in `crate::types`, but not operation request or
    /// response structures. This is the default.
    #[default]
    ValueTypes,
}

impl CliShorthand {
    /// Whether operation request structures get a parser.
    #[must_use]
    pub fn includes_operation_inputs(self) -> bool {
        matches!(self, Self::All)
    }

    /// Whether plain value types get a parser.
    #[must_use]
    pub fn includes_value_types(self) -> bool {
        matches!(self, Self::All | Self::ValueTypes)
    }
}
