//! Model transformations applied between parsing and resolution.
//!
//! Published AWS models need patching before they can be generated from: some carry regular
//! expressions the `regex` crate cannot compile, some carry documentation with HTML that rustdoc
//! rejects, and a service may need structures the model does not declare. Every transform here is
//! phrased in terms of Smithy concepts alone -- shapes, members, traits -- so the code generator
//! never learns about any particular service's conventions. Whatever a transform produces is an
//! ordinary shape, indistinguishable from one that was in the model file to begin with.

use {
    crate::{LengthConstraint, Member, Shape, SmithyModel, Structure, TraitMap},
    std::{
        cell::RefCell,
        collections::BTreeSet,
        io::{Error as IoError, Result as IoResult},
        rc::Rc,
    },
};

/// A member to add to each structure produced by a [`DerivedStructs`] rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedMember {
    /// Documentation for the member, used as its doc comment.
    pub documentation: String,

    /// The member name, as it appears on the wire and in the Smithy model.
    pub name: String,

    /// Whether the member is required.
    pub required: bool,

    /// The shape id the member targets.
    pub target: String,
}

/// A rule for deriving additional structures from the input shapes of a model's operations.
///
/// For each operation in the configured namespace, the operation's input structure is cloned under
/// a new name -- the operation's simple name plus [`suffix`][Self::suffix] -- and the configured
/// members are added to it. The clone keeps the original's traits, so a derived structure carries
/// the same `smithy.api#input` marker and is generated into the same module as its source.
///
/// The result is a plain structure shape. Nothing downstream of this transform can tell it was
/// derived rather than declared, which is the point: `scratchstack-shapes-iam` uses it to add an
/// `account_id` to each request so its service implementation can address any account, and the
/// generator has no notion of what an "internal request" is.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DerivedStructs {
    /// Simple operation names to skip.
    pub exclude: BTreeSet<String>,

    /// Members to add to each derived structure.
    pub members: Vec<DerivedMember>,

    /// Appended to the operation's simple name to name the derived structure.
    pub suffix: String,
}

/// A documentation rewrite applied to the members of specific shapes.
///
/// Used to repair prose that rustdoc will not accept -- most often angle-bracketed placeholders
/// such as `<role-name>`, which rustdoc reads as an HTML tag.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DocRewrite {
    /// Literal `(from, to)` replacements, applied in order to each member's documentation.
    pub replacements: Vec<(String, String)>,

    /// The shape ids whose members are rewritten.
    pub shape_ids: Vec<String>,
}

/// A replacement for a regular expression the `regex` crate cannot compile.
///
/// The `regex` crate has no lookaround support, so a pattern relying on it has to be replaced with
/// one that is merely permissive, usually paired with a length constraint that recovers part of
/// what the original expressed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternRewrite {
    /// The pattern to match, compared literally against each shape's `smithy.api#pattern`.
    pub from: String,

    /// A length constraint to set alongside the replacement, if any.
    pub length: Option<LengthConstraint>,

    /// The replacement pattern.
    pub to: String,
}

impl DerivedMember {
    /// Creates a required derived member.
    #[must_use]
    pub fn new(name: impl Into<String>, target: impl Into<String>, documentation: impl Into<String>) -> Self {
        Self {
            documentation: documentation.into(),
            name: name.into(),
            required: true,
            target: target.into(),
        }
    }

    /// Marks the member optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }
}

impl DerivedStructs {
    /// Creates a rule naming derived structures with the given suffix.
    #[must_use]
    pub fn new(suffix: impl Into<String>) -> Self {
        Self {
            exclude: BTreeSet::new(),
            members: Vec::new(),
            suffix: suffix.into(),
        }
    }

    /// Adds a member to every derived structure.
    #[must_use]
    pub fn with_member(mut self, member: DerivedMember) -> Self {
        self.members.push(member);
        self
    }

    /// Excludes operations by simple name.
    #[must_use]
    pub fn excluding<S: AsRef<str>>(mut self, names: impl IntoIterator<Item = S>) -> Self {
        self.exclude.extend(names.into_iter().map(|n| n.as_ref().to_string()));
        self
    }

    /// Applies this rule to every operation in `namespace`.
    ///
    /// # Panics
    ///
    /// Panics if an operation names an input shape that is missing from the model or that is not a
    /// structure. Either means the model is inconsistent, which no caller can recover from.
    pub fn apply(&self, model: &mut SmithyModel, namespace: &str) {
        let prefix = format!("{namespace}#");
        let mut derived = Vec::new();

        for (shape_id, shape) in &model.shapes {
            let Shape::Operation(operation) = &*shape.borrow() else {
                continue;
            };

            let Some(simple_name) = shape_id.strip_prefix(&prefix) else {
                continue;
            };

            if self.exclude.contains(simple_name) {
                continue;
            }

            let input_id = operation.input.target.as_str();
            let input_shape = model.get_shape(input_id).unwrap_or_else(|| {
                panic!("operation {shape_id} names input shape {input_id}, which is not in the model")
            });
            let input = input_shape.borrow();
            let Shape::Structure(input_structure) = &*input else {
                panic!("operation {shape_id} names input shape {input_id}, which is not a structure")
            };

            derived.push((format!("{prefix}{simple_name}{}", self.suffix), self.derive(input_structure)));
        }

        for (shape_id, structure) in derived {
            model.shapes.insert(shape_id, Rc::new(RefCell::new(Shape::Structure(structure))));
        }
    }

    /// Clones `source` and adds this rule's members to the clone.
    fn derive(&self, source: &Structure) -> Structure {
        let mut derived = source.clone();

        for member in &self.members {
            let mut traits = TraitMap::new();
            traits.set_required(member.required);
            traits.set_documentation(member.documentation.clone());

            derived.members.insert(
                member.name.clone(),
                Member {
                    shape: None,
                    target: member.target.clone(),
                    traits,
                },
            );
        }

        derived
    }
}

impl DocRewrite {
    /// Creates a rewrite over the given shape ids.
    #[must_use]
    pub fn new<S: AsRef<str>>(shape_ids: impl IntoIterator<Item = S>) -> Self {
        Self {
            replacements: Vec::new(),
            shape_ids: shape_ids.into_iter().map(|id| id.as_ref().to_string()).collect(),
        }
    }

    /// Adds a literal replacement.
    #[must_use]
    pub fn replacing(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.replacements.push((from.into(), to.into()));
        self
    }

    /// Applies this rewrite to the members of each named shape.
    ///
    /// # Panics
    ///
    /// Panics if a named shape is absent from the model or has no members -- a rewrite that names a
    /// shape which is not there is a stale configuration, and silently ignoring it would let the
    /// broken documentation back in unnoticed.
    pub fn apply(&self, model: &mut SmithyModel) {
        for shape_id in &self.shape_ids {
            let shape = model
                .shapes
                .get(shape_id)
                .unwrap_or_else(|| panic!("documentation rewrite names shape {shape_id}, which is not in the model"));
            let mut shape = shape.borrow_mut();
            let members = shape
                .members_mut()
                .unwrap_or_else(|| panic!("documentation rewrite names shape {shape_id}, which has no members"));

            for member in members.values_mut() {
                let Some(documentation) = member.traits.documentation() else {
                    continue;
                };

                let mut rewritten = documentation.to_string();
                for (from, to) in &self.replacements {
                    rewritten = rewritten.replace(from, to);
                }
                member.traits.set_documentation(rewritten);
            }
        }
    }
}

impl PatternRewrite {
    /// Creates a pattern rewrite.
    #[must_use]
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            length: None,
            to: to.into(),
        }
    }

    /// Sets a length constraint to apply alongside the replacement.
    #[must_use]
    pub fn with_length(mut self, length: LengthConstraint) -> Self {
        self.length = Some(length);
        self
    }

    /// Replaces every occurrence of this pattern across the model.
    pub fn apply(&self, model: &mut SmithyModel) {
        for shape in model.shapes.values_mut() {
            let mut shape = shape.borrow_mut();
            let traits = shape.traits_mut();

            if traits.pattern() != Some(self.from.as_str()) {
                continue;
            }

            traits.set_pattern(&self.to);
            if let Some(length) = self.length {
                traits.set_length_constraint(length);
            }
        }
    }
}

/// Merges every shape from `extension` into `model`, replacing any shape with the same id.
///
/// # Errors
///
/// Returns an error if the extension contributes no shapes. An empty extension is always a mistake
/// -- a wrong path, or a file that lost its contents -- and it would otherwise be invisible until
/// something downstream failed to compile.
pub fn merge_extension(model: &mut SmithyModel, extension: SmithyModel, source: &str) -> IoResult<()> {
    if extension.shapes.is_empty() {
        return Err(IoError::other(format!("extension model {source} contributes no shapes")));
    }

    for (shape_id, shape) in extension.shapes {
        model.shapes.insert(shape_id, shape);
    }

    Ok(())
}
