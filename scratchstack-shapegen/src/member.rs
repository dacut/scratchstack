use {
    crate::{Enum, List, Shape, ShapeInfo, SmithyModel, TraitMap},
    serde::{Deserialize, Serialize},
    std::{
        cell::{Ref, RefCell},
        rc::Rc,
    },
};

/// An AST member definition defines a member of a shape. It is a special kind of AST shape
/// reference that also contains an optional traits property that defines traits attached to the
/// member. Each key in the traits property is the absolute shape ID of the trait to apply, and
/// each value is the value to assign to the trait.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    /// The shape of this member in the Smithy model.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub shape: Option<Rc<RefCell<Shape>>>,

    /// The target shape ID of the member.
    pub target: String,

    /// A map of absolute shape IDs to trait values.
    #[serde(skip_serializing_if = "TraitMap::is_empty", default)]
    pub traits: TraitMap,
}

impl ShapeInfo for Member {
    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        assert!(self.shape.is_none(), "member of {shape_name} targeting {} has already been resolved", self.target);

        let Some(shape) = model.shapes.get(&self.target) else {
            panic!("shape {shape_name} has a member targeting {}, which is not in the model", self.target);
        };
        self.shape = Some(shape.clone());
    }

    fn smithy_name(&self) -> String {
        self.inner().borrow().smithy_name()
    }

    fn rust_typename(&self) -> String {
        self.inner().borrow().rust_typename()
    }

    #[inline(always)]
    fn validator_fn_name(&self) -> Option<String> {
        self.inner().borrow().validator_fn_name()
    }
}

impl Member {
    /// Returns this as an enum member if it is an enum type; otherwise returns `None`.
    #[must_use]
    pub(crate) fn as_enum<'a>(&'a self) -> Option<Ref<'a, Enum>> {
        let borrowed = self.shape.as_ref()?.borrow();
        Ref::filter_map(borrowed, |s| match s {
            Shape::Enum(e) => Some(e),
            _ => None,
        })
        .ok()
    }

    /// Returns this as a list member if it is a list type; otherwise returns `None`.
    #[must_use]
    pub(crate) fn as_list<'a>(&'a self) -> Option<Ref<'a, List>> {
        let borrowed = self.shape.as_ref()?.borrow();
        Ref::filter_map(borrowed, |s| match s {
            Shape::List(l) => Some(l),
            _ => None,
        })
        .ok()
    }

    /// Returns the inner shape of this member.
    ///
    /// Panics if the member is not resolved.
    #[must_use]
    pub(crate) fn inner(&self) -> Rc<RefCell<Shape>> {
        self.shape.clone().unwrap_or_else(|| panic!("member targeting {} was not resolved", self.target))
    }

    /// Indicates whether this member is an enum.
    #[must_use]
    pub(crate) fn is_enum(&self) -> bool {
        self.as_enum().is_some()
    }

    /// Indicates whether the inner shape is a list type.
    #[must_use]
    pub(crate) fn is_list(&self) -> bool {
        self.as_list().is_some()
    }

    /// Indicates whether this member is a list of primitive members.
    #[must_use]
    pub(crate) fn is_list_of_primitives(&self) -> bool {
        let Some(list) = self.as_list() else {
            return false;
        };

        list.member.is_primitive()
    }

    /// Indicates whether this is a primitive member.
    #[must_use]
    pub(crate) fn is_primitive(&self) -> bool {
        self.inner().borrow().is_primitive()
    }

    /// Indicates whether this is a required member.
    #[must_use]
    pub(crate) fn is_required(&self) -> bool {
        self.traits.is_required()
    }
}
