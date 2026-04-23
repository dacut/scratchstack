use {
    crate::{List, Shape, ShapeInfo, SmithyModel, TraitMap},
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
    fn resolve(&mut self, _: &str, model: &SmithyModel) {
        assert!(self.shape.is_none());

        let Some(shape) = model.shapes.get(&self.target) else {
            panic!("Member {} does not exist in SmithyModel", self.target);
        };
        self.shape = Some(shape.clone());
    }

    fn smithy_name(&self) -> String {
        self.shape.as_ref().expect("Member should be resolved before generating Rust code").borrow().smithy_name()
    }

    #[inline(always)]
    fn rust_typename(&self) -> String {
        self.inner().borrow().rust_typename()
    }

    #[inline(always)]
    fn clap_parser(&self) -> Option<String> {
        self.inner().borrow().clap_parser()
    }

    #[inline(always)]
    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        self.inner().borrow().derive_builder_validator(var, field_name)
    }

    fn mark_reachable_from_input(&mut self) {
        self.inner().borrow_mut().mark_reachable_from_input();
    }
}

impl Member {
    /// Returns the inner shape of this member.
    ///
    /// Panics if the member is not resolved.
    pub fn inner(&self) -> Rc<RefCell<Shape>> {
        self.shape.clone().expect("Member should be resolved before generating Rust code")
    }

    /// Indicates whether this is a required member.
    #[inline(always)]
    pub fn is_required(&self) -> bool {
        self.traits.is_required()
    }

    /// Indicates whether the inner shape is a list type.
    pub fn is_list(&self) -> bool {
        self.as_list().is_some()
    }

    /// Returns this as a list member if it is a list type; otherwise returns `None`.
    pub fn as_list<'a>(&'a self) -> Option<Ref<'a, List>> {
        let borrowed = self.shape.as_ref()?.borrow();
        if matches!(&*borrowed, Shape::List(_)) {
            Some(Ref::map(borrowed, |s| match s {
                Shape::List(l) => l,
                _ => unreachable!(),
            }))
        } else {
            None
        }
    }
}
