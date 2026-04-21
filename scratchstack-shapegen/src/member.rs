use {
    super::{List, Shape, Typed},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        cell::{Ref, RefCell},
        collections::HashMap,
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
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Member {
    /// Returns the inner shape of this member; panics if the member is not resolved or if the inner shape is not a [`Typed`] shape.
    pub fn inner(&self) -> Rc<RefCell<Shape>> {
        self.shape.clone().expect("Member should be resolved before generating Rust code")
    }

    /// Indicates whether this is an optional member.
    pub fn is_optional(&self) -> bool {
        !self.traits.contains_key("smithy.api#required")
    }

    /// Indicates whether this member is a primitive type.
    pub fn is_primitive(&self) -> bool {
        self.inner().borrow().is_primitive()
    }

    /// Indicates whether this member is a list type.
    pub fn is_list(&self) -> bool {
        matches!(&*self.inner().borrow(), Shape::List(_))
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

    /// Returns the bare Rust type of this member without any wrappers like `Option`.
    pub fn bare_rust_type(&self) -> String {
        let shape = self.shape.as_ref().expect("Member should be resolved before generating Rust code");
        shape.borrow().rust_typename()
    }
}

impl Typed for Member {
    fn rust_typename(&self) -> String {
        self.bare_rust_type()
    }

    fn write(&self, _output: &mut dyn std::io::Write) -> std::io::Result<()> {
        // No declaration to write for members
        Ok(())
    }

    fn has_decl(&self, _model: &super::SmithyModel) -> bool {
        false
    }

    fn is_primitive(&self) -> bool {
        self.inner().borrow().is_primitive()
    }

    fn get_clap_parser(&self) -> String {
        self.shape.as_ref().expect("Member should be resolved before generating Rust code").borrow().get_clap_parser()
    }

    fn get_derive_builder_validator(&self, var: &str) -> Option<String> {
        self.shape
            .as_ref()
            .expect("Member should be resolved before generating Rust code")
            .borrow()
            .get_derive_builder_validator(var)
    }

    fn mark_reachable_from_input(&mut self) {
        if let Some(shape) = &self.shape {
            shape.borrow_mut().mark_reachable_from_input();
        }
    }
}
