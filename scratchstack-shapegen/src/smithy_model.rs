use {
    crate::{Shape, ShapeInfo as _, primitive::SmithyUnit},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        cell::RefCell,
        collections::BTreeMap,
        io::{Result as IoResult, Write},
        rc::Rc,
    },
};

/// Smithy service model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmithyModel {
    /// Defines the version of the Smithy specification (e.g., "2.0"). The version can be set to a
    /// single number like "2" or include a point release like "2.0".
    pub smithy: String,

    /// Defines all of the metadata about the model using a JSON object. Each key is the metadata
    /// key to set, and each value is the metadata value to assign to the key.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, Value>,

    /// A map of absolute shape IDs to shape definitions.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub shapes: BTreeMap<String, Rc<RefCell<Shape>>>,
}

impl SmithyModel {
    /// Adds default shapes to the model if they do not already exist.
    pub fn add_default_shapes(&mut self) {
        self.shapes.entry("smithy.api#Unit".to_string()).or_insert_with(|| {
            let unit = SmithyUnit::new("smithy.api#Unit");
            Rc::new(RefCell::new(Shape::Unit(unit)))
        });
    }

    /// Resolve all shapes in the model by calling `resolve` on each shape until all shapes are resolved.
    pub fn resolve(&self) {
        for (shape_name, shape) in &self.shapes {
            if shape_name.starts_with("smithy.api#") {
                continue;
            }

            let mut shape = shape.borrow_mut();
            shape.resolve(shape_name, self);
        }

        // Mark all input structures as reachable from the input.
        for shape in self.shapes.values() {
            let mut shape = shape.borrow_mut();
            if let Shape::Structure(s) = &mut *shape
                && s.base.traits.is_input()
            {
                s.mark_reachable_from_input();
            }
        }
    }

    //         let hash_pos = shape_name.find('#').expect("Shape ID should contain a '#' character");
    //         let simple_typename = &shape_name[hash_pos + 1..];
    //         let rust_typename = simple_typename.to_pascal_case();

    //         match &mut *shape {
    //             Shape::Unit(u) => {
    //                 assert!(u.smithy_typename.is_none());
    //                 assert!(u.rust_typename.is_none());
    //                 u.smithy_typename = Some(shape_name.clone());
    //                 u.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Blob(b) => {
    //                 assert!(b.smithy_typename.is_none());
    //                 assert!(b.rust_typename.is_none());
    //                 b.smithy_typename = Some(shape_name.clone());
    //                 b.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Boolean(b) => {
    //                 assert!(b.smithy_typename.is_none());
    //                 assert!(b.rust_typename.is_none());
    //                 b.smithy_typename = Some(shape_name.clone());
    //                 b.rust_typename = Some(rust_typename);
    //             }
    //             Shape::String(s) => {
    //                 assert!(s.smithy_typename.is_none());
    //                 assert!(s.rust_typename.is_none());
    //                 s.smithy_typename = Some(shape_name.clone());
    //                 s.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Byte(b) => {
    //                 assert!(b.smithy_typename.is_none());
    //                 assert!(b.rust_typename.is_none());
    //                 b.smithy_typename = Some(shape_name.clone());
    //                 b.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Short(s) => {
    //                 assert!(s.smithy_typename.is_none());
    //                 assert!(s.rust_typename.is_none());
    //                 s.smithy_typename = Some(shape_name.clone());
    //                 s.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Integer(i) => {
    //                 assert!(i.smithy_typename.is_none());
    //                 assert!(i.rust_typename.is_none());
    //                 i.smithy_typename = Some(shape_name.clone());
    //                 i.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Long(l) => {
    //                 assert!(l.smithy_typename.is_none());
    //                 assert!(l.rust_typename.is_none());
    //                 l.smithy_typename = Some(shape_name.clone());
    //                 l.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Float(f) => {
    //                 assert!(f.smithy_typename.is_none());
    //                 assert!(f.rust_typename.is_none());
    //                 f.smithy_typename = Some(shape_name.clone());
    //                 f.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Double(d) => {
    //                 assert!(d.smithy_typename.is_none());
    //                 assert!(d.rust_typename.is_none());
    //                 d.smithy_typename = Some(shape_name.clone());
    //                 d.rust_typename = Some(rust_typename);
    //             }
    //             Shape::BigInteger(b) => {
    //                 assert!(b.smithy_typename.is_none());
    //                 assert!(b.rust_typename.is_none());
    //                 b.smithy_typename = Some(shape_name.clone());
    //                 b.rust_typename = Some(rust_typename);
    //             }
    //             Shape::BigDecimal(b) => {
    //                 assert!(b.smithy_typename.is_none());
    //                 assert!(b.rust_typename.is_none());
    //                 b.smithy_typename = Some(shape_name.clone());
    //                 b.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Document(_) => {
    //                 unimplemented!("Document type is not supported yet");
    //             }
    //             Shape::Timestamp(t) => {
    //                 assert!(t.smithy_typename.is_none());
    //                 assert!(t.rust_typename.is_none());
    //                 t.smithy_typename = Some(shape_name.clone());
    //                 t.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Enum(e) => {
    //                 assert!(e.smithy_typename.is_none());
    //                 assert!(e.rust_typename.is_none());
    //                 e.smithy_typename = Some(shape_name.clone());
    //                 e.rust_typename = Some(rust_typename);
    //             }
    //             Shape::IntEnum(e) => {
    //                 assert!(e.smithy_typename.is_none());
    //                 assert!(e.rust_typename.is_none());
    //                 e.smithy_typename = Some(shape_name.clone());
    //                 e.rust_typename = Some(rust_typename);
    //             }
    //             Shape::List(l) => {
    //                 let member_shape =
    //                     self.shapes.get(&l.member.target).expect("List member should exist in model").clone();
    //                 l.member.shape = Some(member_shape);
    //             }
    //             Shape::Map(m) => {
    //                 let key_shape = self.shapes.get(&m.key.target).expect("Map key should exist in model").clone();
    //                 let value_shape =
    //                     self.shapes.get(&m.value.target).expect("Map value should exist in model").clone();
    //                 m.key.shape = Some(key_shape);
    //                 m.value.shape = Some(value_shape);
    //             }
    //             Shape::Structure(s) => {
    //                 assert!(s.smithy_typename.is_none());
    //                 assert!(s.rust_typename.is_none());
    //                 s.smithy_typename = Some(shape_name.clone());
    //                 s.rust_typename = Some(rust_typename);

    //                 for member in &mut s.members.values_mut() {
    //                     let member_shape =
    //                         self.shapes.get(&member.target).expect("Structure member should exist in model").clone();
    //                     member.shape = Some(member_shape);
    //                 }
    //             }
    //             Shape::Union(u) => {
    //                 assert!(u.smithy_typename.is_none());
    //                 assert!(u.rust_typename.is_none());
    //                 u.smithy_typename = Some(shape_name.clone());
    //                 u.rust_typename = Some(rust_typename);
    //             }
    //             Shape::Operation(o) => {
    //                 assert!(o.smithy_name.is_none());
    //                 assert!(o.rust_typename.is_none());
    //                 assert!(o.input_shape.is_none());
    //                 assert!(o.output_shape.is_none());
    //                 assert!(o.error_shapes.is_empty());

    //                 let Some(input_target) = self.shapes.get(&o.input.target) else {
    //                     panic!("Input shape {} should exist in model", o.input.target);
    //                 };
    //                 let Some(output_target) = self.shapes.get(&o.output.target) else {
    //                     panic!("Output shape {} should exist in model", o.output.target);
    //                 };

    //                 o.smithy_name = Some(shape_name.clone());
    //                 o.rust_typename = Some(rust_typename);
    //                 o.input_shape = Some(input_target.clone());
    //                 o.output_shape = Some(output_target.clone());
    //                 o.error_shapes = o
    //                     .errors
    //                     .iter()
    //                     .filter_map(|r| {
    //                         Some(self.shapes.get(&r.target).expect("Error shape should exist in model").clone())
    //                     })
    //                     .collect();
    //             }
    //             _ => {}
    //         }
    //     }

    // }

    /// Gets a shape by its shape ID.
    pub fn get_shape(&self, shape_id: &str) -> Option<Rc<RefCell<Shape>>> {
        self.shapes.get(shape_id).cloned()
    }

    /// Generates Rust code for the Smithy model.
    pub fn generate(&self, writer: &mut impl Write) -> IoResult<()> {
        for shape in self.shapes.values() {
            shape.borrow().generate(writer)?;
        }
        Ok(())
    }
}
