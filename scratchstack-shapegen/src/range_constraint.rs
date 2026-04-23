/// A range constraint associated with a shape.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RangeConstraint {
    /// The lower bound, if any.
    pub min: Option<i64>,

    /// The upper bound, if any.
    pub max: Option<i64>,
}
