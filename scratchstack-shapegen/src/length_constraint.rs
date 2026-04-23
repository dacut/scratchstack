/// A length constraint associated with a shape.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LengthConstraint {
    /// The lower bound, if any.
    pub min: Option<usize>,

    /// The upper bound, if any.
    pub max: Option<usize>,
}

impl LengthConstraint {
    /// Creates a new `LengthConstraint` with the given min and max.
    pub fn new(min: Option<usize>, max: Option<usize>) -> Self {
        Self {
            min,
            max,
        }
    }
}
