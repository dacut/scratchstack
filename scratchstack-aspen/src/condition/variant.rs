/// The variant on an operation.
///
/// The offsets used in the representation are used to index into the operation names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Variant {
    /// No variation on the basic operation.
    None = 0,

    /// IfExists variant.
    IfExists = 1,

    /// Negated: Equals => NotEquals, LessThan => GreaterThanEquals, etc.
    Negated = 2,

    /// IfExists and Negated.
    IfExistsNegated = 3,
}

impl Variant {
    /// Return the index into the operation names for this variant.
    #[inline]
    pub(super) fn as_usize(self) -> usize {
        self as usize
    }

    /// Indicates if this is [Variant::IfExists] or [Variant::IfExistsNegated].
    #[inline]
    pub(super) fn if_exists(self) -> bool {
        matches!(self, Self::IfExists | Self::IfExistsNegated)
    }

    /// Indicates if this is [Variant::Negated] or [Variant::IfExistsNegated].
    #[inline]
    pub(super) fn negated(self) -> bool {
        matches!(self, Self::Negated | Self::IfExistsNegated)
    }
}

impl From<u8> for Variant {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::IfExists,
            2 => Self::Negated,
            3 => Self::IfExistsNegated,
            _ => panic!("Invalid variant value: {}", value),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::Variant, pretty_assertions::assert_eq, std::panic::catch_unwind};

    #[test_log::test]
    fn test_clone() {
        assert_eq!(Variant::None.clone(), Variant::None);
        assert_eq!(Variant::IfExists.clone(), Variant::IfExists);
        assert_eq!(Variant::Negated.clone(), Variant::Negated);
        assert_eq!(Variant::IfExistsNegated.clone(), Variant::IfExistsNegated);
    }

    #[test_log::test]
    fn test_variant_values() {
        assert_eq!(Variant::None, Variant::from(0));
        assert_eq!(Variant::IfExists, Variant::from(1));
        assert_eq!(Variant::Negated, Variant::from(2));
        assert_eq!(Variant::IfExistsNegated, Variant::from(3));

        let e = catch_unwind(|| Variant::from(4)).unwrap_err();
        assert_eq!(e.downcast_ref::<String>().unwrap(), "Invalid variant value: 4");
    }
}
