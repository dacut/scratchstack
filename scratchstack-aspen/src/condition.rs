use {
    crate::serutil::StringList,
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ConditionOp {
    ArnEquals,
    ArnEqualsIfExists,
    ArnLike,
    ArnLikeIfExists,
    ArnNotEquals,
    ArnNotEqualsIfExists,
    ArnNotLike,
    ArnNotLikeIfExists,
    BinaryEquals,
    BinaryEqualsIfExists,
    Bool,
    BoolIfExists,
    DateEquals,
    DateEqualsIfExists,
    DateGreaterThan,
    DateGreaterThanEquals,
    DateGreaterThanEqualsIfExists,
    DateGreaterThanIfExists,
    DateLessThan,
    DateLessThanEquals,
    DateLessThanEqualsIfExists,
    DateLessThanIfExists,
    DateNotEquals,
    DateNotEqualsIfExists,
    IpAddress,
    IpAddressIfExists,
    NotIpAddress,
    NotIpAddressIfExists,
    Null,
    NumericEquals,
    NumericEqualsIfExists,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    NumericGreaterThanEqualsIfExists,
    NumericGreaterThanIfExists,
    NumericLessThan,
    NumericLessThanEquals,
    NumericLessThanEqualsIfExists,
    NumericLessThanIfExists,
    NumericNotEquals,
    NumericNotEqualsIfExists,
    StringEquals,
    StringEqualsIfExists,
    StringEqualsIgnoreCase,
    StringEqualsIgnoreCaseIfExists,
    StringLike,
    StringLikeIfExists,
    StringNotEquals,
    StringNotEqualsIfExists,
    StringNotEqualsIgnoreCase,
    StringNotEqualsIgnoreCaseIfExists,
    StringNotLike,
    StringNotLikeIfExists,
}

impl Display for ConditionOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Debug::fmt(self, f)
    }
}

pub type ConditionMap = BTreeMap<String, StringList>;
pub type Condition = BTreeMap<ConditionOp, ConditionMap>;

#[cfg(test)]
mod tests {
    use {
        crate::ConditionOp::*,
        std::{cmp::Ordering, collections::HashMap},
    };

    #[test_log::test]
    #[allow(clippy::comparison_chain)]
    fn test_ordering() {
        let sorted_order = vec![
            ArnEquals,
            ArnEqualsIfExists,
            ArnLike,
            ArnLikeIfExists,
            ArnNotEquals,
            ArnNotEqualsIfExists,
            ArnNotLike,
            ArnNotLikeIfExists,
            BinaryEquals,
            BinaryEqualsIfExists,
            Bool,
            BoolIfExists,
            DateEquals,
            DateEqualsIfExists,
            DateGreaterThan,
            DateGreaterThanEquals,
            DateGreaterThanEqualsIfExists,
            DateGreaterThanIfExists,
            DateLessThan,
            DateLessThanEquals,
            DateLessThanEqualsIfExists,
            DateLessThanIfExists,
            DateNotEquals,
            DateNotEqualsIfExists,
            IpAddress,
            IpAddressIfExists,
            NotIpAddress,
            NotIpAddressIfExists,
            Null,
            NumericEquals,
            NumericEqualsIfExists,
            NumericGreaterThan,
            NumericGreaterThanEquals,
            NumericGreaterThanEqualsIfExists,
            NumericGreaterThanIfExists,
            NumericLessThan,
            NumericLessThanEquals,
            NumericLessThanEqualsIfExists,
            NumericLessThanIfExists,
            NumericNotEquals,
            NumericNotEqualsIfExists,
            StringEquals,
            StringEqualsIfExists,
            StringEqualsIgnoreCase,
            StringEqualsIgnoreCaseIfExists,
            StringLike,
            StringLikeIfExists,
            StringNotEquals,
            StringNotEqualsIfExists,
            StringNotEqualsIgnoreCase,
            StringNotEqualsIgnoreCaseIfExists,
            StringNotLike,
            StringNotLikeIfExists,
        ];

        let mut map = HashMap::new();
        for (i, el) in sorted_order.iter().enumerate() {
            map.insert(el, i);
        }

        for (el, i) in map.iter() {
            assert_eq!(**el, sorted_order[*i]);
            let _ = format!("{:?}", el);
        }

        for i in 0..sorted_order.len() {
            for j in 0..sorted_order.len() {
                let ordering = sorted_order[i].partial_cmp(&sorted_order[j]).unwrap();

                if i == j {
                    assert_eq!(ordering, Ordering::Equal);
                    assert!(sorted_order[i].eq(&sorted_order[j]));
                    assert!(sorted_order[i].le(&sorted_order[j]));
                    assert!(sorted_order[i].ge(&sorted_order[j]));
                } else if i < j {
                    assert_eq!(ordering, Ordering::Less);
                    assert!(sorted_order[i].ne(&sorted_order[j]));
                    assert!(sorted_order[i].lt(&sorted_order[j]));
                    assert!(sorted_order[i].le(&sorted_order[j]));
                } else {
                    assert_eq!(ordering, Ordering::Greater);
                    assert!(sorted_order[i].ne(&sorted_order[j]));
                    assert!(sorted_order[i].gt(&sorted_order[j]));
                    assert!(sorted_order[i].ge(&sorted_order[j]));
                }
            }
        }
    }

    #[test_log::test]
    fn test_display() {
        let items = vec![
            (ArnEquals, "ArnEquals"),
            (ArnEqualsIfExists, "ArnEqualsIfExists"),
            (ArnLike, "ArnLike"),
            (ArnLikeIfExists, "ArnLikeIfExists"),
            (ArnNotEquals, "ArnNotEquals"),
            (ArnNotEqualsIfExists, "ArnNotEqualsIfExists"),
            (ArnNotLike, "ArnNotLike"),
            (ArnNotLikeIfExists, "ArnNotLikeIfExists"),
            (BinaryEquals, "BinaryEquals"),
            (BinaryEqualsIfExists, "BinaryEqualsIfExists"),
            (Bool, "Bool"),
            (BoolIfExists, "BoolIfExists"),
            (DateEquals, "DateEquals"),
            (DateEqualsIfExists, "DateEqualsIfExists"),
            (DateGreaterThan, "DateGreaterThan"),
            (DateGreaterThanEquals, "DateGreaterThanEquals"),
            (DateGreaterThanEqualsIfExists, "DateGreaterThanEqualsIfExists"),
            (DateGreaterThanIfExists, "DateGreaterThanIfExists"),
            (DateLessThan, "DateLessThan"),
            (DateLessThanEquals, "DateLessThanEquals"),
            (DateLessThanEqualsIfExists, "DateLessThanEqualsIfExists"),
            (DateLessThanIfExists, "DateLessThanIfExists"),
            (DateNotEquals, "DateNotEquals"),
            (DateNotEqualsIfExists, "DateNotEqualsIfExists"),
            (IpAddress, "IpAddress"),
            (IpAddressIfExists, "IpAddressIfExists"),
            (NotIpAddress, "NotIpAddress"),
            (NotIpAddressIfExists, "NotIpAddressIfExists"),
            (Null, "Null"),
            (NumericEquals, "NumericEquals"),
            (NumericEqualsIfExists, "NumericEqualsIfExists"),
            (NumericGreaterThan, "NumericGreaterThan"),
            (NumericGreaterThanEquals, "NumericGreaterThanEquals"),
            (NumericGreaterThanEqualsIfExists, "NumericGreaterThanEqualsIfExists"),
            (NumericGreaterThanIfExists, "NumericGreaterThanIfExists"),
            (NumericLessThan, "NumericLessThan"),
            (NumericLessThanEquals, "NumericLessThanEquals"),
            (NumericLessThanEqualsIfExists, "NumericLessThanEqualsIfExists"),
            (NumericLessThanIfExists, "NumericLessThanIfExists"),
            (NumericNotEquals, "NumericNotEquals"),
            (NumericNotEqualsIfExists, "NumericNotEqualsIfExists"),
            (StringEquals, "StringEquals"),
            (StringEqualsIfExists, "StringEqualsIfExists"),
            (StringEqualsIgnoreCase, "StringEqualsIgnoreCase"),
            (StringEqualsIgnoreCaseIfExists, "StringEqualsIgnoreCaseIfExists"),
            (StringLike, "StringLike"),
            (StringLikeIfExists, "StringLikeIfExists"),
            (StringNotEquals, "StringNotEquals"),
            (StringNotEqualsIfExists, "StringNotEqualsIfExists"),
            (StringNotEqualsIgnoreCase, "StringNotEqualsIgnoreCase"),
            (StringNotEqualsIgnoreCaseIfExists, "StringNotEqualsIgnoreCaseIfExists"),
            (StringNotLike, "StringNotLike"),
            (StringNotLikeIfExists, "StringNotLikeIfExists"),
        ];

        for (item, expected) in items {
            assert_eq!(format!("{}", item), expected);
        }
    }
}
