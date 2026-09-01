use {
    super::setop::{OperatorNames, display_names},
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
};

/// Null operation names.
///
/// `Null` has no variants of its own -- it asks whether the key is present, which neither
/// `IfExists` nor negation has anything to add to -- so it is a single operator rather than a
/// family of them.
pub(super) const NULL_DISPLAY_NAMES: OperatorNames = display_names!["Null"];

/// Indicates whether the presence of a condition key is what the policy asks for.
///
/// `Null` does not compare the value a key holds; it asks whether the key is there at all. The
/// policy lists `"true"` to require that the key be absent and `"false"` to require that it be
/// present -- the reverse of most operators, where the listed value is the one that matches.
///
/// Entries that spell neither are ignored, so a clause listing nothing recognizable matches
/// nothing: there is no answer it could be asking for. Listing both matches either way, which is
/// a clause that constrains nothing rather than an error.
///
/// A key holding an empty list of values counts as absent, matching what a multivalued key with
/// nothing in it says: no more than an absent key does.
pub(super) fn null_match(
    context: &Context,
    pv: PolicyVersion,
    allowed: &StringLikeList<String>,
    value: &SessionValue,
) -> Result<bool, AspenError> {
    let mut allowed_bools = Vec::with_capacity(2);

    for el in allowed.iter() {
        let el = match pv {
            PolicyVersion::None | PolicyVersion::V2008_10_17 => el.clone(),
            PolicyVersion::V2012_10_17 => context.subst_vars_plain(el)?,
        };
        match el.as_str() {
            "true" => allowed_bools.push(true),
            "false" => allowed_bools.push(false),
            _ => (),
        }
    }

    let is_null = value.is_null();
    Ok(allowed_bools.contains(&is_null))
}

#[cfg(test)]
mod tests {
    use {
        crate::{Condition, Context, PolicyVersion},
        scratchstack_arn::Arn,
        scratchstack_aws_principal::{Principal, Service, SessionData, SessionValue},
        std::str::FromStr,
    };

    fn matches(policy_value: &str, session_data: &SessionData) -> bool {
        let condition = Condition::from_str(&format!(r#"{{"Null": {{"hello": {policy_value}}}}}"#)).unwrap();
        let context = Context::builder()
            .api("action")
            .actor(Principal::from(
                Service::builder().service_name("example").dns_suffix("amazonaws.com").build().unwrap(),
            ))
            .resources(vec![Arn::new("aws", "s3", "", "", "example").unwrap()])
            .session_data(session_data.clone())
            .service("service")
            .build()
            .unwrap();
        condition.matches(&context, PolicyVersion::V2012_10_17).unwrap()
    }

    /// `"true"` asks that the key be absent and `"false"` that it be present -- the opposite way
    /// round from every other operator, where the listed value is the one that matches.
    #[test_log::test]
    fn test_null_asks_about_presence() {
        let absent = SessionData::new();
        let mut present = SessionData::new();
        present.insert("hello", SessionValue::from("world"));

        assert!(matches(r#""true""#, &absent));
        assert!(!matches(r#""true""#, &present));

        assert!(!matches(r#""false""#, &absent));
        assert!(matches(r#""false""#, &present));

        // A key present but holding no values counts as absent: an empty multivalued key says no
        // more than a missing one.
        let mut empty_list = SessionData::new();
        empty_list.insert("hello", SessionValue::List(vec![]));
        assert!(matches(r#""true""#, &empty_list));
        assert!(!matches(r#""false""#, &empty_list));
    }

    /// Entries that spell neither `"true"` nor `"false"` are ignored rather than rejected, so a
    /// clause listing nothing recognizable matches nothing at all.
    #[test_log::test]
    fn test_null_ignores_values_that_are_not_booleans() {
        let absent = SessionData::new();
        let mut present = SessionData::new();
        present.insert("hello", SessionValue::from("world"));

        for value in [r#""yes""#, r#""TRUE""#, r#""1""#, r#""""#, "[]", r#"["yes", "no"]"#] {
            assert!(!matches(value, &absent), "{value} matched an absent key");
            assert!(!matches(value, &present), "{value} matched a present key");
        }

        // An unrecognized entry alongside a recognized one leaves the recognized one in force.
        assert!(matches(r#"["true", "yes"]"#, &absent));
        assert!(!matches(r#"["true", "yes"]"#, &present));

        // Listing both constrains nothing.
        assert!(matches(r#"["true", "false"]"#, &absent));
        assert!(matches(r#"["true", "false"]"#, &present));
    }
}
