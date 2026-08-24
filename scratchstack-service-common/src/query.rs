//! Helpers for the AWS query protocol shared by every service's request dispatcher.
//!
//! A service's dispatcher joins the query string and request body into a single parameter list,
//! reads the `Action` and `Version` parameters that select the operation, and then hands the
//! still-encoded parameter list to the operation, which deserializes it into the operation's own
//! request type. The joining and scanning steps do not vary between services and live here.

use {
    crate::constants::{NO_ACTION_SPECIFIED, NO_VERSION_SPECIFIED, QP_ACTION, QP_VERSION},
    std::borrow::Cow,
};

/// Join the query string and request body into a single parameter list.
///
/// The AWS query protocol carries parameters in the query string, in the body, or split across
/// both; SigV4 signs both, so they are joined into a single parameter list. Body parameters are
/// appended last so they win if a parameter appears in both places. The parameters are left
/// url-encoded here; each operation deserializes them into its own request type.
pub fn join_parameters<'a>(query: &'a str, body: &'a str) -> Cow<'a, str> {
    match (query, body) {
        ("", body) => Cow::Borrowed(body),
        (query, "") => Cow::Borrowed(query),
        (query, body) => Cow::Owned(format!("{query}&{body}")),
    }
}

/// Scan a joined parameter list for the `Action` and `Version` parameters, returning them in that
/// order.
///
/// A request that omits either parameter yields [`NO_ACTION_SPECIFIED`] or
/// [`NO_VERSION_SPECIFIED`] in its place, so the caller can name the missing value in the error
/// response it returns. As elsewhere in the protocol, the last occurrence of a repeated parameter
/// wins.
pub fn scan_action_version(parameters: &str) -> (Cow<'_, str>, Cow<'_, str>) {
    let mut action: Cow<'_, str> = Cow::Borrowed(NO_ACTION_SPECIFIED);
    let mut version: Cow<'_, str> = Cow::Borrowed(NO_VERSION_SPECIFIED);

    for (key, value) in form_urlencoded::parse(parameters.as_bytes()) {
        match key.as_ref() {
            QP_ACTION => action = value,
            QP_VERSION => version = value,
            _ => (),
        }
    }

    (action, version)
}

#[cfg(test)]
mod tests {
    use {
        super::{join_parameters, scan_action_version},
        crate::constants::{NO_ACTION_SPECIFIED, NO_VERSION_SPECIFIED},
        pretty_assertions::assert_eq,
        std::borrow::Cow,
    };

    #[test]
    fn join_borrows_when_only_one_side_is_present() {
        assert_eq!(join_parameters("", "Action=ListUsers"), Cow::Borrowed("Action=ListUsers"));
        assert_eq!(join_parameters("Action=ListUsers", ""), Cow::Borrowed("Action=ListUsers"));
        assert_eq!(join_parameters("", ""), Cow::Borrowed(""));
    }

    #[test]
    fn join_concatenates_query_then_body() {
        assert_eq!(join_parameters("Action=ListUsers", "Version=2010-05-08"), "Action=ListUsers&Version=2010-05-08");
    }

    /// Body parameters are appended last, and the protocol takes the last occurrence of a
    /// repeated parameter, so a parameter present in both places resolves to the body's value.
    #[test]
    fn body_parameters_override_query_parameters() {
        let parameters = join_parameters("Action=FromQuery", "Action=FromBody");
        let (action, _) = scan_action_version(&parameters);
        assert_eq!(action, "FromBody");
    }

    #[test]
    fn scan_finds_action_and_version_in_any_order() {
        let (action, version) = scan_action_version("Version=2010-05-08&Foo=bar&Action=ListUsers");
        assert_eq!(action, "ListUsers");
        assert_eq!(version, "2010-05-08");
    }

    #[test]
    fn scan_reports_placeholders_for_missing_parameters() {
        let (action, version) = scan_action_version("Foo=bar");
        assert_eq!(action, NO_ACTION_SPECIFIED);
        assert_eq!(version, NO_VERSION_SPECIFIED);

        let (action, version) = scan_action_version("Action=ListUsers");
        assert_eq!(action, "ListUsers");
        assert_eq!(version, NO_VERSION_SPECIFIED);
    }

    #[test]
    fn scan_percent_decodes_values() {
        let (action, _) = scan_action_version("Action=List%2BUsers");
        assert_eq!(action, "List+Users");
    }
}
