use super::signature::canonicalize_uri_path;

#[test]
fn canonicalize_uri_path_empty() {
    assert_eq!(canonicalize_uri_path(&"").expect("empty path should map to /"), "/".to_string());
    assert_eq!(canonicalize_uri_path(&"/").expect("/ should map to /"), "/".to_string());
}

#[test]
fn canonicalize_valid() {
    assert_eq!(canonicalize_uri_path(&"/hello/world").expect("should map to /hello/world"), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/./world").expect("/. should be elided"), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/foo/../world").expect("/.. should replace parent"), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/%77%6F%72%6C%64").expect("ASCII letters should be decoded"), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/w*rld").expect("RFC3986 reserved should be encoded"), "/hello/w%2Arld".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/w%2arld").expect("Percent-escapes should be uppercased"), "/hello/w%2Arld".to_string());
}
