use {
    crate::PrincipalError,
    std::fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Details about an S3 canonical user.
pub struct CanonicalUser {
    /// The canonical user id.
    canonical_user_id: String,
}

impl CanonicalUser {
    /// Create a [CanonicalUser] object.
    ///
    /// # Arguments
    ///
    /// * `canonical_user_id`: The canonical user id. This must be a 64 character hex string in lower-case form.
    ///
    /// If all of the requirements are met, a [CanonicalUser] object is returned.  Otherwise, a [PrincipalError]
    /// error is returned.
    pub fn new(canonical_user_id: &str) -> Result<Self, PrincipalError> {
        if canonical_user_id.len() != 64 {
            return Err(PrincipalError::InvalidCanonicalUserId(canonical_user_id.to_string()));
        }

        for c in canonical_user_id.bytes() {
            if !matches!(c, b'0'..=b'9' | b'a'..=b'f') {
                return Err(PrincipalError::InvalidCanonicalUserId(canonical_user_id.to_string()));
            }
        }

        Ok(Self {
            canonical_user_id: canonical_user_id.into(),
        })
    }

    #[inline]
    pub fn canonical_user_id(&self) -> &str {
        &self.canonical_user_id
    }
}

impl Display for CanonicalUser {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.canonical_user_id())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::CanonicalUser,
        crate::{Principal, PrincipalSource},
        std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        },
    };

    #[test]
    fn check_components() {
        let cu1a = CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap();
        assert_eq!(cu1a.canonical_user_id(), "9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d");

        let p = Principal::from(cu1a);
        let source = p.source();
        assert_eq!(source, PrincipalSource::CanonicalUser);
        assert_eq!(source.to_string(), "CanonicalUser".to_string());
    }

    #[test]
    fn check_derived() {
        let cu1a = CanonicalUser::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let cu1b = CanonicalUser::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let cu2 = CanonicalUser::new("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let cu3 = CanonicalUser::new("0000000000000000000000000000000000000000000000000000000000000002").unwrap();

        assert_eq!(cu1a, cu1b);
        assert_ne!(cu1a, cu2);
        assert_eq!(cu1a.clone(), cu1a);

        // Ensure we can hash a canonical user.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        cu1a.hash(&mut h1a);
        cu1b.hash(&mut h1b);
        cu2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure ordering is logical.
        assert!(cu1a <= cu1b);
        assert!(cu1a < cu2);
        assert!(cu2 > cu1a);
        assert!(cu2 < cu3);
        assert!(cu3 > cu2);
        assert!(cu3 > cu1a);

        assert_eq!(cu1a.clone().max(cu2.clone()), cu2);
        assert_eq!(cu1a.clone().min(cu2), cu1a);

        // Ensure we can debug a canonical user.
        let _ = format!("{:?}", cu1a);
    }

    #[test]
    fn check_valid_canonical_user() {
        let cu1a = CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap();
        let cu1b = CanonicalUser::new("9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d").unwrap();
        let cu2 = CanonicalUser::new("772183b840c93fe103e45cd24ca8b8c94425a373465c6eb535b7c4b9593811e5").unwrap();

        assert_eq!(cu1a, cu1b);
        assert_eq!(cu1a, cu1a.clone());
        assert_ne!(cu1a, cu2);

        assert_eq!(cu1a.to_string(), "9da4bcba2132ad952bba3c8ecb37e668d99b310ce313da30c98aba4cdf009a7d");
        assert_eq!(cu2.to_string(), "772183b840c93fe103e45cd24ca8b8c94425a373465c6eb535b7c4b9593811e5");
    }

    #[test]
    fn check_invalid_canonical_users() {
        let err = CanonicalUser::new("123456789012345678901234567890123456789012345678901234567890123").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid canonical user id: "123456789012345678901234567890123456789012345678901234567890123""#
        );

        let err = CanonicalUser::new("12345678901234567890123456789012345678901234567890123456789012345").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid canonical user id: "12345678901234567890123456789012345678901234567890123456789012345""#
        );

        let err = CanonicalUser::new("123456789012345678901234567890123456789012345678901234567890AAAA").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"Invalid canonical user id: "123456789012345678901234567890123456789012345678901234567890AAAA""#
        );
    }
}
