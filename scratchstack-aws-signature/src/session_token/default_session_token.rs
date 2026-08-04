//! Default session token extractor implementation.
use {
    crate::{
        ExtractSessionToken, InternalFailureError, InvalidClientTokenIdError, SessionTokenData, SignatureError,
        constants::*, invalid_session_token_error,
    },
    aes_gcm::{AeadCore, AeadInOut as _, Aes256Gcm, KeyInit as _, KeySizeUser, Nonce, aead::common::Generate as _},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    log::error,
    std::{
        collections::HashMap,
        future::Future,
        marker::PhantomData,
        mem::take,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::Service,
    typenum::Unsigned,
    zeroize::Zeroizing,
};

/// The length of an AWS account id in characters/bytes.
pub const ACCOUNT_ID_LENGTH: usize = 12;

/// The current token version (ASCII `0`).
pub const CURRENT_TOKEN_VERSION: u8 = b'0';

/// The size of the nonce, as a hybrid array type.
pub type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;

/// The length of the nonce used for AES256-GCM encryption in bytes.
pub const NONCE_LENGTH: usize = NonceSize::USIZE;

/// The length of the keys used for AES256-GCM encryption in bytes.
pub const AES256_KEY_LENGTH: usize = <Aes256Gcm as KeySizeUser>::KeySize::USIZE;

/// The default Scratchstack implementation of the `ExtractSessionToken` trait that relies on the
/// [postcard] serialization format. This is enabled by the `default_session_token` feature.
///
/// The format of the session token used in this implementation is:
/// * Version: 1 byte, currently always ASCII `0`.
/// * Base64Payload: base-64 encoded string representing an [`EncryptedSessionTokenData`] struct.
#[derive(Clone)]
pub struct DefaultSessionTokenExtractor<KeyService> {
    /// An underlying Tower service that converts a `KeyId` into an AES256-GCM key for decrypting
    /// the session token data.
    key_service: KeyService,
}

/// The encrypted session token data.
///
/// This is parsed from the Base64Payload of the session token. After base64 decoding, the format
/// of the encrypted session token data is:
/// * KeyIdLength: u8
/// * KeyId: variable length, an ASCII string representing the KeyId of the signing key associated
///   with the session token.
/// * AccountId: 12 bytes, the 12-digit AWS account ID associated with the session token,
///   represented as an ASCII string.
/// * NonceLength: u8.
/// * Nonce: variable bytes, a random nonce used for encryption.
/// * EncryptionAlgorithm: 1 byte, an enum representing the encryption algorithm used; currently
///   always 0 forAES256-GCM.
/// * EncryptedPayloadLength: u32 in little-endian format
/// * EncryptedPayload: variable length encrypted data with associated authentication tag of
///   "AccountId=<i>account-id</i>". The underlying plaintext data is a postcard-serialized
///   `SessionTokenData` struct.
#[derive(Clone)]
pub struct EncryptedSessionTokenData {
    /// The KeyId of the signing key associated with the session token.
    key_id: String,

    /// The AWS account ID associated with the session token.
    account_id: String,

    /// The nonce used for encryption.
    nonce: Vec<u8>,

    /// The encrypted session token data. The associated authentication tag is
    /// "AccountId=<i>account-id</i>".
    encrypted_payload: Vec<u8>,
}

/// Session token encryption algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionTokenEncryptionAlgorithm {
    /// AES256-GCM, currently the only supported encryption algorithm for session tokens.
    Aes256Gcm = 0,
}

/// Information about a session token encryption key.
#[derive(Clone)]
pub struct SessionTokenEncryptionKeyInfo {
    /// The ID of the session token encryption key.
    pub session_token_encryption_key_id: String,

    /// The encryption algorithm used by the session token encryption key.
    pub encryption_algorithm: SessionTokenEncryptionAlgorithm,

    /// The key material for encrypting session tokens, formatted as raw bytes.
    pub encryption_key: Zeroizing<Vec<u8>>,
}

/// A static key service, primarily for testing.
#[derive(Clone)]
#[repr(transparent)]
pub struct StaticKeyService(pub HashMap<String, SessionTokenEncryptionKeyInfo>);

impl<KeyService> DefaultSessionTokenExtractor<KeyService> {
    /// Create a new `DefaultSessionTokenExtractor` with the given key service.
    pub fn new(key_service: KeyService) -> Self {
        Self {
            key_service,
        }
    }
}

impl<KeyService> DefaultSessionTokenExtractor<KeyService>
where
    KeyService:
        Service<String, Response = SessionTokenEncryptionKeyInfo, Error = SignatureError> + Clone + Send + 'static,
    KeyService::Future: Send,
{
    /// Extract the session token data from the given session token string.
    async fn extract(&mut self, session_token: &[u8]) -> Result<SessionTokenData, SignatureError> {
        let EncryptedSessionTokenData {
            key_id,
            account_id,
            nonce,
            encrypted_payload,
        } = EncryptedSessionTokenData::from_session_token(session_token)?;
        // After decryption, this buffer holds the plaintext token data -- including the raw
        // secret key -- so it must be zeroized on every exit path.
        let mut payload = Zeroizing::new(encrypted_payload);
        let key_info: SessionTokenEncryptionKeyInfo = self.key_service.call(key_id).await?;
        if key_info.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
            log::error!(
                "Unsupported encryption algorithm for session token encryption key {}: {:?}",
                key_info.session_token_encryption_key_id,
                key_info.encryption_algorithm,
            );
            return Err(InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build().into());
        }

        let nonce = Nonce::try_from(nonce.as_slice())
            .map_err(|_| InvalidClientTokenIdError::builder().message(ERR_MSG_INVALID_SESSION_TOKEN).build())?;
        let associated_data = format!("AccountId={account_id}");
        let cipher = Aes256Gcm::new_from_slice(key_info.encryption_key.as_slice()).map_err(|e| {
            log::error!(
                "Failed to create cipher for session token decryption with key {}: {e}",
                key_info.session_token_encryption_key_id,
            );
            InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build()
        })?;

        cipher
            .decrypt_in_place(&nonce, associated_data.as_bytes(), &mut *payload)
            .map_err(|_| invalid_session_token_error())?;

        let (result, remainder) =
            postcard::take_from_bytes(payload.as_slice()).map_err(|_| invalid_session_token_error())?;
        if !remainder.is_empty() {
            return Err(invalid_session_token_error());
        }

        Ok(result)
    }
}

impl<KeyService> Service<String> for DefaultSessionTokenExtractor<KeyService>
where
    KeyService:
        Service<String, Response = SessionTokenEncryptionKeyInfo, Error = SignatureError> + Clone + Send + 'static,
    KeyService::Future: Send,
{
    type Response = SessionTokenData;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.key_service.poll_ready(cx)
    }

    fn call(&mut self, session_token: String) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move { this.extract(session_token.as_bytes()).await })
    }
}

impl EncryptedSessionTokenData {
    /// Encrypt the given session token data with the given encryption key, producing the
    /// encrypted session token data. The account ID must be the 12-digit AWS account ID
    /// associated with the session, represented as an ASCII string; it is used as the
    /// associated authentication data for the encryption.
    pub fn encrypt(
        session_token_data: &SessionTokenData,
        key_info: &SessionTokenEncryptionKeyInfo,
        account_id: &str,
        request_id: Option<&str>,
    ) -> Result<Self, SignatureError> {
        let request_id = request_id.map(|s| s.into());
        Self::encrypt_inner(session_token_data, key_info, account_id, request_id)
    }

    fn encrypt_inner(
        session_token_data: &SessionTokenData,
        key_info: &SessionTokenEncryptionKeyInfo,
        account_id: &str,
        request_id: Option<String>,
    ) -> Result<Self, SignatureError> {
        if key_info.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
            log::error!(
                "Unsupported encryption algorithm for session token encryption key {}: {:?}",
                key_info.session_token_encryption_key_id,
                key_info.encryption_algorithm,
            );
            return Err(InternalFailureError::builder()
                .message(ERR_MSG_INTERNAL_SERVICE_ERROR)
                .maybe_request_id(request_id)
                .build()
                .into());
        }

        if account_id.len() != ACCOUNT_ID_LENGTH || !account_id.bytes().all(|b| b.is_ascii_digit()) {
            error!("Invalid account ID for session token: {account_id}");
            return Err(InternalFailureError::builder()
                .message(ERR_MSG_INTERNAL_SERVICE_ERROR)
                .maybe_request_id(request_id)
                .build()
                .into());
        }

        let cipher = match Aes256Gcm::new_from_slice(key_info.encryption_key.as_slice()) {
            Ok(cipher) => cipher,
            Err(e) => {
                log::error!(
                    "Failed to create cipher for session token encryption with key {}: {e}",
                    key_info.session_token_encryption_key_id,
                );
                return Err(InternalFailureError::builder().maybe_request_id(request_id).build().into());
            }
        };

        // Before encryption, this buffer holds the plaintext token data -- including the raw
        // secret key -- so it must be zeroized on every exit path. On success, the plaintext is
        // overwritten in place by the ciphertext.
        let mut payload = Zeroizing::new(match postcard::to_allocvec(session_token_data) {
            Ok(payload) => payload,
            Err(e) => {
                log::error!("Failed to serialize session token data: {e}");
                return Err(InternalFailureError::builder().maybe_request_id(request_id).build().into());
            }
        });

        let nonce = Nonce::<NonceSize>::generate_from_rng(&mut rand::rng());
        let associated_data = format!("AccountId={account_id}");

        cipher.encrypt_in_place(&nonce, associated_data.as_bytes(), &mut *payload).map_err(|e| {
            log::error!("Failed to encrypt session token data: {e}");
            InternalFailureError::builder().maybe_request_id(request_id).build()
        })?;

        Ok(Self {
            key_id: key_info.session_token_encryption_key_id.clone(),
            account_id: account_id.to_string(),
            nonce: nonce.to_vec(),
            encrypted_payload: take(&mut *payload),
        })
    }

    /// Parse the encrypted session token data from the given byte slice.
    fn parse_encrypted_session_token_data(session_token: &[u8]) -> Result<Self, SignatureError> {
        if session_token.is_empty() {
            return Err(invalid_session_token_error());
        }

        let key_id_length = session_token[0] as usize;
        let key_id_start = 1;
        let key_id_end = key_id_start + key_id_length;
        if key_id_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let key_id = String::from_utf8(session_token[key_id_start..key_id_end].to_vec())
            .map_err(|_| invalid_session_token_error())?;

        let account_id_start = key_id_end;
        let account_id_end = account_id_start + ACCOUNT_ID_LENGTH;
        if account_id_end > session_token.len() {
            return Err(invalid_session_token_error());
        }

        let account_id = &session_token[account_id_start..account_id_end];
        if !account_id.iter().all(|&b| b.is_ascii_digit()) {
            return Err(invalid_session_token_error());
        }
        let account_id = String::from_utf8(account_id.to_vec()).map_err(|_| invalid_session_token_error())?;

        let nonce_start = account_id_end;
        let nonce_end = nonce_start + NONCE_LENGTH;
        if nonce_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let nonce = session_token[nonce_start..nonce_end].to_vec();

        let encrypted_payload_length_start = nonce_end;
        let encrypted_payload_length_end = encrypted_payload_length_start + 4;
        if encrypted_payload_length_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let encrypted_payload_length = u32::from_le_bytes(
            session_token[encrypted_payload_length_start..encrypted_payload_length_end]
                .try_into()
                .map_err(|_| invalid_session_token_error())?,
        ) as usize;
        let encrypted_payload_start = encrypted_payload_length_end;
        let encrypted_payload_end = encrypted_payload_start + encrypted_payload_length;
        if encrypted_payload_end > session_token.len() {
            return Err(invalid_session_token_error());
        }
        let encrypted_payload = session_token[encrypted_payload_start..encrypted_payload_end].to_vec();

        Ok(Self {
            key_id,
            account_id,
            nonce,
            encrypted_payload,
        })
    }

    /// Parse a session token and return the parsed [`EncryptedSessionTokenData`].
    pub(crate) fn from_session_token(session_token: &[u8]) -> Result<Self, SignatureError> {
        if session_token.is_empty() || session_token.len() > MAX_SESSION_TOKEN_SIZE {
            return Err(invalid_session_token_error());
        }

        if session_token[0] != CURRENT_TOKEN_VERSION {
            return Err(invalid_session_token_error());
        }

        URL_SAFE_NO_PAD
            .decode(&session_token[1..])
            .map_err(|_| invalid_session_token_error())
            .and_then(|decoded| Self::parse_encrypted_session_token_data(&decoded))
    }

    /// Serialize this encrypted session token data into an opaque session token string.
    pub fn to_session_token(&self) -> Result<String, SignatureError> {
        let key_id_length = u8::try_from(self.key_id.len()).map_err(|_| {
            error!("Session token encryption key id is too long: {}", self.key_id);
            InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build()
        })?;
        let encrypted_payload_length = u32::try_from(self.encrypted_payload.len()).map_err(|_| {
            error!("Encrypted session token payload is too long");
            InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build()
        })?;

        let mut body = Vec::with_capacity(
            1 + self.key_id.len() + ACCOUNT_ID_LENGTH + self.nonce.len() + 4 + self.encrypted_payload.len(),
        );
        body.push(key_id_length);
        body.extend_from_slice(self.key_id.as_bytes());
        body.extend_from_slice(self.account_id.as_bytes());
        body.extend_from_slice(&self.nonce);
        body.extend_from_slice(&encrypted_payload_length.to_le_bytes());
        body.extend_from_slice(&self.encrypted_payload);

        let session_token = format!("{}{}", CURRENT_TOKEN_VERSION as char, URL_SAFE_NO_PAD.encode(body));
        if session_token.len() > MAX_SESSION_TOKEN_SIZE {
            error!("Encrypted session token payload is too long");
            return Err(InternalFailureError::builder().message(ERR_MSG_INTERNAL_SERVICE_ERROR).build().into());
        }

        Ok(session_token)
    }
}

impl Default for StaticKeyService {
    #[inline(always)]
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl StaticKeyService {
    /// Creates an empty `StaticKeyService`.
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty `StaticKeyService` with at least the specified capacity.
    #[inline(always)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }
}

impl Service<String> for StaticKeyService {
    type Response = SessionTokenEncryptionKeyInfo;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, key_id: String) -> Self::Future {
        let key = self.0.get(&key_id).cloned();
        Box::pin(async move {
            key.ok_or_else(|| {
                InvalidClientTokenIdError::builder()
                    .message(format!("KeyId {key_id} not found in StaticKeyService"))
                    .build()
                    .into()
            })
        })
    }
}

// Compile-time checks that `DefaultSessionTokenExtractor` satisfies the bounds the rest of the
// framework expects: the `Service` associated types (asserted individually so a mismatch produces
// a plain type error naming the offending type), a `Send` future, and `ExtractSessionToken`.
const _: () = {
    fn assert_extract_session_token<T: ExtractSessionToken>() {}
    fn assert_send<T: Send>() {}

    fn assoc<S: Service<R>, R>() -> (PhantomData<S::Response>, PhantomData<S::Error>) {
        (PhantomData, PhantomData)
    }

    #[allow(dead_code)]
    fn check<K>()
    where
        K: Service<String, Response = SessionTokenEncryptionKeyInfo, Error = SignatureError> + Clone + Send + 'static,
        K::Future: Send,
    {
        let (response, error) = assoc::<DefaultSessionTokenExtractor<K>, String>();
        let _: PhantomData<SessionTokenData> = response;
        let _: PhantomData<SignatureError> = error;
        assert_send::<<DefaultSessionTokenExtractor<K> as Service<String>>::Future>();
        assert_extract_session_token::<DefaultSessionTokenExtractor<K>>();
    }
};

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::KSecretKey,
        aes_gcm::Key as AesKey,
        ascii_casing::AsciiString,
        chrono::{DateTime, Duration},
        scratchstack_aspen::Policy as AspenPolicy,
        scratchstack_aws_principal::{AssumedRole, SessionData, SessionValue},
        scratchstack_core::error::ProvideErrorMetadata as _,
        std::{
            collections::{HashMap, HashSet},
            str::FromStr as _,
        },
        tower::ServiceExt as _,
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";
    const TEST_KEY: [u8; AES256_KEY_LENGTH] = [0x42; AES256_KEY_LENGTH];
    const TEST_KEY_ID: &str = "test-key-1";
    const TEST_NONCE: [u8; NONCE_LENGTH] = [0x07; NONCE_LENGTH];

    /// Asserts that `result` is an `InvalidSessionToken` error carrying `expected_message`.
    fn assert_invalid_session_token<T>(result: Result<T, SignatureError>, expected_message: &str) {
        match result {
            Err(SignatureError::InvalidClientTokenId(err)) => {
                assert_eq!(err.message().as_deref(), Some(expected_message))
            }
            _ => panic!("expected Err(SignatureError::InvalidSessionToken), got Ok()"),
        }
    }

    /// Assembles the binary (pre-base64) form of an encrypted session token.
    fn build_token_body(key_id: &str, account_id: &str, encrypted_payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(key_id.len() as u8);
        body.extend_from_slice(key_id.as_bytes());
        body.extend_from_slice(account_id.as_bytes());
        body.extend_from_slice(&TEST_NONCE);
        body.extend_from_slice(&(encrypted_payload.len() as u32).to_le_bytes());
        body.extend_from_slice(encrypted_payload);
        body
    }

    /// Prefixes the version byte and base64-encodes `body` to form a session token string.
    fn encode_token(body: &[u8]) -> String {
        format!("{}{}", CURRENT_TOKEN_VERSION as char, URL_SAFE_NO_PAD.encode(body))
    }

    /// Encrypts `plaintext` in place with AES256-GCM using `key`, `TEST_NONCE`, and the
    /// "AccountId=<account_id>" associated data, returning the ciphertext with the appended tag.
    fn encrypt_payload(key: &[u8; AES256_KEY_LENGTH], account_id: &str, mut plaintext: Vec<u8>) -> Vec<u8> {
        let key = AesKey::<Aes256Gcm>::from(*key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::<NonceSize>::from(TEST_NONCE);
        cipher.encrypt_in_place(&nonce, format!("AccountId={account_id}").as_bytes(), &mut plaintext).unwrap();
        plaintext
    }

    /// Serializes `data` into the postcard plaintext that a session token carries.
    fn serialize_session_token_data(data: &SessionTokenData) -> Vec<u8> {
        let mut buffer = [0u8; 4096];
        postcard::to_slice(data, &mut buffer).unwrap().to_vec()
    }

    /// Returns a `StaticKeyService` holding `TEST_KEY` under `TEST_KEY_ID`.
    fn test_key_service() -> StaticKeyService {
        let mut service = StaticKeyService::new();
        service.0.insert(
            TEST_KEY_ID.to_string(),
            SessionTokenEncryptionKeyInfo {
                session_token_encryption_key_id: TEST_KEY_ID.to_string(),
                encryption_algorithm: SessionTokenEncryptionAlgorithm::Aes256Gcm,
                encryption_key: Zeroizing::new(TEST_KEY.to_vec()),
            },
        );
        service
    }

    /// Builds a complete, valid session token for `data`, encrypted with `TEST_KEY`.
    fn test_session_token(data: &SessionTokenData) -> String {
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(data));
        encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload))
    }

    /// Returns a representative `SessionTokenData` with an assumed-role principal.
    fn test_session_token_data() -> SessionTokenData {
        // 2026-01-01T00:00:00Z; a fixed timestamp since chrono's `clock` feature is not enabled.
        let issued_at = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
        let mut metadata = SessionData::new();
        metadata.insert("MultiFactorAuthPresent", SessionValue::Bool(true));
        let inline_policy = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        )
        .unwrap();
        let environment_tag_key = AsciiString::from_ascii(b"Environment".to_vec()).unwrap();
        let tags = HashMap::from([(environment_tag_key.clone(), "Production".to_string())]);
        let transitive_tag_keys = HashSet::from([environment_tag_key]);

        SessionTokenData {
            role_id: "AROAEXAMPLEROLEID".to_string(),
            access_key_id: "ASIAEXAMPLEACCESSKEY".to_string(),
            secret_key: KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap(),
            principal: AssumedRole::new("aws", TEST_ACCOUNT_ID, "TestRole", "test-session").unwrap().into(),
            expires_at: issued_at + Duration::hours(1),
            issued_at,
            inline_policy: Some(inline_policy),
            managed_policy_ids: vec!["ANPAEXAMPLEPOLICYID".to_string()],
            role_session_name: "test-session".to_string(),
            metadata,
            tags,
            transitive_tag_keys,
        }
    }

    #[tokio::test]
    async fn test_extractor_round_trip() {
        let expected = test_session_token_data();
        let token = test_session_token(&expected);
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        let actual = extractor.ready().await.unwrap().call(token).await.unwrap();
        assert_eq!(actual.access_key_id, expected.access_key_id);
        assert_eq!(actual.secret_key, expected.secret_key);
        assert_eq!(actual.principal, expected.principal);
        assert_eq!(actual.expires_at, expected.expires_at);
        assert_eq!(actual.issued_at, expected.issued_at);
        assert_eq!(actual.inline_policy, expected.inline_policy);
        assert_eq!(actual.managed_policy_ids, expected.managed_policy_ids);
        assert_eq!(actual.role_session_name, expected.role_session_name);
        assert!(matches!(actual.metadata.get("MultiFactorAuthPresent"), Some(SessionValue::Bool(true))));
        assert_eq!(actual.tags, expected.tags);
        assert_eq!(actual.transitive_tag_keys, expected.transitive_tag_keys);
    }

    #[tokio::test]
    async fn test_extractor_unknown_key_id() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body("unknown-key", TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "KeyId unknown-key not found in StaticKeyService",
        );
    }

    #[tokio::test]
    async fn test_extractor_wrong_key() {
        let wrong_key = [0x99; AES256_KEY_LENGTH];
        let payload =
            encrypt_payload(&wrong_key, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "The security token included in the request is invalid",
        );
    }

    #[tokio::test]
    async fn test_extractor_tampered_account_id() {
        // The associated data says TEST_ACCOUNT_ID, but the token body claims a different
        // (well-formed) account id, so authentication must fail.
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, "999999999999", &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "The security token included in the request is invalid",
        );
    }

    #[tokio::test]
    async fn test_extractor_undecodable_plaintext() {
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, vec![0xff; 4]);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "The security token included in the request is invalid",
        );
    }

    #[tokio::test]
    async fn test_extractor_trailing_plaintext() {
        let mut plaintext = serialize_session_token_data(&test_session_token_data());
        plaintext.push(0x00);
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, plaintext);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(token).await,
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_extractor_clone() {
        let _extractor = DefaultSessionTokenExtractor::new(test_key_service()).clone();
    }

    #[test_log::test]
    fn test_from_session_token_valid() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));

        let parsed = EncryptedSessionTokenData::from_session_token(token.as_bytes()).unwrap();
        assert_eq!(parsed.key_id, TEST_KEY_ID);
        assert_eq!(parsed.account_id, TEST_ACCOUNT_ID);
        assert_eq!(parsed.nonce, TEST_NONCE);
        assert_eq!(parsed.encrypted_payload, payload);

        let cloned = parsed.clone();
        assert_eq!(cloned.key_id, parsed.key_id);
    }

    #[test_log::test]
    fn test_from_session_token_empty() {
        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(b""),
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_from_session_token_wrong_version() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);
        let token = format!("1{}", URL_SAFE_NO_PAD.encode(&body));

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(token.as_bytes()),
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_from_session_token_invalid_base64() {
        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(b"0!not-base64!"),
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_from_session_token_truncated() {
        // Every strict prefix of a valid body fails: the empty body, a truncated key id, a
        // truncated account id, a truncated nonce, a truncated payload length, and a payload
        // shorter than its declared length.
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);

        for length in 0..body.len() {
            assert_invalid_session_token(
                EncryptedSessionTokenData::from_session_token(encode_token(&body[..length]).as_bytes()),
                "The security token included in the request is invalid",
            );
        }
    }

    #[test_log::test]
    fn test_from_session_token_non_utf8_key_id() {
        let mut body = vec![2, 0xff, 0xfe];
        body.extend_from_slice(TEST_ACCOUNT_ID.as_bytes());
        body.extend_from_slice(&TEST_NONCE);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes()),
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_from_session_token_non_digit_account_id() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, "12345678901a", &payload);

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes()),
            "The security token included in the request is invalid",
        );
    }

    #[test_log::test]
    fn test_static_key_service_construction() {
        assert!(StaticKeyService::new().0.is_empty());
        assert!(StaticKeyService::default().0.is_empty());

        let service = StaticKeyService::with_capacity(10);
        assert!(service.0.is_empty());
        assert!(service.0.capacity() >= 10);
    }

    #[tokio::test]
    async fn test_encrypt_round_trip() {
        let data = test_session_token_data();
        let key_info = SessionTokenEncryptionKeyInfo {
            session_token_encryption_key_id: TEST_KEY_ID.to_string(),
            encryption_algorithm: SessionTokenEncryptionAlgorithm::Aes256Gcm,
            encryption_key: Zeroizing::new(TEST_KEY.to_vec()),
        };

        let encrypted = EncryptedSessionTokenData::encrypt(&data, &key_info, TEST_ACCOUNT_ID, None).unwrap();
        let session_token = encrypted.to_session_token().unwrap();

        let mut extractor = DefaultSessionTokenExtractor::new(test_key_service());
        let extracted = extractor.ready().await.unwrap().call(session_token).await.unwrap();

        assert_eq!(extracted.access_key_id, data.access_key_id);
        assert_eq!(extracted.expires_at, data.expires_at);
        assert_eq!(extracted.issued_at, data.issued_at);
        assert_eq!(extracted.managed_policy_ids, data.managed_policy_ids);
        assert_eq!(extracted.role_id, data.role_id);
        assert_eq!(extracted.role_session_name, data.role_session_name);
        assert_eq!(extracted.secret_key, data.secret_key);
        assert_eq!(extracted.tags, data.tags);
        assert_eq!(extracted.transitive_tag_keys, data.transitive_tag_keys);
    }

    #[tokio::test]
    async fn test_encrypt_rejects_bad_inputs() {
        let data = test_session_token_data();
        let key_info = SessionTokenEncryptionKeyInfo {
            session_token_encryption_key_id: TEST_KEY_ID.to_string(),
            encryption_algorithm: SessionTokenEncryptionAlgorithm::Aes256Gcm,
            encryption_key: Zeroizing::new(TEST_KEY.to_vec()),
        };

        // Non-numeric and wrong-length account IDs are rejected.
        for account_id in ["12345678901a", "123456789012345"] {
            assert!(matches!(
                EncryptedSessionTokenData::encrypt(&data, &key_info, account_id, None),
                Err(SignatureError::InternalFailure(_))
            ));
        }

        // Wrong key length is rejected.
        let short_key_info = SessionTokenEncryptionKeyInfo {
            session_token_encryption_key_id: TEST_KEY_ID.to_string(),
            encryption_algorithm: SessionTokenEncryptionAlgorithm::Aes256Gcm,
            encryption_key: Zeroizing::new(vec![0x42; 16]),
        };
        assert!(matches!(
            EncryptedSessionTokenData::encrypt(&data, &short_key_info, TEST_ACCOUNT_ID, None),
            Err(SignatureError::InternalFailure(_))
        ));
    }

    #[tokio::test]
    async fn test_static_key_service_call() {
        let mut service = test_key_service().clone();

        let key_info = service.ready().await.unwrap().call(TEST_KEY_ID.to_string()).await.unwrap();
        assert_eq!(key_info.session_token_encryption_key_id, TEST_KEY_ID);
        assert_eq!(key_info.encryption_algorithm, SessionTokenEncryptionAlgorithm::Aes256Gcm);
        assert_eq!(key_info.encryption_key.as_slice(), TEST_KEY);

        assert_invalid_session_token(
            service.ready().await.unwrap().call("missing".to_string()).await,
            "KeyId missing not found in StaticKeyService",
        );
    }
}
