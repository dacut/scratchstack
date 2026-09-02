//! Default session token extractor implementation.
use {
    crate::{
        ExpiredTokenError, ExtractSessionToken, ExtractSessionTokenRequest, InvalidSessionTokenError, SessionTokenData,
        SignatureError, constants::*, internal_service_error,
    },
    aes_gcm::{AeadCore, AeadInOut as _, Aes256Gcm, KeyInit as _, KeySizeUser, Nonce, aead::common::Generate as _},
    base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD},
    bon::Builder,
    chrono::{DateTime, Utc},
    scratchstack_core::RequestId,
    std::{
        collections::HashMap,
        fmt::{Display, Formatter, Result as FmtResult},
        future::Future,
        marker::PhantomData,
        mem::take,
        pin::Pin,
        str::FromStr,
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
/// [Postcard][postcard] serialization format. This is enabled by the `default_session_token`
/// feature.
///
/// The format of the session token used in this implementation is:
/// * Version: 1 byte, currently always ASCII `0`.
/// * Base64Payload: base-64 encoded string representing an [`EncryptedSessionTokenData`] struct.
///
/// A token that decrypts and decodes but whose `expires_at` is not later than the request's
/// server timestamp is rejected with [`ExpiredTokenError`]. The key service is handed the same
/// timestamp so that it can refuse keys whose acceptance window has closed.
#[derive(Builder, Clone)]
pub struct PostcardSessionTokenExtractor<KeyService> {
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
/// * NonceLength: u8, the length of the nonce that follows. AES256-GCM fixes this at
///   [`NONCE_LENGTH`]; a token declaring any other length is rejected.
/// * Nonce: `NonceLength` bytes, a random nonce used for encryption.
/// * EncryptedPayloadLength: u32 in little-endian format
/// * EncryptedPayload: variable length encrypted data, followed by its AEAD authentication tag.
///   The associated data is the string `AccountId=<account-id>`, so a token cannot be replayed
///   against a different account. The underlying plaintext is a postcard-serialized
///   [`SessionTokenData`] struct.
///
/// The encryption algorithm is not carried in the token: it is a property of the encryption key,
/// which [`SessionTokenEncryptionKeyInfo`] supplies, and reading it from the token would let a
/// caller nominate the algorithm used to decrypt their own token.
#[derive(Clone)]
pub struct EncryptedSessionTokenData {
    /// The KeyId of the signing key associated with the session token.
    key_id: String,

    /// The AWS account ID associated with the session token.
    account_id: String,

    /// The nonce used for encryption.
    nonce: Vec<u8>,

    /// The encrypted session token data, followed by its AEAD authentication tag. The associated
    /// data is the string `AccountId=<account-id>`.
    encrypted_payload: Vec<u8>,
}

/// Session token encryption algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionTokenEncryptionAlgorithm {
    /// AES256-GCM, currently the only supported encryption algorithm for session tokens.
    Aes256Gcm = 0,
}

impl FromStr for SessionTokenEncryptionAlgorithm {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AES256-GCM" => Ok(Self::Aes256Gcm),
            _ => Err(internal_service_error!("Unsupported session token encryption algorithm: {s}")),
        }
    }
}

impl Display for SessionTokenEncryptionAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Aes256Gcm => write!(f, "AES256-GCM"),
        }
    }
}

/// Request for obtaining a session token encryption key.
#[derive(Builder, Clone, Debug)]
pub struct GetSessionTokenEncryptionKeyRequest {
    /// The session token encryption key id.
    #[builder(into)]
    session_token_encryption_key_id: String,

    /// The request id for logging and tracing.
    #[builder(into)]
    request_id: RequestId,

    /// The time the server received the request. A key service that retires keys should refuse
    /// one whose acceptance window has closed by this instant, rather than by its own clock.
    server_timestamp: DateTime<Utc>,
}

impl GetSessionTokenEncryptionKeyRequest {
    /// Returns the session token encryption key id being requested.
    #[inline(always)]
    pub fn session_token_encryption_key_id(&self) -> &str {
        &self.session_token_encryption_key_id
    }

    /// Returns the request id for logging and tracing.
    #[inline(always)]
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the time the server received the request.
    #[inline(always)]
    pub fn server_timestamp(&self) -> DateTime<Utc> {
        self.server_timestamp
    }
}

/// Information about a session token encryption key.
#[derive(Builder, Clone)]
pub struct SessionTokenEncryptionKeyInfo {
    /// The ID of the session token encryption key.
    session_token_encryption_key_id: String,

    /// The encryption algorithm used by the session token encryption key.
    encryption_algorithm: SessionTokenEncryptionAlgorithm,

    /// The key material for encrypting session tokens, formatted as raw bytes.
    encryption_key: Zeroizing<Vec<u8>>,
}

impl SessionTokenEncryptionKeyInfo {
    /// Returns the id of the session token encryption key.
    #[inline(always)]
    pub fn session_token_encryption_key_id(&self) -> &str {
        &self.session_token_encryption_key_id
    }

    /// Returns the encryption algorithm used by the session token encryption key.
    #[inline(always)]
    pub fn encryption_algorithm(&self) -> SessionTokenEncryptionAlgorithm {
        self.encryption_algorithm
    }

    /// Returns the key material for encrypting session tokens, formatted as raw bytes.
    #[inline(always)]
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }
}

/// A static key service, primarily for testing. It has no notion of an acceptance window, so it
/// ignores the request's server timestamp.
#[derive(Clone)]
#[repr(transparent)]
pub struct StaticKeyService(pub HashMap<String, SessionTokenEncryptionKeyInfo>);

impl<KeyService> PostcardSessionTokenExtractor<KeyService>
where
    KeyService: Service<GetSessionTokenEncryptionKeyRequest, Response = SessionTokenEncryptionKeyInfo, Error = SignatureError>
        + Clone
        + Send
        + 'static,
    KeyService::Future: Send,
{
    /// Extract the session token data from the given session token string.
    pub async fn extract(&mut self, request: ExtractSessionTokenRequest) -> Result<SessionTokenData, SignatureError> {
        let EncryptedSessionTokenData {
            key_id,
            account_id,
            nonce,
            encrypted_payload,
        } = EncryptedSessionTokenData::from_session_token(request.session_token().as_bytes(), request.request_id())?;

        // After decryption, this buffer holds the plaintext token data -- including the raw
        // secret key -- so it must be zeroized on every exit path.
        let mut payload = Zeroizing::new(encrypted_payload);
        let stek_req = GetSessionTokenEncryptionKeyRequest::builder()
            .session_token_encryption_key_id(key_id)
            .request_id(request.request_id())
            .server_timestamp(request.server_timestamp())
            .build();
        let key_info: SessionTokenEncryptionKeyInfo = self.key_service.call(stek_req).await?;
        if key_info.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
            return Err(internal_service_error!(request.request_id();
                "Unsupported encryption algorithm for session token encryption key {}: {:?}",
                key_info.session_token_encryption_key_id, key_info.encryption_algorithm));
        }

        let nonce = Nonce::try_from(nonce.as_slice())
            .map_err(|_| InvalidSessionTokenError::builder().request_id(request.request_id()).build())?;
        let associated_data = format!("AccountId={account_id}");
        let cipher = Aes256Gcm::new_from_slice(key_info.encryption_key.as_slice()).map_err(|e| {
            internal_service_error!(request.request_id();
                "Failed to create cipher for session token decryption with key {}: {e}",
                key_info.session_token_encryption_key_id)
        })?;

        cipher
            .decrypt_in_place(&nonce, associated_data.as_bytes(), &mut *payload)
            .map_err(|_| invalid_session_token_error(request.request_id()))?;

        let (result, remainder): (SessionTokenData, &[u8]) = postcard::take_from_bytes(payload.as_slice())
            .map_err(|_| invalid_session_token_error(request.request_id()))?;
        if !remainder.is_empty() {
            return Err(invalid_session_token_error(request.request_id()));
        }

        // The token is authentic; now check that it is still current. Nothing downstream repeats
        // this check, so an expired token must not leave here. (The secret key inside `result`
        // is zeroized when it drops on this path.)
        if request.server_timestamp() >= result.expires_at {
            return Err(ExpiredTokenError::builder().request_id(request.request_id()).build().into());
        }

        Ok(result)
    }
}

impl<KeyService> Service<ExtractSessionTokenRequest> for PostcardSessionTokenExtractor<KeyService>
where
    KeyService: Service<GetSessionTokenEncryptionKeyRequest, Response = SessionTokenEncryptionKeyInfo, Error = SignatureError>
        + Clone
        + Send
        + 'static,
    KeyService::Future: Send,
{
    type Response = SessionTokenData;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.key_service.poll_ready(cx)
    }

    fn call(&mut self, req: ExtractSessionTokenRequest) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move { this.extract(req).await })
    }
}

impl EncryptedSessionTokenData {
    /// Encrypt the given session token data with the given encryption key, producing the
    /// encrypted session token data. The account ID must be the 12-digit AWS account ID
    /// associated with the session, represented as an ASCII string; it is used as the
    /// associated data for the encryption, binding the token to that account.
    pub fn encrypt(
        session_token_data: &SessionTokenData,
        key_info: &SessionTokenEncryptionKeyInfo,
        account_id: &str,
    ) -> Result<Self, SignatureError> {
        if key_info.encryption_algorithm != SessionTokenEncryptionAlgorithm::Aes256Gcm {
            return Err(internal_service_error!(
                "Unsupported encryption algorithm for session token encryption key {}: {:?}",
                key_info.session_token_encryption_key_id,
                key_info.encryption_algorithm
            ));
        }

        if account_id.len() != ACCOUNT_ID_LENGTH || !account_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(internal_service_error!("Invalid account ID for session token: {account_id}"));
        }

        let cipher = Aes256Gcm::new_from_slice(key_info.encryption_key.as_slice()).map_err(|e| {
            internal_service_error!(
                "Failed to create cipher for session token encryption with key {}: {e}",
                key_info.session_token_encryption_key_id
            )
        })?;

        // Before encryption, this buffer holds the plaintext token data -- including the raw
        // secret key -- so it must be zeroized on every exit path. On success, the plaintext is
        // overwritten in place by the ciphertext.
        let mut payload = Zeroizing::new(
            postcard::to_allocvec(session_token_data)
                .map_err(|e| internal_service_error!("Failed to serialize session token data: {e}"))?,
        );

        let nonce = Nonce::<NonceSize>::generate_from_rng(&mut rand::rng());
        let associated_data = format!("AccountId={account_id}");

        cipher
            .encrypt_in_place(&nonce, associated_data.as_bytes(), &mut *payload)
            .map_err(|e| internal_service_error!("Failed to encrypt session token data: {e}"))?;

        Ok(Self {
            key_id: key_info.session_token_encryption_key_id.clone(),
            account_id: account_id.to_string(),
            nonce: nonce.to_vec(),
            encrypted_payload: take(&mut *payload),
        })
    }

    /// Parse the encrypted session token data from the given byte slice.
    fn parse_encrypted_session_token_data(session_token: &[u8], request_id: RequestId) -> Result<Self, SignatureError> {
        if session_token.is_empty() {
            return Err(invalid_session_token_error(request_id));
        }

        let key_id_length = session_token[0] as usize;
        let key_id_start = 1;
        let key_id_end = key_id_start + key_id_length;
        if key_id_end > session_token.len() {
            return Err(invalid_session_token_error(request_id));
        }
        let key_id = String::from_utf8(session_token[key_id_start..key_id_end].to_vec())
            .map_err(|_| invalid_session_token_error(request_id))?;

        let account_id_start = key_id_end;
        let account_id_end = account_id_start + ACCOUNT_ID_LENGTH;
        if account_id_end > session_token.len() {
            return Err(invalid_session_token_error(request_id));
        }

        let account_id = &session_token[account_id_start..account_id_end];
        if !account_id.iter().all(|&b| b.is_ascii_digit()) {
            return Err(invalid_session_token_error(request_id));
        }
        let account_id = String::from_utf8(account_id.to_vec()).map_err(|_| invalid_session_token_error(request_id))?;

        let nonce_length_start = account_id_end;
        if nonce_length_start >= session_token.len() {
            return Err(invalid_session_token_error(request_id));
        }
        // AES256-GCM nonces are a fixed width, so a token declaring any other length was not
        // produced by `to_session_token` and cannot be decrypted; reject it rather than reading
        // a nonce of the wrong size.
        let nonce_length = session_token[nonce_length_start] as usize;
        if nonce_length != NONCE_LENGTH {
            return Err(invalid_session_token_error(request_id));
        }

        let nonce_start = nonce_length_start + 1;
        let nonce_end = nonce_start + nonce_length;
        if nonce_end > session_token.len() {
            return Err(invalid_session_token_error(request_id));
        }
        let nonce = session_token[nonce_start..nonce_end].to_vec();

        let encrypted_payload_length_start = nonce_end;
        let encrypted_payload_length_end = encrypted_payload_length_start + 4;
        if encrypted_payload_length_end > session_token.len() {
            return Err(invalid_session_token_error(request_id));
        }
        let encrypted_payload_length = u32::from_le_bytes(
            session_token[encrypted_payload_length_start..encrypted_payload_length_end]
                .try_into()
                .map_err(|_| invalid_session_token_error(request_id))?,
        ) as usize;
        let encrypted_payload_start = encrypted_payload_length_end;
        let encrypted_payload_end = encrypted_payload_start + encrypted_payload_length;
        if encrypted_payload_end > session_token.len() {
            return Err(invalid_session_token_error(request_id));
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
    pub(crate) fn from_session_token(session_token: &[u8], request_id: RequestId) -> Result<Self, SignatureError> {
        if session_token.is_empty() || session_token.len() > MAX_SESSION_TOKEN_SIZE {
            return Err(invalid_session_token_error(request_id));
        }

        if session_token[0] != CURRENT_TOKEN_VERSION {
            return Err(invalid_session_token_error(request_id));
        }

        URL_SAFE_NO_PAD
            .decode(&session_token[1..])
            .map_err(|_| invalid_session_token_error(request_id))
            .and_then(|decoded| Self::parse_encrypted_session_token_data(&decoded, request_id))
    }

    /// Serialize this encrypted session token data into an opaque session token string.
    pub fn to_session_token(&self) -> Result<String, SignatureError> {
        let key_id_length = u8::try_from(self.key_id.len())
            .map_err(|_| internal_service_error!("Session token encryption key id is too long: {}", self.key_id))?;
        let encrypted_payload_length = u32::try_from(self.encrypted_payload.len())
            .map_err(|_| internal_service_error!("Encrypted session token payload is too long"))?;
        // `encrypt` always produces a nonce of exactly `NONCE_LENGTH` bytes; anything else means
        // this struct was assembled some other way and would not survive a round trip.
        let nonce_length = u8::try_from(self.nonce.len()).ok().filter(|len| usize::from(*len) == NONCE_LENGTH);
        let Some(nonce_length) = nonce_length else {
            return Err(internal_service_error!(
                "Session token nonce must be {NONCE_LENGTH} bytes, got {}",
                self.nonce.len()
            ));
        };

        let mut body = Vec::with_capacity(
            1 + self.key_id.len() + ACCOUNT_ID_LENGTH + 1 + self.nonce.len() + 4 + self.encrypted_payload.len(),
        );
        body.push(key_id_length);
        body.extend_from_slice(self.key_id.as_bytes());
        body.extend_from_slice(self.account_id.as_bytes());
        body.push(nonce_length);
        body.extend_from_slice(&self.nonce);
        body.extend_from_slice(&encrypted_payload_length.to_le_bytes());
        body.extend_from_slice(&self.encrypted_payload);

        let session_token = format!("{}{}", CURRENT_TOKEN_VERSION as char, URL_SAFE_NO_PAD.encode(body));
        if session_token.len() > MAX_SESSION_TOKEN_SIZE {
            return Err(internal_service_error!("Session token is too long"));
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

impl Service<GetSessionTokenEncryptionKeyRequest> for StaticKeyService {
    type Response = SessionTokenEncryptionKeyInfo;
    type Error = SignatureError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSessionTokenEncryptionKeyRequest) -> Self::Future {
        let key_id = req.session_token_encryption_key_id.clone();
        let request_id = req.request_id;
        let key = self.0.get(&key_id).cloned();
        Box::pin(async move {
            key.ok_or_else(|| {
                InvalidSessionTokenError::builder()
                    .message(format!("KeyId {key_id} not found in StaticKeyService"))
                    .request_id(request_id)
                    .build()
                    .into()
            })
        })
    }
}

/// Helper function to create a `SignatureError::InvalidSessionToken` error with a default message.
fn invalid_session_token_error(request_id: RequestId) -> SignatureError {
    InvalidSessionTokenError::builder().message(MSG_SECURITY_TOKEN_INVALID).request_id(request_id).build().into()
}

// Compile-time checks that `PostcardSessionTokenExtractor` satisfies the bounds the rest of the
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
        K: Service<
                GetSessionTokenEncryptionKeyRequest,
                Response = SessionTokenEncryptionKeyInfo,
                Error = SignatureError,
            > + Clone
            + Send
            + 'static,
        K::Future: Send,
    {
        let (response, error) = assoc::<PostcardSessionTokenExtractor<K>, ExtractSessionTokenRequest>();
        let _: PhantomData<SessionTokenData> = response;
        let _: PhantomData<SignatureError> = error;
        assert_send::<<PostcardSessionTokenExtractor<K> as Service<ExtractSessionTokenRequest>>::Future>();
        assert_extract_session_token::<PostcardSessionTokenExtractor<K>>();
    }
};

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::KSecretKey,
        aes_gcm::Key as AesKey,
        ascii_casing::AsciiString,
        chrono::Duration,
        scratchstack_aspen::Policy as AspenPolicy,
        scratchstack_aws_principal::{AssumedRole, SessionData, SessionValue},
        std::collections::{HashMap, HashSet},
        tower::ServiceExt as _,
    };

    const TEST_ACCOUNT_ID: &str = "123456789012";
    const TEST_KEY: [u8; AES256_KEY_LENGTH] = [0x42; AES256_KEY_LENGTH];
    const TEST_KEY_ID: &str = "test-key-1";
    const TEST_NONCE: [u8; NONCE_LENGTH] = [0x07; NONCE_LENGTH];
    const MSG_INVALID_SESSION_TOKEN: &str = "The security token included in the request is invalid";
    const MSG_EXPIRED_TOKEN: &str = "The security token included in the request is expired";

    /// When the test token was issued: 2026-01-01T00:00:00Z. The tests use fixed instants so
    /// they never depend on the wall clock.
    fn test_issued_at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_767_225_600, 0).unwrap()
    }

    /// A moment inside the test token's one-hour lifetime.
    fn test_now() -> DateTime<Utc> {
        test_issued_at() + Duration::minutes(5)
    }

    /// Asserts that `result` is an `InvalidSessionToken` error carrying `expected_message`.
    fn assert_invalid_session_token<T>(result: Result<T, SignatureError>, expected_message: &str) {
        match result {
            Err(SignatureError::InvalidSessionToken(e)) => assert_eq!(e.message, expected_message),
            _ => panic!("expected Err(SignatureError::InvalidSessionToken), got Ok()"),
        }
    }

    /// Assembles the binary (pre-base64) form of an encrypted session token.
    fn build_token_body(key_id: &str, account_id: &str, encrypted_payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(key_id.len() as u8);
        body.extend_from_slice(key_id.as_bytes());
        body.extend_from_slice(account_id.as_bytes());
        body.push(TEST_NONCE.len() as u8);
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
        let issued_at = test_issued_at();
        let mut metadata = SessionData::new();
        metadata.insert("MultiFactorAuthPresent", SessionValue::Bool(true));
        let inline_policy = AspenPolicy::from_str(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        )
        .unwrap();
        let environment_tag_key = AsciiString::from_ascii(b"Environment".to_vec()).unwrap();
        let tags = HashMap::from([(environment_tag_key.clone(), "Production".to_string())]);
        let transitive_tag_keys = HashSet::from([environment_tag_key]);

        SessionTokenData::builder()
            .role_id("AROAEXAMPLEROLEID")
            .access_key_id("ASIAEXAMPLEACCESSKEY")
            .secret_key(KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap())
            .principal(
                AssumedRole::builder()
                    .partition("aws")
                    .account_id(TEST_ACCOUNT_ID)
                    .role_name("TestRole")
                    .session_name("test-session")
                    .build()
                    .unwrap(),
            )
            .expires_at(issued_at + Duration::hours(1))
            .issued_at(issued_at)
            .inline_policy(inline_policy)
            .managed_policy_ids(vec!["ANPAEXAMPLEPOLICYID".to_string()])
            .role_session_name("test-session")
            .metadata(metadata)
            .tags(tags)
            .transitive_tag_keys(transitive_tag_keys)
            .build()
    }

    #[tokio::test]
    async fn test_extractor_round_trip() {
        let expected = test_session_token_data();
        let token = test_session_token(&expected);
        let request_id = RequestId::new();
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();

        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        let actual = extractor.ready().await.unwrap().call(req).await.unwrap();
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
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let request_id = RequestId::new();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        assert_invalid_session_token(
            extractor.ready().await.unwrap().call(req).await,
            "KeyId unknown-key not found in StaticKeyService",
        );
    }

    #[tokio::test]
    async fn test_extractor_wrong_key() {
        let wrong_key = [0x99; AES256_KEY_LENGTH];
        let payload =
            encrypt_payload(&wrong_key, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let request_id = RequestId::new();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        assert_invalid_session_token(extractor.ready().await.unwrap().call(req).await, MSG_INVALID_SESSION_TOKEN);
    }

    #[tokio::test]
    async fn test_extractor_tampered_account_id() {
        // The associated data says TEST_ACCOUNT_ID, but the token body claims a different
        // (well-formed) account id, so authentication must fail.
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, "999999999999", &payload));
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let request_id = RequestId::new();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        assert_invalid_session_token(extractor.ready().await.unwrap().call(req).await, MSG_INVALID_SESSION_TOKEN);
    }

    #[tokio::test]
    async fn test_extractor_undecodable_plaintext() {
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, vec![0xff; 4]);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let request_id = RequestId::new();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        assert_invalid_session_token(extractor.ready().await.unwrap().call(req).await, MSG_INVALID_SESSION_TOKEN);
    }

    #[tokio::test]
    async fn test_extractor_trailing_plaintext() {
        let mut plaintext = serialize_session_token_data(&test_session_token_data());
        plaintext.push(0x00);
        let payload = encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, plaintext);
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let request_id = RequestId::new();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        assert_invalid_session_token(extractor.ready().await.unwrap().call(req).await, MSG_INVALID_SESSION_TOKEN);
    }

    /// A token is accepted right up until the instant it expires, and rejected from then on.
    /// Nothing after the extractor repeats this check, so it has to be exact.
    #[tokio::test]
    async fn test_extractor_expired_token() {
        let data = test_session_token_data();
        let token = test_session_token(&data);
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();

        let request = |server_timestamp: DateTime<Utc>| {
            ExtractSessionTokenRequest::builder()
                .session_token(token.clone())
                .request_id(RequestId::new())
                .server_timestamp(server_timestamp)
                .build()
        };

        let just_before = request(data.expires_at - Duration::seconds(1));
        extractor.ready().await.unwrap().call(just_before).await.expect("token must be accepted before it expires");

        for server_timestamp in
            [data.expires_at, data.expires_at + Duration::seconds(1), data.expires_at + Duration::days(365)]
        {
            let result = extractor.ready().await.unwrap().call(request(server_timestamp)).await;
            match result {
                Err(SignatureError::ExpiredToken(e)) => assert_eq!(e.message, MSG_EXPIRED_TOKEN),
                Err(e) => panic!("expected ExpiredToken at {server_timestamp}, got {e:?}"),
                Ok(_) => panic!("expired token accepted at {server_timestamp}"),
            }
        }
    }

    /// The key service is handed the request's server timestamp, so a service that retires keys
    /// can judge the acceptance window by the same clock the rest of validation uses.
    #[tokio::test]
    async fn test_extractor_passes_server_timestamp_to_key_service() {
        /// Wraps the static service, asserting on the timestamp every request carries.
        #[derive(Clone)]
        struct Expecting {
            inner: StaticKeyService,
            server_timestamp: DateTime<Utc>,
        }

        impl Service<GetSessionTokenEncryptionKeyRequest> for Expecting {
            type Response = SessionTokenEncryptionKeyInfo;
            type Error = SignatureError;
            type Future = <StaticKeyService as Service<GetSessionTokenEncryptionKeyRequest>>::Future;

            fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                self.inner.poll_ready(cx)
            }

            fn call(&mut self, req: GetSessionTokenEncryptionKeyRequest) -> Self::Future {
                assert_eq!(req.server_timestamp(), self.server_timestamp);
                self.inner.call(req)
            }
        }

        let data = test_session_token_data();
        let token = test_session_token(&data);
        let key_service = Expecting {
            inner: test_key_service(),
            server_timestamp: test_now(),
        };
        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(key_service).build();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(token)
            .request_id(RequestId::new())
            .server_timestamp(test_now())
            .build();

        extractor.ready().await.unwrap().call(req).await.expect("token should extract");
    }

    #[test_log::test]
    fn test_extractor_clone() {
        let _extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build().clone();
    }

    #[test_log::test]
    fn test_from_session_token_valid() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let token = encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload));
        let request_id = RequestId::new();

        let parsed = EncryptedSessionTokenData::from_session_token(token.as_bytes(), request_id).unwrap();
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
            EncryptedSessionTokenData::from_session_token(b"", RequestId::new()),
            MSG_INVALID_SESSION_TOKEN,
        );
    }

    #[test_log::test]
    fn test_from_session_token_wrong_version() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);
        let token = format!("1{}", URL_SAFE_NO_PAD.encode(&body));
        let request_id = RequestId::new();

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(token.as_bytes(), request_id),
            MSG_INVALID_SESSION_TOKEN,
        );
    }

    #[test_log::test]
    fn test_from_session_token_invalid_base64() {
        let request_id = RequestId::new();
        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(b"0!not-base64!", request_id),
            MSG_INVALID_SESSION_TOKEN,
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
        let request_id = RequestId::new();

        for length in 0..body.len() {
            assert_invalid_session_token(
                EncryptedSessionTokenData::from_session_token(encode_token(&body[..length]).as_bytes(), request_id),
                MSG_INVALID_SESSION_TOKEN,
            );
        }
    }

    /// The nonce length is carried in the token, but AES256-GCM fixes it, so any declared length
    /// other than `NONCE_LENGTH` is refused before a nonce of the wrong size is read.
    #[test_log::test]
    fn test_from_session_token_wrong_nonce_length() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload);
        let nonce_length_offset = 1 + TEST_KEY_ID.len() + ACCOUNT_ID_LENGTH;
        assert_eq!(body[nonce_length_offset], NONCE_LENGTH as u8, "the helper writes the real nonce length");
        let request_id = RequestId::new();

        for declared in [0u8, 1, (NONCE_LENGTH - 1) as u8, (NONCE_LENGTH + 1) as u8, u8::MAX] {
            let mut body = body.clone();
            body[nonce_length_offset] = declared;
            assert_invalid_session_token(
                EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes(), request_id),
                MSG_INVALID_SESSION_TOKEN,
            );
        }
    }

    /// A nonce of the wrong size never reaches the wire: `to_session_token` refuses it rather
    /// than emitting a token that `from_session_token` would reject.
    #[test_log::test]
    fn test_to_session_token_wrong_nonce_length() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let mut data = EncryptedSessionTokenData::from_session_token(
            encode_token(&build_token_body(TEST_KEY_ID, TEST_ACCOUNT_ID, &payload)).as_bytes(),
            RequestId::new(),
        )
        .unwrap();

        data.nonce.push(0);
        let e = data.to_session_token().unwrap_err();
        assert!(matches!(e, SignatureError::InternalServiceError(_)), "got {e:?}");
    }

    #[test_log::test]
    fn test_from_session_token_non_utf8_key_id() {
        let mut body = vec![2, 0xff, 0xfe];
        body.extend_from_slice(TEST_ACCOUNT_ID.as_bytes());
        body.extend_from_slice(&TEST_NONCE);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        let request_id = RequestId::new();

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes(), request_id),
            MSG_INVALID_SESSION_TOKEN,
        );
    }

    #[test_log::test]
    fn test_from_session_token_non_digit_account_id() {
        let payload =
            encrypt_payload(&TEST_KEY, TEST_ACCOUNT_ID, serialize_session_token_data(&test_session_token_data()));
        let body = build_token_body(TEST_KEY_ID, "12345678901a", &payload);
        let request_id = RequestId::new();

        assert_invalid_session_token(
            EncryptedSessionTokenData::from_session_token(encode_token(&body).as_bytes(), request_id),
            MSG_INVALID_SESSION_TOKEN,
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

        let encrypted = EncryptedSessionTokenData::encrypt(&data, &key_info, TEST_ACCOUNT_ID).unwrap();
        let session_token = encrypted.to_session_token().unwrap();
        let request_id = RequestId::new();

        let mut extractor = PostcardSessionTokenExtractor::builder().key_service(test_key_service()).build();
        let req = ExtractSessionTokenRequest::builder()
            .session_token(session_token)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();
        let extracted = extractor.ready().await.unwrap().call(req).await.unwrap();

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
                EncryptedSessionTokenData::encrypt(&data, &key_info, account_id),
                Err(SignatureError::InternalServiceError(_))
            ));
        }

        // Wrong key length is rejected.
        let short_key_info = SessionTokenEncryptionKeyInfo {
            session_token_encryption_key_id: TEST_KEY_ID.to_string(),
            encryption_algorithm: SessionTokenEncryptionAlgorithm::Aes256Gcm,
            encryption_key: Zeroizing::new(vec![0x42; 16]),
        };
        assert!(matches!(
            EncryptedSessionTokenData::encrypt(&data, &short_key_info, TEST_ACCOUNT_ID),
            Err(SignatureError::InternalServiceError(_))
        ));
    }

    #[tokio::test]
    async fn test_static_key_service_call() {
        let mut service = test_key_service().clone();
        let request_id = RequestId::new();
        let req = GetSessionTokenEncryptionKeyRequest::builder()
            .session_token_encryption_key_id(TEST_KEY_ID)
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();

        let key_info = service.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(key_info.session_token_encryption_key_id, TEST_KEY_ID);
        assert_eq!(key_info.encryption_algorithm, SessionTokenEncryptionAlgorithm::Aes256Gcm);
        assert_eq!(key_info.encryption_key.as_slice(), TEST_KEY);

        let req = GetSessionTokenEncryptionKeyRequest::builder()
            .session_token_encryption_key_id("missing")
            .request_id(request_id)
            .server_timestamp(test_now())
            .build();
        assert_invalid_session_token(
            service.ready().await.unwrap().call(req).await,
            "KeyId missing not found in StaticKeyService",
        );
    }
}
