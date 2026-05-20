use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthentikJWTClaims {
  // Standard JWT claims
  pub sub: String,  // User UUID
  pub exp: i64,
  pub iat: i64,
  pub iss: String,
  pub aud: Option<String>,

  // OIDC standard claims
  pub email: Option<String>,
  pub preferred_username: Option<String>,
  pub name: Option<String>,
  pub given_name: Option<String>,
  pub family_name: Option<String>,

  // Authentik-specific claims
  #[serde(flatten)]
  pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JWKSResponse {
  pub keys: Vec<JWK>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWK {
  pub kty: String,
  pub use_: Option<String>,
  #[serde(rename = "use")]
  pub use_value: Option<String>,
  pub kid: Option<String>,
  pub n: String,
  pub e: String,
  pub alg: Option<String>,
}

/// Cache for JWKS keys with synchronous interface for use in FromRequest
pub struct JWKSCache {
  keys: Arc<RwLock<Vec<JWK>>>,
}

impl JWKSCache {
  /// Create a new cache with pre-fetched keys
  pub fn with_keys(keys: Vec<JWK>) -> Self {
    Self {
      keys: Arc::new(RwLock::new(keys)),
    }
  }

  /// Synchronously get the cached keys
  pub fn get_keys(&self) -> Vec<JWK> {
    self.keys.try_read().map(|k| k.clone()).unwrap_or_default()
  }

  /// Async fetch from a URL (for initialization)
  #[instrument(level = "trace", err)]
  pub async fn fetch_from_url(jwks_url: &str) -> Result<Vec<JWK>, AuthentikJWTError> {
    debug!("Fetching JWKS from: {}", jwks_url);
    let client = Client::new();
    let response = client
      .get(jwks_url)
      .send()
      .await
      .map_err(|e| AuthentikJWTError::JWKSFetchError(e.to_string()))?;

    if !response.status().is_success() {
      return Err(AuthentikJWTError::JWKSFetchError(format!(
        "JWKS endpoint returned {}",
        response.status()
      )));
    }

    let jwks: JWKSResponse = response
      .json()
      .await
      .map_err(|e| AuthentikJWTError::JWKSParseError(e.to_string()))?;

    Ok(jwks.keys)
  }
}

#[derive(Debug)]
pub enum AuthentikJWTError {
  InvalidToken(String),
  InvalidSignature,
  TokenExpired,
  JWKSFetchError(String),
  JWKSParseError(String),
  JWKNotFound,
}

impl std::fmt::Display for AuthentikJWTError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      AuthentikJWTError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
      AuthentikJWTError::InvalidSignature => write!(f, "Invalid token signature"),
      AuthentikJWTError::TokenExpired => write!(f, "Token expired"),
      AuthentikJWTError::JWKSFetchError(msg) => write!(f, "Failed to fetch JWKS: {}", msg),
      AuthentikJWTError::JWKSParseError(msg) => write!(f, "Failed to parse JWKS: {}", msg),
      AuthentikJWTError::JWKNotFound => write!(f, "Appropriate JWK not found"),
    }
  }
}

impl std::error::Error for AuthentikJWTError {}

impl AuthentikJWTClaims {
  #[instrument(level = "trace", skip(token, cache), err)]
  pub fn decode(token: &str, cache: &JWKSCache) -> Result<TokenData<Self>, AuthentikJWTError> {
    // First decode without verification to get the header and check for errors
    let header =
      decode_header(token).map_err(|e| AuthentikJWTError::InvalidToken(e.to_string()))?;

    let kid = header
      .kid
      .ok_or(AuthentikJWTError::InvalidToken("No 'kid' in token header".to_string()))?;

    // Get JWKS keys (now synchronous)
    let keys = cache.get_keys();

    // Find the matching key
    let jwk = keys
      .iter()
      .find(|k| k.kid.as_ref().map(|id| id == &kid).unwrap_or(false))
      .ok_or(AuthentikJWTError::JWKNotFound)?;

    // Decode the RSA public key
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
      .map_err(|e| AuthentikJWTError::InvalidToken(format!("Invalid RSA key: {}", e)))?;

    // Validate the token
    let mut validation = Validation::new(Algorithm::RS256);
    // Allow some clock skew (30 seconds)
    validation.leeway = 30;

    let token_data = decode::<AuthentikJWTClaims>(token, &decoding_key, &validation)
      .map_err(|e| {
        let err_msg = e.to_string();
        if err_msg.contains("ExpiredSignature") {
          AuthentikJWTError::TokenExpired
        } else if err_msg.contains("InvalidSignature") {
          AuthentikJWTError::InvalidSignature
        } else {
          AuthentikJWTError::InvalidToken(err_msg)
        }
      })?;

    Ok(token_data)
  }
}

#[derive(Clone)]
pub struct AuthentikValidator {
  cache: Arc<JWKSCache>,
}

impl AuthentikValidator {
  /// Create a new validator with pre-fetched keys
  pub fn new(cache: Arc<JWKSCache>) -> Self {
    Self { cache }
  }

  #[instrument(level = "trace", skip(self, token), err)]
  pub fn validate(&self, token: &str) -> Result<TokenData<AuthentikJWTClaims>, AuthentikJWTError> {
    AuthentikJWTClaims::decode(token, &self.cache)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_authentik_jwt_claims_creation() {
    let mut extra = HashMap::new();
    extra.insert("test".to_string(), serde_json::json!("value"));

    let claims = AuthentikJWTClaims {
      sub: "uuid-123".to_string(),
      exp: 1234567890,
      iat: 1234567800,
      iss: "https://auth.example.com".to_string(),
      aud: Some("app-id".to_string()),
      email: Some("user@example.com".to_string()),
      preferred_username: Some("user".to_string()),
      name: Some("Test User".to_string()),
      given_name: Some("Test".to_string()),
      family_name: Some("User".to_string()),
      extra,
    };

    assert_eq!(claims.sub, "uuid-123");
    assert_eq!(claims.email, Some("user@example.com".to_string()));
  }
}
