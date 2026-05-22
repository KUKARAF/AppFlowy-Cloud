use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SupportedClientFeatures {
  // Supports Collab Params serialization using Protobuf
  CollabParamsProtobuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfoResponseItem {
  pub supported_client_features: Vec<SupportedClientFeatures>,
  pub minimum_supported_client_version: Option<String>,
  pub appflowy_web_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthProvidersResponseItem {
  pub count: usize,
  pub providers: Vec<String>,
  pub signup_disabled: bool,
  pub mailer_autoconfirm: bool,
}
