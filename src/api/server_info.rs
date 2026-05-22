use actix_web::web::Data;
use actix_web::{web, Scope};
use shared_entity::dto::server_info_dto::{AuthProvidersResponseItem, ServerInfoResponseItem};
use shared_entity::response::{AppResponse, JsonAppResponse};

use crate::state::AppState;

pub fn server_info_scope() -> Scope {
  web::scope("/api/server").service(web::resource("").route(web::get().to(server_info_handler)))
}

pub fn auth_providers_scope() -> Scope {
  web::scope("/api/server-info")
    .service(web::resource("/auth-providers").route(web::get().to(auth_providers_handler)))
}

async fn server_info_handler(
  state: Data<AppState>,
) -> actix_web::Result<JsonAppResponse<ServerInfoResponseItem>> {
  Ok(
    AppResponse::Ok()
      .with_data(ServerInfoResponseItem {
        supported_client_features: vec![],
        minimum_supported_client_version: None,
        appflowy_web_url: state.config.appflowy_web_url.clone(),
      })
      .into(),
  )
}

async fn auth_providers_handler(
  state: Data<AppState>,
) -> actix_web::Result<JsonAppResponse<AuthProvidersResponseItem>> {
  let providers = if state.authentik_validator.is_some() {
    vec!["authentik".to_string()]
  } else {
    vec!["password".to_string()]
  };

  Ok(
    AppResponse::Ok()
      .with_data(AuthProvidersResponseItem {
        count: providers.len(),
        providers,
        signup_disabled: true,
        mailer_autoconfirm: false,
      })
      .into(),
  )
}
