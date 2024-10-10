use std::sync::Arc;

use axum::{middleware, Extension, Router};
use tower_http::trace::TraceLayer;

use crate::{handler::{auth::auth_handler, keys::get_secret_key, secrets::secrets_handler, secrets_version::secrets_version_handler, setting::setting_handler, user::users_handler}, middleware::auth, AppState};



pub fn create_router(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
    .nest("/auth", auth_handler())
    .nest(
        "/users",
        users_handler()
            .layer(middleware::from_fn(auth))
    )
    .nest(
        "/setting", 
        setting_handler()
            .layer(middleware::from_fn(auth))
    )
    .nest(
        "/secrets", 
        secrets_handler()
            .layer(middleware::from_fn(auth))
    )
    .nest(
        "/secrets_version", 
        secrets_version_handler()
            .layer(middleware::from_fn(auth))
    )
    .nest("/keys", get_secret_key())
    .layer(TraceLayer::new_for_http())
    .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}