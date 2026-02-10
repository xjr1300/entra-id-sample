use std::sync::Arc;

use crate::entra_id::{ClientCredentials, EntraIdTokenVerifier};

#[derive(Clone)]
pub struct AppState {
    pub token_verifier: Arc<EntraIdTokenVerifier>,
    pub client_credentials: ClientCredentials,
    pub http_client: reqwest::Client,
}
