use std::sync::Arc;

use crate::{config::ClientCredentials, entra_id::EntraIdTokenVerifier};

#[derive(Clone)]
pub struct AppState {
    pub token_verifier: Arc<EntraIdTokenVerifier>,
    pub client_credentials: ClientCredentials,
}
