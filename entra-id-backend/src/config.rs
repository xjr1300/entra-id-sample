use config::Config;
use secrecy::SecretString;
use serde::Deserialize;

use crate::entra_id::Tenant;

type ConfigResult<T> = Result<T, ConfigError>;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    LoadError(config::ConfigError),
    #[error("{0}")]
    DeserializeError(config::ConfigError),
}

#[derive(Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub web: WebConfig,
    pub entra_id: EntraIdConfig,
    pub client_credentials: ClientCredentials,
}

impl AppConfig {
    pub fn load() -> ConfigResult<Self> {
        let config = Config::builder()
            .add_source(config::File::with_name("config.yaml"))
            .build()
            .map_err(ConfigError::LoadError)?;
        config
            .try_deserialize()
            .map_err(ConfigError::DeserializeError)
    }
}

#[derive(Deserialize)]
pub struct WebConfig {
    pub port: u16,
}

#[derive(Deserialize)]
pub struct EntraIdConfig {
    /// テナントベクタ
    pub tenants: Vec<Tenant>,

    /// キャッシュしたJWK公開鍵のTTL（秒）
    pub jwk_cache_ttl: u64,

    /// 定期的にバックグラウンドですべてのテナントのJWK公開鍵をリフレッシュする間隔（秒）
    pub refresh_jwks_interval: u64,

    /// kidを基にテナントのJWK公開鍵を得られなかったときに、そのテナントのJWK公開鍵が最後にリフレッシュされてから、
    /// 次にリフレッシュするまでの最小時間（秒）
    pub refresh_tenant_jwks_interval: u64,
}

#[derive(Clone, Deserialize)]
pub struct ClientId(pub String);

/// クライアント資格情報
#[derive(Clone, Deserialize)]
pub struct ClientCredentials {
    pub client_id: ClientId,
    pub client_secret: SecretString,
}
