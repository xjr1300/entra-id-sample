use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::{
    SeedableRng as _,
    distr::{Distribution as _, Uniform},
    rngs::SmallRng,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Entra ID関連の処理の結果型
pub type EntraIdResult<T> = Result<T, EntraIdError>;

/// Entra ID関連のエラー
#[derive(Debug, thiserror::Error)]
pub enum EntraIdError {
    /// Entra IDトークン検証者の初期化に失敗
    #[error("{0}")]
    InitializeError(String),

    /// JWKsプロバイダの初期化に失敗
    #[error("Failed to initialize JWKs provider: {0}")]
    JwksProviderInitError(#[from] reqwest::Error),

    /// 指定したテナントのJWK公開鍵セットの取得に失敗
    #[error("Failed to fetch JWKs from {1}: {0}")]
    JwksFetchError(reqwest::Error, Url),

    #[error("Failed to parse JWKS from {0}: {1}")]
    /// JWK公開鍵セットのパースに失敗
    JwksResponseParseError(Url, reqwest::Error),

    /// 特定のテナントに、特定のkidを持つJWK公開鍵が存在しない
    #[error("{0}")]
    DecodingKeyNotFound(String),

    /// テナントレジストリに、指定したテナントが存在しない
    #[error("Tenant not found in registry: {0}")]
    TenantNotFound(TenantId),

    /// トークンのヘッダのデコードに失敗
    #[error("Failed to decodeJWT header:{0}")]
    TokenHeaderDecodeError(#[from] jsonwebtoken::errors::Error),

    /// トークンのヘッダにkidが存在しない
    #[error("{0}")]
    TokenHeaderMissingKid(String),

    /// 許可していない発行者のテナント
    #[error("Disallowed issuer tenant: {0}")]
    DisallowedIssuerTenant(IssuerTenant),

    /// トークンがRS256アルゴリズムを使用していない
    #[error("Unsupported JWT alg: {0:?}")]
    UnsupportedTokenAlgorithm(jsonwebtoken::Algorithm),

    /// JWTの署名またはクレームの検証に失敗
    #[error("Failed to verify JWT signature or claims")]
    VerifyTokenError,

    /// JWKから復号鍵の作成に失敗
    #[error("Failed to create decoding key for kid {0}: {1}")]
    CreateDecodingKeyError(Kid, jsonwebtoken::errors::Error),

    /// JWTフォーマットエラー
    #[error("{0}")]
    InvalidTokenFormat(String),

    /// JWTペイロードのデコードエラー
    #[error("JWT payload decode failed: {0}")]
    TokenPayloadDecodeError(base64::DecodeError),

    /// JWTペイロードのパースエラー
    #[error("JWT payload parse failed: {0}")]
    TokenPayloadParseError(serde_json::Error),

    /// JWTトークンにissが存在しない
    #[error("Token doesn't contain iss: {0}")]
    TokenMissingIssuer(url::ParseError),

    /// issパースエラー
    #[error("Invalid issuer format: {0}")]
    InvalidIssuerFormat(String),
}

/// JWTのクレーム
#[allow(dead_code)]
#[derive(Clone, Deserialize)]
pub struct Claims {
    /// 購読者（audience）
    pub aud: String,
    /// 発行者（issuer）
    pub iss: String,
    /// 有効期限（expiration）
    pub exp: usize,
    /// オブジェクトID
    pub oid: String,
    /// サブジェクト
    pub sub: String,
    /// ロール
    pub roles: Option<Vec<String>>,
}

/// テナントID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct TenantId(pub String);

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// テナント
#[derive(Clone, Deserialize)]
pub struct Tenant {
    /// テナントID
    pub id: TenantId,
    /// JWK公開鍵セットを取得するURI
    pub uri: Url,
    /// トークンの発行者
    pub issuer: String,
    /// トークンの購読者
    pub audience: String,
}

/// テナントレジストリ
type TenantRegistry = HashMap<TenantId, Tenant>;

/// JWK (Json Web Key)
///
/// JWKは、JWT（JSON Web Token）の署名を検証するための公開鍵をJSONで表現したものである。
/// JWKは、JWTを発行するEntra IDが公開している。
/// バックエンドは、このJWKを使用して、受信したJWTの署名を検証する。
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Jwk {
    /// JWK公開鍵を識別するID
    pub kid: String,
    /// JWK公開鍵の種類（RSAなど）
    pub kty: String,
    /// RSA公開鍵のモジュラス
    pub n: String,
    /// RSA公開鍵の指数
    pub e: String,
    /// JWK公開鍵のアルゴリズム（RS256など）
    pub alg: Option<String>,
    /// JWK公開鍵の用途（sig（署名用）, enc（暗号化用）など）
    #[serde(rename = "use")]
    pub use_: Option<String>,
}

/// キャッシュしたJWK
#[derive(Debug)]
struct CachedJwk {
    /// JWK公開鍵
    jwk: Jwk,
    /// JWK公開鍵を最後に確認した時刻
    last_seen_at: Instant,
}

impl From<Jwk> for CachedJwk {
    fn from(jwk: Jwk) -> Self {
        let now = Instant::now();
        Self {
            jwk,
            last_seen_at: now,
        }
    }
}

/// JWK公開鍵のキーID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Kid(String);

impl std::fmt::Display for Kid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// テナントごとにキャッシュしたJWK公開鍵のkidをキーに持ち、そのJWK公開鍵を値に持つハッシュマップ
///
/// JWK公開鍵は、ローテーションされることがあるため、複数のJWK公開鍵が公開されている。
/// バックエンドは、JWK公開鍵セットを取得し、JWT公開鍵のkidに対応するJWK公開鍵を使用して署名を検証する。
type CachedJwkMap = HashMap<Kid, CachedJwk>;

/// テナントをキー、JWK公開鍵セットを値としたハッシュマップ
type TenantJwksCache = HashMap<TenantId, CachedJwkMap>;

/// Entra IDから取得したJWS公開鍵セットを提供
#[derive(Clone)]
struct JwksProvider {
    /// HTTPクライアント
    client: reqwest::Client,

    /// Entra IDのJWKsエンドポイントからレスポンスが返ってくるまでリクエストする最大試行回数
    jwks_request_max_attempts: u32,

    /// Entra IDのJWKsエンドポイントに最初に再試行リクエストを送信するまでの待機する時間
    jwks_request_retry_initial_wait: Duration,

    /// Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する時間を増加させる乗数
    /// 待機時間は、initial_wait * (multiplier ^ (attempt_number - 1))で計算される
    /// 指数バックオフ
    jwks_request_retry_backoff_multiplier: f64,

    /// Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する最大時間
    jwks_request_retry_max_wait: Duration,
}

/// JWK公開鍵セットのレスポンス
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// 再試行可能なエラーかどうかを判定する。
///
/// タイムアウト、接続エラー、サーバーエラー、レートリミットエラーは再試行可能とみなす。
/// 上記以外は、再試行不可能とみなす。
///
/// # Arguments
///
/// * `err` - reqwestのエラー
///
/// # Returns
///
/// 再試行可能なエラーであればtrue、そうでなければfalse
fn is_retryable_error(e: &reqwest::Error) -> bool {
    if e.is_timeout() {
        return true;
    }
    if e.is_connect() {
        return true;
    }
    match e.status() {
        Some(status) if status.is_server_error() => true,
        Some(status) if status == reqwest::StatusCode::TOO_MANY_REQUESTS => true,
        _ => false,
    }
}

impl JwksProvider {
    /// コンストラクタ
    ///
    /// # Arguments
    ///
    /// * `connection_timeout` - Entra IDのJWKsエンドポイントに接続する際のタイムアウト
    /// * `timeout` - Entra IDのJWKsエンドポイントからの応答を待つタイムアウト
    /// * `jwks_request_max_attempts`
    ///     - Entra IDのJWKsエンドポイントからレスポンスが返ってくるまでリクエストする最大試行回数
    /// * `jwks_request_retry_initial_wait`
    ///     - Entra IDのJWKsエンドポイントに最初に再試行リクエストを送信するまでの待機する時間
    /// * `jwks_request_retry_backoff_multiplier`
    ///     - Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する時間を増加させる乗数
    /// * `jwks_request_retry_max_wait`
    ///     - Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する最大時間
    fn new(
        connection_timeout: Duration,
        timeout: Duration,
        jwks_request_max_attempts: u32,
        jwks_request_retry_initial_wait: Duration,
        jwks_request_retry_backoff_multiplier: f64,
        jwks_request_retry_max_wait: Duration,
    ) -> EntraIdResult<Self> {
        let builder = reqwest::Client::builder()
            .connect_timeout(connection_timeout)
            .timeout(timeout);
        let client = builder
            .build()
            .map_err(EntraIdError::JwksProviderInitError)?;
        Ok(Self {
            client,
            jwks_request_max_attempts,
            jwks_request_retry_initial_wait,
            jwks_request_retry_backoff_multiplier,
            jwks_request_retry_max_wait,
        })
    }

    /// 指定したJWKsエンドポイントからJWK公開鍵セットを取得する。
    ///
    /// # Arguments
    ///
    /// * `jwks_uri` - JWKsエンドポイントのURI
    ///
    /// # Returns
    ///
    /// * JWK公開鍵セット
    async fn fetch_jwks(&self, jwks_uri: &Url) -> EntraIdResult<JwksResponse> {
        let mut delay = self
            .jwks_request_retry_initial_wait
            .min(self.jwks_request_retry_max_wait);
        let initial_millis = self.jwks_request_retry_initial_wait.as_millis() as f64;

        let mut attempts = 0;
        let multiplier = self.jwks_request_retry_backoff_multiplier;
        let mut rng = SmallRng::from_rng(&mut rand::rng());
        let jitter_dist = Uniform::new(0.8, 1.2);

        loop {
            attempts += 1;
            let response = self
                .client
                .get(jwks_uri.clone())
                .send()
                .await
                .map_err(|e| EntraIdError::JwksFetchError(e, jwks_uri.clone()))?;
            match response.error_for_status() {
                Ok(response) => {
                    return response
                        .json::<JwksResponse>()
                        .await
                        .map_err(|e| EntraIdError::JwksResponseParseError(jwks_uri.clone(), e));
                }
                Err(e) => {
                    let retryable = is_retryable_error(&e);
                    tracing::warn!(
                        error = %e, attempts = %attempts, delay_ms = %delay.as_millis(),
                        "Failed to fetch JWKs from {}, retryable: {}, max attempts: {}",
                        jwks_uri, retryable, self.jwks_request_max_attempts
                    );
                    if !retryable || attempts >= self.jwks_request_max_attempts {
                        return Err(EntraIdError::JwksFetchError(e, jwks_uri.clone()));
                    }
                    // 試行回数に対して指数関数的に待機時間を増加させる（指数バックオフ）
                    let mut delay_millis = initial_millis * multiplier.powf((attempts - 1) as f64);
                    // ランダムジッターを追加して、同時に再試行が発生するのを防ぐ
                    let jitter: f64 = match jitter_dist {
                        Ok(dist) => dist.sample(&mut rng),
                        Err(e) => {
                            tracing::warn!(
                                error = %e, "Failed to create jitter distribution, skipping jitter application"
                            );
                            1.0
                        }
                    };
                    delay_millis *= jitter;
                    delay = Duration::from_millis(delay_millis as u64)
                        .min(self.jwks_request_retry_max_wait);
                    // リクエストの再試行を待機
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// JWK公開鍵キャッシュのリフレッシュ状態
struct JwksCacheRefreshState {
    /// 最後にリフレッシュした時刻
    last_refreshed_at: Option<Instant>,
    /// リフレッシュ中かどうか
    refreshing: bool,
    /// リフレッシュ完了を待機しているタスクを通知するためのNotify
    notify: Arc<Notify>,
}

impl JwksCacheRefreshState {
    fn default() -> Self {
        Self {
            last_refreshed_at: None,
            refreshing: false,
            notify: Arc::new(Notify::new()),
        }
    }
}

/// テナントごとのJWK公開鍵キャッシュのリフレッシュ状態を保持するハッシュマップ
type TenantJwksCacheRefreshStates = HashMap<TenantId, JwksCacheRefreshState>;

/// テナントごとのJWK公開鍵のキャッシュ
struct JwksCache {
    /// テナントごとのJWK公開鍵キャッシュ
    entries: RwLock<TenantJwksCache>,
    /// テナントごとのJWK公開鍵キャッシュのリフレッシュ状態
    refresh_states: Mutex<TenantJwksCacheRefreshStates>,
    /// JWK公開鍵キャッシュのTTL
    ttl: Duration,
}

/// Bearerトークン
#[derive(Clone)]
pub struct BearerToken(pub SecretString);

/// Entra IDトークン検証者
pub struct EntraIdTokenVerifier {
    /// テナントレジストリ
    registry: TenantRegistry,
    /// JwKsプロバイダ
    provider: JwksProvider,
    /// JWK公開鍵キャッシュ
    cache: JwksCache,
    /// バックグラウンドで定期的に、すべてのテナントのキャッシュされたJWK公開鍵をリフレッシュする間隔
    refresh_jwks_interval: Duration,
    /// テナントのキャッシュされたJWK公開鍵がリフレッシュされてから、次にリフレッシュされるまでの最小時間
    refresh_tenant_jwks_interval: Duration,
    /// バックグラウンドタスクを停止するためのキャンセルトークン
    shutdown: CancellationToken,
}

impl EntraIdTokenVerifier {
    /// コンストラクタ
    ///
    /// # Arguments
    ///
    /// * `tenants` - テナントのリスト
    /// * `jwk_cache_ttl` - キャッシュしたJWK公開鍵のTTL
    /// * `refresh_jwks_interval` - 定期的にバックグラウンドですべてのテナントのJWK公開鍵をリフレッシュする間隔（秒）
    /// * `refresh_tenant_jwks_interval`
    ///   - kidを基にテナントのJWK公開鍵を得られなかったときに、そのテナントのJWK公開鍵が最後にリフレッシュされてから、
    ///     次にリフレッシュするまでの最小時間
    /// * `entra_id_connection_timeout` - Entra IDのJWKsエンドポイントに接続する際のタイムアウト
    /// * `entra_id_timeout` - Entra IDのJWKsエンドポイントからの応答を待つタイムアウト
    /// * `jwks_request_max_attempts`
    ///     - Entra IDのJWKsエンドポイントからレスポンスが返ってくるまでリクエストする最大試行回数
    /// * `jwks_request_retry_initial_wait`
    ///     - Entra IDのJWKsエンドポイントに最初に再試行リクエストを送信するまでの待機する時間
    /// * `jwks_request_retry_backoff_multiplier`
    ///     - Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する時間を増加させる乗数
    /// * `jwks_request_retry_max_wait`
    ///    - Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する最大時間
    /// * `shutdown` - バックグラウンドタスクを停止するためのキャンセルトークン
    #[allow(clippy::too_many_arguments)]
    async fn new(
        tenants: Vec<Tenant>,
        jwk_cache_ttl: Duration,
        refresh_jwks_interval: Duration,
        refresh_tenant_jwks_interval: Duration,
        entra_id_connection_timeout: Duration,
        entra_id_timeout: Duration,
        jwks_request_max_attempts: u32,
        jwks_request_retry_initial_wait: Duration,
        jwks_request_retry_backoff_multiplier: f64,
        jwks_request_retry_max_wait: Duration,
        shutdown: CancellationToken,
    ) -> EntraIdResult<Arc<Self>> {
        let mut tenant_registry = TenantRegistry::new();
        for tenant in tenants.into_iter() {
            tenant_registry.insert(tenant.id.clone(), tenant);
        }

        let provider = JwksProvider::new(
            entra_id_connection_timeout,
            entra_id_timeout,
            jwks_request_max_attempts,
            jwks_request_retry_initial_wait,
            jwks_request_retry_backoff_multiplier,
            jwks_request_retry_max_wait,
        )?;

        let mut tenant_jwks_cache = TenantJwksCache::new();
        let mut tenant_refresh_states = HashMap::new();
        for (tenant_id, tenant) in &tenant_registry {
            // 初期化時はJWKs取得に失敗したら起動させない（fail-fast）
            let jwks = provider.fetch_jwks(&tenant.uri).await?;
            let cached_jwks: Vec<CachedJwk> = jwks.keys.into_iter().map(|key| key.into()).collect();
            let mut cached_jwk_map = CachedJwkMap::new();
            for cached_jwk in cached_jwks {
                cached_jwk_map.insert(Kid(cached_jwk.jwk.kid.clone()), cached_jwk);
            }
            tenant_jwks_cache.insert(tenant_id.clone(), cached_jwk_map);
            tenant_refresh_states.insert(tenant_id.clone(), JwksCacheRefreshState::default());
        }
        let cache = JwksCache {
            entries: RwLock::new(tenant_jwks_cache),
            ttl: jwk_cache_ttl,
            refresh_states: Mutex::new(tenant_refresh_states),
        };
        let instance = Arc::new(Self {
            registry: tenant_registry,
            provider,
            cache,
            refresh_jwks_interval,
            refresh_tenant_jwks_interval,
            shutdown,
        });
        let cloned = Arc::clone(&instance);
        cloned.refresh_jwks_cache_periodically().await?;

        Ok(instance)
    }

    /// 指定したテナントIDとキーIDに対応する復号鍵を検索する。
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - テナントID
    /// * `key_id` - キーID（kid）
    ///
    /// # Returns
    ///
    /// * 見つかった場合は公開鍵、見つからなかった場合はNone
    async fn find_decoding_key(&self, tenant_id: &TenantId, key_id: &Kid) -> Option<DecodingKey> {
        let cache = self.cache.entries.read().await;
        let cached_jwk_map = cache.get(tenant_id)?;
        let cached_jwk = cached_jwk_map.get(key_id)?;
        decoding_key_from_jwk(&cached_jwk.jwk).ok()
    }

    /// 指定したテナントIDとJWK公開鍵のキーIDに対応するDecodingKeyを返す。
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - テナントID
    /// * `key_id` - JWK公開鍵のキーID（kid）
    ///
    /// # Returns
    ///
    /// * JWK公開鍵、またはエラー
    async fn get_decoding_key(
        &self,
        tenant_id: &TenantId,
        key_id: &Kid,
    ) -> EntraIdResult<DecodingKey> {
        // テナントIDとキーのIDからJWK公開鍵を取得
        if let Some(key) = self.find_decoding_key(tenant_id, key_id).await {
            return Ok(key);
        }

        // JWK公開鍵を得られなかった場合は、テナントのJWK公開鍵キャッシュを条件付きでリフレッシュ
        // リフレッシュに失敗しても無視して、再度JWK公開鍵を取得を試行
        let _ = self.maybe_refresh_tenant_jwks_cache(tenant_id).await;

        // 再度、テナントIDとJWK公開鍵のキーのIDからJWK公開鍵を取得
        self.find_decoding_key(tenant_id, key_id)
            .await
            .ok_or_else(|| {
                EntraIdError::DecodingKeyNotFound(format!(
                    "DecodingKey not found for tenant_id: {}, key_id: {}",
                    tenant_id, key_id
                ))
            })
    }

    /// 指定したテナントIDのJWK公開鍵を取得して、既存のキャッシュに追加する。
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - テナントID
    ///
    /// # Notes
    ///
    /// このメソッドは、新たにテナントのJWK公開鍵を取得し、既存のキャッシュに同じ`kid`を持つJWK公開鍵が存在する場合は、
    /// `last_seen_at`を更新し、存在しない場合はキャッシュに追加する。
    ///
    /// したがって、既存のキャッシュに古いJWK公開鍵があっても、それらは削除されない。
    ///
    /// 古いJWK公開鍵の削除は、バックグラウンドで実行することを想定した`refresh_jwks_cache_periodically`メソッド
    /// から呼び出される`cleanup_expired_jwks_cache`メソッドで行われる。
    async fn refresh_tenant_jwks_cache(&self, tenant_id: &TenantId) -> EntraIdResult<()> {
        // テナント情報を取得
        let tenant = self
            .registry
            .get(tenant_id)
            .ok_or_else(|| EntraIdError::TenantNotFound(tenant_id.clone()))?;

        // テナントのJWK公開鍵をフェッチ
        let fetched = self.provider.fetch_jwks(&tenant.uri).await?;

        // 取得したJWK公開鍵が、既存のキャッシュに存在するかを確認し、存在する場合は`last_seen_at`を更新し、
        // 存在しない場合はキャッシュに追加
        let now = Instant::now();
        let mut cache = self.cache.entries.write().await;
        let cached_jwk_map = cache.get_mut(tenant_id).unwrap(); // 存在確認済み
        for key in fetched.keys {
            cached_jwk_map
                .entry(Kid(key.kid.clone()))
                .and_modify(|managed| {
                    managed.last_seen_at = now;
                })
                .or_insert(CachedJwk {
                    jwk: key,
                    last_seen_at: now,
                });
        }
        Ok(())
    }

    /// 指定したテナントのJWK公開鍵を条件付きでリフレッシュする。
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - テナントID
    ///
    /// # Notes
    ///
    /// 指定したテナントのJWK公開鍵が、最後にリフレッシュされてから`refresh_tenant_jwks_interval`を超えていなければ、
    /// リフレッシュ頻度が多くなることを避けるため、リフレッシュしない。
    ///
    /// 現在のスレッドが、指定したテナントのJWK公開鍵をリフレッシュ中であることを確認した場合、他のスレッドがリフレッシュを
    /// 完了するまで待機する。
    ///
    /// 現在のスレッドが、指定したテナントのJWK公開鍵をリフレッシュ中出ないことを確認した場合、リフレッシュフラグを成立させる
    /// ことで、現在のスレッドが他のスレッドを待機させた後、リフレッシュする。
    /// JWK公開鍵のリフレッシュが終了したとき、成功または失敗をにかかわらず、リフレッシュフラグを解除し、他のスレッドに通知して
    /// 待機を解除する。
    async fn maybe_refresh_tenant_jwks_cache(&self, tenant_id: &TenantId) -> EntraIdResult<()> {
        let now = Instant::now();

        let mut states = self.cache.refresh_states.lock().await;
        let state = states
            .entry(tenant_id.clone())
            .or_insert(JwksCacheRefreshState::default());

        // 最後にリフレッシュしてから、最小リフレッシュ間隔を超えていなければリフレッシュしない
        if let Some(last_refreshed_at) = state.last_refreshed_at
            && now.duration_since(last_refreshed_at) < self.refresh_tenant_jwks_interval
        {
            tracing::info!( tenant_id = %tenant_id, "Skip JWK refresh due to cool down");
            return Ok(());
        }

        if state.refreshing {
            // 現在リフレッシュしている場合は、他のスレッドがリフレッシュするまで待機
            let notify = state.notify.clone();
            drop(states); // ロック解放
            notify.notified().await;
            return Ok(());
        }

        // リフレッシュしていない場合は、このスレッドがリフレッシュを担当
        state.refreshing = true;
        drop(states); // ロック解放

        // テナントのJWK公開鍵キャッシュをリフレッシュ
        // 運用中のリフレッシュはベストエフォートとし、失敗しても処理を継続
        let result = self.refresh_tenant_jwks_cache(tenant_id).await;
        let last_refreshed_at = if result.is_ok() {
            Some(Instant::now())
        } else {
            None
        };

        // リフレッシュを実行
        let mut states = self.cache.refresh_states.lock().await;

        // リフレッシュ処理が終了したため、リフレッシュ中でない状態に変更した後、他のスレッドに通知して待機を解除
        let state = states.get_mut(tenant_id).unwrap();
        state.refreshing = false;
        state.notify.notify_waiters();
        // リフレッシュに成功した場合は、最後にリフレッシュした時刻を更新
        if last_refreshed_at.is_some() {
            state.last_refreshed_at = last_refreshed_at;
        }
        result
    }

    /// JWK公開鍵を最後に確認した時刻が、指定された時間を超えた場合、そのJWK公開鍵をキャッシュから削除する。
    ///
    /// # Notes
    ///
    /// TTLを超過した場合でも、テナントで`last_seen_at`が最も新しいJWK公開鍵は最低1つ残す。
    async fn cleanup_expired_jwks_cache(&self) {
        let mut cache = self.cache.entries.write().await;
        let now = Instant::now();

        // テナントごとにJWK公開鍵のキャッシュを走査
        for (tenant_id, jwks) in cache.iter_mut() {
            // 現在キャッシュしているJWK公開鍵を保持
            let mut original = std::mem::take(jwks);
            // 現在キャッシュしているJWK公開鍵からTTLを超えていないJWK公開鍵を取得
            let mut retained: CachedJwkMap = original
                .drain()
                .filter(|(_, jwk)| now.duration_since(jwk.last_seen_at) < self.cache.ttl)
                .collect();
            // テナントのJWK公開鍵がすべて削除されないようにする安全策として、 テナントにTTLを超えていないJWK公開鍵が存在せず、
            // 現在のキャッシュにそのテナントのJWK公開鍵が存在する場合、last_seen_atが最も新しいJWK公開鍵を1つ残す
            if retained.is_empty()
                && let Some((kid, jwk)) =
                    original.into_iter().max_by_key(|(_, jwk)| jwk.last_seen_at)
            {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    kid = %kid,
                    "All JWKs expired by TTL, retaining the most recent one as a safety measures"
                );
                retained.insert(kid, jwk);
            }
            *jwks = retained;
        }
    }

    /// バックグラウンドで定期的にJWK公開鍵をリフレッシュするタスクを起動する。
    async fn refresh_jwks_cache_periodically(self: Arc<Self>) -> EntraIdResult<()> {
        let mut interval = tokio::time::interval(self.refresh_jwks_interval);
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        tracing::info!("JWKs refresh task is shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::info!("Refresh all tenants JWKs cache");
                        // すべてのテナントについて、キャッシュしているJWK公開鍵をリフレッシュ
                        for tenant_id in self.registry.keys() {
                            if let Err(e) = self.maybe_refresh_tenant_jwks_cache(tenant_id).await {
                                tracing::warn!(tenant_id = %tenant_id, error = %e, "Error refreshing JWKs for tenant");
                            }
                        }
                        // TTLを超えたJWK公開鍵をキャッシュから削除
                        tracing::info!("Cleanup expired JWKs cache");
                        self.cleanup_expired_jwks_cache().await;
                    }
                }
            }
        });

        Ok(())
    }

    /// JWTを検証する。
    ///
    /// # Arguments
    ///
    /// * `token` - 検証するJWT
    /// * `jwks` - Entra IDから取得したJWK公開鍵セット
    ///
    /// # Returns
    ///
    /// * 検証に成功した場合は検証に成功したJWTから取得したクレーム
    pub async fn verify_token(&self, token: &BearerToken) -> EntraIdResult<Claims> {
        // JWTヘッダーをデコードしてkidを取得
        // このkidを信用してはならない。あくまでJWK公開鍵を特定するために使用するだけ。
        let header =
            decode_header(token.0.expose_secret()).map_err(EntraIdError::TokenHeaderDecodeError)?;
        let kid = header.kid.ok_or_else(|| {
            EntraIdError::TokenHeaderMissingKid("JWT header missing 'kid'".into())
        })?;

        // Entra IDはRS256以外のRSA署名アルゴリズムをサポートしていない。
        // ヘッダに記録されているアルゴリズムは信用してはならないため検証する。
        if header.alg != Algorithm::RS256 {
            return Err(EntraIdError::UnsupportedTokenAlgorithm(header.alg));
        }

        // JWTペイロードをデコードしてiss、audおよびtidを取得
        let unverified_claims = extract_payload(token)?;

        // JWTのペイロード部分をデコードして発行者を特定
        let issuer = specify_issuer(&unverified_claims)?;
        let tenant_id = if let IssuerTenant::Tenant(tenant_id) = issuer {
            tenant_id
        } else {
            return Err(EntraIdError::DisallowedIssuerTenant(issuer));
        };

        // テナントレジストリからテナントを取得
        let tenant = self
            .registry
            .get(&tenant_id)
            .ok_or_else(|| EntraIdError::TenantNotFound(tenant_id.clone()))?;

        // JWK公開鍵セットからkidに対応するJWK公開鍵を取得
        let kid = Kid(kid);
        let decoding_key = self.get_decoding_key(&tenant_id, &kid).await?;

        // 検証パラメーターを設定
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&tenant.audience]);
        validation.set_issuer(&[&tenant.issuer]);

        // デコードと検証
        let token_data = decode::<Claims>(token.0.expose_secret(), &decoding_key, &validation)
            .map_err(|_| EntraIdError::VerifyTokenError)?;
        Ok(token_data.claims)
    }
}

/// Entra IDトークン検証者ビルダー
#[derive(Default)]
pub struct EntraIdTokenVerifierBuilder {
    tenants: Option<Vec<Tenant>>,
    jwk_cache_ttl: Option<Duration>,
    refresh_jwks_interval: Option<Duration>,
    refresh_tenant_jwks_interval: Option<Duration>,
    entra_id_connection_timeout: Option<Duration>,
    entra_id_timeout: Option<Duration>,
    jwks_request_max_attempts: Option<u32>,
    jwks_request_retry_initial_wait: Option<Duration>,
    jwks_request_retry_backoff_multiplier: Option<f64>,
    jwks_request_retry_max_wait: Option<Duration>,
    shutdown: Option<CancellationToken>,
}

impl From<&str> for EntraIdError {
    fn from(s: &str) -> Self {
        EntraIdError::InitializeError(s.into())
    }
}

impl EntraIdTokenVerifierBuilder {
    /// テナントを設定する。
    ///
    /// # Arguments
    ///
    /// * `tenants` - テナントのリスト
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn tenants(mut self, tenants: Vec<Tenant>) -> EntraIdResult<Self> {
        if tenants.is_empty() {
            return Err("Tenants list cannot be empty".into());
        }
        self.tenants = Some(tenants);
        Ok(self)
    }

    /// JWK公開鍵キャッシュのTTLを設定する。
    ///
    /// # Arguments
    ///
    /// * `ttl` - JWK公開鍵キャッシュのTTL
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn jwk_cache_ttl(mut self, ttl: Duration) -> EntraIdResult<Self> {
        if ttl.is_zero() {
            return Err("JWK cache TTL must be greater than zero".into());
        }
        self.jwk_cache_ttl = Some(ttl);
        Ok(self)
    }

    /// 定期的にバックグラウンドですべてのテナントのJWK公開鍵をリフレッシュする間隔を設定する。
    ///
    /// # Arguments
    ///
    /// * `interval` - JWK公開鍵リフレッシュ間隔
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn refresh_jwks_interval(mut self, interval: Duration) -> EntraIdResult<Self> {
        if interval.is_zero() {
            return Err("Refresh JWKs interval must be greater than zero".into());
        }
        self.refresh_jwks_interval = Some(interval);
        Ok(self)
    }

    /// テナントのJWK公開鍵がリフレッシュされてから、次にリフレッシュされるまでの最小時間を設定する。
    ///
    /// # Arguments
    ///
    /// * `interval` - テナントJWK公開鍵リフレッシュ最小間隔
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn refresh_tenant_jwks_interval(mut self, interval: Duration) -> EntraIdResult<Self> {
        if interval.is_zero() {
            return Err("Refresh tenant JWKs interval must be greater than zero".into());
        }
        self.refresh_tenant_jwks_interval = Some(interval);
        Ok(self)
    }

    /// Entra IDのJWKsエンドポイントに接続する際のタイムアウトを設定する。
    ///
    /// # Arguments
    ///
    /// * `timeout` - 接続タイムアウト
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn entra_id_connection_timeout(mut self, timeout: Duration) -> EntraIdResult<Self> {
        if timeout.is_zero() {
            return Err("Entra ID connection timeout must be greater than zero".into());
        }
        self.entra_id_connection_timeout = Some(timeout);
        Ok(self)
    }

    /// Entra IDのJWKsエンドポイントからの応答を待つタイムアウトを設定する。
    ///
    /// # Arguments
    ///
    /// * `timeout` - 応答待機タイムアウト
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn entra_id_timeout(mut self, timeout: Duration) -> EntraIdResult<Self> {
        if timeout.is_zero() {
            return Err("Entra ID timeout must be greater than zero".into());
        }
        self.entra_id_timeout = Some(timeout);
        Ok(self)
    }

    /// Entra IDのJWKsエンドポイントからレスポンスが返ってくるまでリクエストする最大試行回数を設定する。
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - 最大試行回数
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn jwks_request_max_attempts(mut self, max_attempts: u32) -> EntraIdResult<Self> {
        if max_attempts == 0 {
            return Err("JWKs request max attempts must be greater than zero".into());
        }
        self.jwks_request_max_attempts = Some(max_attempts);
        Ok(self)
    }

    /// Entra IDのJWKsエンドポイントに最初に再試行リクエストを送信するまでの待機する時間を設定する。
    ///
    /// # Arguments
    ///
    /// * `initial_wait` - 最初の待機時間
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn jwks_request_retry_initial_wait(mut self, initial_wait: Duration) -> Self {
        self.jwks_request_retry_initial_wait = Some(initial_wait);
        self
    }

    /// Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する時間を増加させる乗数を設定する。
    ///
    /// # Arguments
    ///
    /// * `multiplier` - 待機時間増加乗数
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn jwks_request_retry_backoff_multiplier(mut self, multiplier: f64) -> EntraIdResult<Self> {
        if multiplier < 1.0 {
            return Err("JWKs request retry backoff multiplier must be at least 1.0".into());
        }
        self.jwks_request_retry_backoff_multiplier = Some(multiplier);
        Ok(self)
    }

    /// Entra IDのJWKsエンドポイントに再試行リクエストを送信するまでに待機する最大時間を設定する。
    ///
    /// # Arguments
    ///
    /// * `max_wait` - 最大待機時間
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn jwks_request_retry_max_wait(mut self, max_wait: Duration) -> EntraIdResult<Self> {
        if max_wait.is_zero() {
            return Err("JWKs request retry max wait must be greater than zero".into());
        }
        self.jwks_request_retry_max_wait = Some(max_wait);
        Ok(self)
    }

    /// バックグラウンドタスクを停止するためのキャンセルトークンを設定する。
    ///
    /// # Arguments
    ///
    /// * `shutdown` - キャンセルトークン
    ///
    /// # Returns
    ///
    /// * 自身のインスタンス
    pub fn shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Entra IDトークン検証者を構築する。
    ///
    /// # Returns
    ///
    /// * Entra IDトークン検証者、またはエラー
    pub async fn build(self) -> EntraIdResult<Arc<EntraIdTokenVerifier>> {
        let tenants = self
            .tenants
            .ok_or_else(|| EntraIdError::InitializeError("Tenants list is not set".into()))?;
        let jwk_cache_ttl = self
            .jwk_cache_ttl
            .ok_or_else(|| EntraIdError::InitializeError("JWK cache TTL is not set".into()))?;
        let refresh_jwks_interval = self.refresh_jwks_interval.ok_or_else(|| {
            EntraIdError::InitializeError("Refresh JWKs interval is not set".into())
        })?;
        let refresh_tenant_jwks_interval = self.refresh_tenant_jwks_interval.ok_or_else(|| {
            EntraIdError::InitializeError("Refresh tenant JWKs interval is not set".into())
        })?;
        let entra_id_connection_timeout = self.entra_id_connection_timeout.ok_or_else(|| {
            EntraIdError::InitializeError("Entra ID connection timeout is not set".into())
        })?;
        let entra_id_timeout = self
            .entra_id_timeout
            .ok_or_else(|| EntraIdError::InitializeError("Entra ID timeout is not set".into()))?;
        let jwks_request_max_attempts = self.jwks_request_max_attempts.ok_or_else(|| {
            EntraIdError::InitializeError("JWKs request max attempts is not set".into())
        })?;
        let jwks_request_retry_initial_wait =
            self.jwks_request_retry_initial_wait.ok_or_else(|| {
                EntraIdError::InitializeError("JWKs request retry initial wait is not set".into())
            })?;
        let jwks_request_retry_backoff_multiplier =
            self.jwks_request_retry_backoff_multiplier.ok_or_else(|| {
                EntraIdError::InitializeError(
                    "JWKs request retry backoff multiplier is not set".into(),
                )
            })?;
        let jwks_request_retry_max_wait = self.jwks_request_retry_max_wait.ok_or_else(|| {
            EntraIdError::InitializeError("JWKs request retry max wait is not set".into())
        })?;
        let shutdown = self
            .shutdown
            .ok_or_else(|| EntraIdError::InitializeError("Shutdown token is not set".into()))?;
        EntraIdTokenVerifier::new(
            tenants,
            jwk_cache_ttl,
            refresh_jwks_interval,
            refresh_tenant_jwks_interval,
            entra_id_connection_timeout,
            entra_id_timeout,
            jwks_request_max_attempts,
            jwks_request_retry_initial_wait,
            jwks_request_retry_backoff_multiplier,
            jwks_request_retry_max_wait,
            shutdown,
        )
        .await
    }
}

/// JWK公開鍵から復号鍵を取得する。
///
/// # Arguments
///
/// * `jwk` - JWK公開鍵
///
/// # Returns
///
/// * 復号鍵、またはエラー
fn decoding_key_from_jwk(jwk: &Jwk) -> EntraIdResult<DecodingKey> {
    DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| EntraIdError::CreateDecodingKeyError(Kid(jwk.kid.clone()), e))
}

/// JWTのペイロード部分をデコードした検証されていないクレーム
#[derive(Deserialize)]
struct UnverifiedClaims {
    /// 発行者（issuer）
    iss: String,
    /// テナントID
    tid: Option<String>,
}

/// JWTのペイロード部分をデコードして検証されていないクレームを抽出する。
fn extract_payload(token: &BearerToken) -> EntraIdResult<UnverifiedClaims> {
    let parts: Vec<&str> = token.0.expose_secret().split('.').collect();
    if parts.len() != 3 {
        return Err(EntraIdError::InvalidTokenFormat(
            "Invalid JWT format".into(),
        ));
    }

    let payload = parts[1];
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(EntraIdError::TokenPayloadDecodeError)?;

    serde_json::from_slice(&decoded).map_err(EntraIdError::TokenPayloadParseError)
}

/// 発行者（issuer）に基づいてテナントを識別する列挙型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerTenant {
    Tenant(TenantId),
    Organizations,
    Common,
}

impl std::fmt::Display for IssuerTenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerTenant::Tenant(tenant_id) => write!(f, "{}", tenant_id),
            IssuerTenant::Organizations => write!(f, "organizations"),
            IssuerTenant::Common => write!(f, "common"),
        }
    }
}

fn specify_issuer(unverified_claims: &UnverifiedClaims) -> EntraIdResult<IssuerTenant> {
    // tidが記録されていれば、それがテナントID
    if let Some(tid) = unverified_claims.tid.as_ref() {
        return Ok(IssuerTenant::Tenant(TenantId(tid.clone())));
    }
    // issからテナントIDを抽出
    // iss: https://login.microsoftonline.com/{tenant-id}/v2.0
    let tenant_id = extract_issuer_from_iss(&unverified_claims.iss)?;
    Ok(IssuerTenant::Tenant(tenant_id))
}

pub fn extract_issuer_from_iss(iss: &str) -> EntraIdResult<TenantId> {
    // issからテナントIDを抽出
    // iss: https://login.microsoftonline.com/{tenant-id}/v2.0
    let uri = Url::parse(iss).map_err(EntraIdError::TokenMissingIssuer)?;

    let mut segments = uri
        .path_segments()
        .ok_or(EntraIdError::InvalidIssuerFormat(
            "No path segments in iss".into(),
        ))?;
    let first = segments.next().ok_or(EntraIdError::InvalidIssuerFormat(
        "Empty path in iss".into(),
    ))?;
    match first {
        "common" => Err(EntraIdError::DisallowedIssuerTenant(IssuerTenant::Common)),
        "organizations" => Err(EntraIdError::DisallowedIssuerTenant(
            IssuerTenant::Organizations,
        )),
        tenant_id => Ok(TenantId(tenant_id.to_string())),
    }
}
