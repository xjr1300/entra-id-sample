use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use url::Url;

pub type EntraIdResult<T> = Result<T, EntraIdError>;

#[derive(Debug, thiserror::Error)]
pub enum EntraIdError {
    /// 指定したテナントのJWK公開鍵セットの取得に失敗
    #[error("Failed to fetch JWKs from {0}")]
    JwksFetchError(Url),

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
#[derive(Deserialize)]
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub exp: usize,
    pub oid: String,
    pub sub: String,
    pub preferred_username: Option<String>,
    pub scp: Option<String>,
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

/// テナントごとにキャッシュしたJWK公開鍵セットを提供
#[derive(Clone)]
struct JwksProvider {
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

impl JwksProvider {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    async fn fetch(&self, jwks_uri: &Url) -> EntraIdResult<JwksResponse> {
        let response = self
            .client
            .get(jwks_uri.to_string())
            .send()
            .await
            .map_err(|_| EntraIdError::JwksFetchError(jwks_uri.clone()))?;
        response
            .json::<JwksResponse>()
            .await
            .map_err(|e| EntraIdError::JwksResponseParseError(jwks_uri.clone(), e))
    }
}

struct TenantRefreshState {
    last_refreshed_at: Option<Instant>,
    refreshing: bool,
}

struct JwksCache {
    /// テナントごとのJWK公開鍵キャッシュ
    entries: RwLock<TenantJwksCache>,
    /// JWK公開鍵キャッシュのTTL
    ttl: Duration,
    /// JWK公開鍵キャッシュのリフレッシュ状態
    refresh_states: Mutex<HashMap<TenantId, TenantRefreshState>>,
    /// JWK公開鍵キャッシュのリフレッシュ間隔
    refresh_interval: Duration,
}

/// JWK公開鍵キャッシュのリフレッシュ結果
///
/// `EntraIdTokenVerifier::self.maybe_refresh_tenant_jwks_cache`メソッドの正常系の`Ok`バリアントで使用する。
/// 上記メソッドの失敗系は`Err(AppError)`で表現する。
enum JwksCacheRefreshResult {
    /// リフレッシュ中
    Refreshing,
    /// 最近リフレッシュされた
    RecentlyRefreshed,
    /// リフレッシュした
    Refreshed,
}

/// Bearerトークン
pub struct BearerToken(pub SecretString);

pub struct EntraIdTokenVerifier {
    /// テナントレジストリ
    registry: TenantRegistry,
    /// JwKsプロバイダ
    provider: JwksProvider,
    /// JWK公開鍵キャッシュ
    cache: JwksCache,
    /// JWK公開鍵を定期的に更新する間隔
    refresh_jwk_interval: Duration,
    /// JWK公開鍵をリフレッシュしているときに処理を遅延させる時間
    jwks_refresh_retry_delay: Duration,
    /// バックグラウンドタスクを停止するためのキャンセルトークン
    shutdown: CancellationToken,
}

impl EntraIdTokenVerifier {
    /// コンストラクタ
    ///
    /// # Arguments
    ///
    /// * `tenants` - テナントのリスト
    /// * `jwk_cache_ttl` - JWK公開鍵キャッシュのTTL
    /// * `refresh_tenant_jwk_cache_interval` - 各テナントのキャッシュしたJWK公開鍵を定期的に更新する間隔
    /// * `refresh_all_tenant_jwk_cache_interval` - すべてのテナントのキャッシュしたJWK公開鍵を定期的に更新する間隔
    /// * `jwks_refresh_retry_delay` - JWK公開鍵をリフレッシュしているときに処理を遅延させる時間
    /// * `shutdown` - バックグラウンドタスクを停止するためのキャンセルトークン
    pub async fn new(
        tenants: Vec<Tenant>,
        jwk_cache_ttl: Duration,
        refresh_tenant_jwk_cache_interval: Duration,
        refresh_all_tenants_jwk_cache_interval: Duration,
        jwks_refresh_retry_delay: Duration,
        shutdown: CancellationToken,
    ) -> EntraIdResult<Arc<Self>> {
        let mut tenant_registry = TenantRegistry::new();
        for tenant in tenants.into_iter() {
            tenant_registry.insert(tenant.id.clone(), tenant);
        }

        let provider = JwksProvider::default();

        let mut tenant_jwks_cach = TenantJwksCache::new();
        let mut tenant_refresh_states = HashMap::new();
        for (tenant_id, tenant) in &tenant_registry {
            let jwks = provider.fetch(&tenant.uri).await?;
            let cached_jwks: Vec<CachedJwk> = jwks.keys.into_iter().map(|key| key.into()).collect();
            let mut cached_jwk_map = CachedJwkMap::new();
            for cached_jwk in cached_jwks {
                cached_jwk_map.insert(Kid(cached_jwk.jwk.kid.clone()), cached_jwk);
            }
            tenant_jwks_cach.insert(tenant_id.clone(), cached_jwk_map);
            tenant_refresh_states.insert(
                tenant_id.clone(),
                TenantRefreshState {
                    last_refreshed_at: None,
                    refreshing: false,
                },
            );
        }
        let cache = JwksCache {
            entries: RwLock::new(tenant_jwks_cach),
            ttl: jwk_cache_ttl,
            refresh_states: Mutex::new(tenant_refresh_states),
            refresh_interval: refresh_tenant_jwk_cache_interval,
        };
        let instance = Arc::new(Self {
            registry: tenant_registry,
            provider,
            cache,
            refresh_jwk_interval: refresh_all_tenants_jwk_cache_interval,
            jwks_refresh_retry_delay,
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

        // JWK公開鍵をえられなかった場合は、テナントのJWK公開鍵キャッシュを条件付きで更新
        match self.maybe_refresh_tenant_jwks_cache(tenant_id).await {
            Ok(result) => match result {
                JwksCacheRefreshResult::Refreshing => {
                    tracing::info!(
                        "JWK cache is already refreshing for tenant_id: {}",
                        tenant_id
                    );
                    tokio::time::sleep(self.jwks_refresh_retry_delay).await;
                }
                JwksCacheRefreshResult::RecentlyRefreshed => {
                    tracing::info!(
                        "JWK cache was recently refreshed for tenant_id: {}",
                        tenant_id
                    );
                }
                JwksCacheRefreshResult::Refreshed => {
                    tracing::info!("JWK cache refreshed for tenant_id: {}", tenant_id);
                }
            },
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Error refreshing JWK cache for tenant_id: {}",
                    tenant_id
                );
            }
        }

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

    async fn maybe_refresh_tenant_jwks_cache(
        &self,
        tenant_id: &TenantId,
    ) -> EntraIdResult<JwksCacheRefreshResult> {
        let mut states = self.cache.refresh_states.lock().await;
        let state = states
            .entry(tenant_id.clone())
            .or_insert(TenantRefreshState {
                last_refreshed_at: None,
                refreshing: false,
            });

        let now = Instant::now();

        // 現在リフレッシュしている場合は待機して終了
        if state.refreshing {
            drop(states);
            return Ok(JwksCacheRefreshResult::Refreshing);
        }

        // 直近でリフレッシュ済みの場合は終了
        if let Some(last) = state.last_refreshed_at
            && now.duration_since(last) < self.cache.refresh_interval
        {
            return Ok(JwksCacheRefreshResult::RecentlyRefreshed);
        }

        // リフレッシュ開始
        state.refreshing = true;
        drop(states); // ロック解放

        let result = self.refresh_tenant_jwks_cache(tenant_id).await;

        // リフレッシュ終了
        let mut states = self.cache.refresh_states.lock().await;
        let state = states.get_mut(tenant_id).unwrap();
        state.refreshing = false;
        if result.is_ok() {
            state.last_refreshed_at = Some(Instant::now());
        }
        result.map(|_| JwksCacheRefreshResult::Refreshed)
    }

    /// 指定したテナントIDのJWK公開鍵セットを更新する。
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - テナントID
    async fn refresh_tenant_jwks_cache(&self, tenant_id: &TenantId) -> EntraIdResult<()> {
        // テナント情報を取得
        let tenant = self
            .registry
            .get(tenant_id)
            .ok_or_else(|| EntraIdError::TenantNotFound(tenant_id.clone()))?;
        // テナントのJWK公開鍵セットをフェッチ
        let fetched = self.provider.fetch(&tenant.uri).await?;
        // 新しいJWK公開鍵をマージ
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

    /// すべてのテナントのJWK公開鍵セットを更新する。
    pub async fn refresh_all_tenants_jwks_cache(&self) -> EntraIdResult<()> {
        for tenant_id in self.registry.keys() {
            if let Err(e) = self.refresh_tenant_jwks_cache(tenant_id).await {
                tracing::warn!(tenant_id = %tenant_id, error = %e, "Failed to refresh JWK cache for tenant");
            }
        }
        Ok(())
    }

    /// 古くなったJWK公開鍵をキャッシュから削除する。
    ///
    /// ただし、TTLを超過した場合でも、テナントで`last_seen_at`が最も新しいJWK公開鍵は最低1つ残す。
    async fn cleanup_expired_jwks_cache(&self) {
        let mut cache = self.cache.entries.write().await;
        let now = Instant::now();

        for (tenant_id, cached_jwk_map) in cache.iter_mut() {
            // 現在キャッシュしているJWK公開鍵を保持
            let mut original = std::mem::take(cached_jwk_map);
            // 現在キャッシュしているJWK公開鍵からTTLを超えていないJWK公開鍵を取得
            let mut retained: CachedJwkMap = original
                .drain()
                .filter(|(_, cached_jwk)| {
                    now.duration_since(cached_jwk.last_seen_at) < self.cache.ttl
                })
                .collect();
            // テナントのJWKがすべて削除されないようにする安全策として、 テナントにTTLを超えていないJWK公開鍵が存在せず、
            // 現在のキャッシュにJWK公開鍵が存在する場合、last_seen_atが最も新しいJWKを1つ残す
            if retained.is_empty()
                && let Some((kid, jwk)) = original
                    .into_iter()
                    .max_by_key(|(_, cached_jwk)| cached_jwk.last_seen_at)
            {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    kid = %kid,
                    "All JWKs expired by TTL, retaining the most recent one as a safety measures"
                );
                retained.insert(kid, jwk);
            }
            *cached_jwk_map = retained;
        }
    }

    /// バックグラウンドで定期的にJWK公開鍵を更新するタスクを起動する。
    async fn refresh_jwks_cache_periodically(self: Arc<Self>) -> EntraIdResult<()> {
        let mut interval = tokio::time::interval(self.refresh_jwk_interval);
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        tracing::info!("JWK refresh task is shutting down.");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::info!("Refresh all tenants JWKs cache");
                        if let Err(e) = self.refresh_all_tenants_jwks_cache().await {
                            tracing::error!(error = %e, "Error refreshing JWKs");
                        }
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
#[allow(dead_code)]
#[derive(Deserialize)]
struct UnverifiedClaims {
    /// 発行者（issuer）
    iss: String,
    /// 購読者（audience）
    aud: String,
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
