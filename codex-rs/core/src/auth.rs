mod storage;

use chrono::Utc;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;
#[cfg(test)]
use serial_test::serial;
use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;

use codex_app_server_protocol::AuthMode;
use codex_protocol::config_types::ForcedLoginMethod;
use sha2::Digest;
use sha2::Sha256;

pub use crate::auth::storage::AuthCredentialsStoreMode;
pub use crate::auth::storage::AuthDotJson;
use crate::auth::storage::AuthStorageBackend;
use crate::auth::storage::ChatGptAuthEntry;
use crate::auth::storage::create_auth_storage;
use crate::config::Config;
use crate::error::RefreshTokenFailedError;
use crate::error::RefreshTokenFailedReason;
use crate::token_data::KnownPlan as InternalKnownPlan;
use crate::token_data::PlanType as InternalPlanType;
use crate::token_data::TokenData;
use crate::token_data::parse_id_token;
use crate::util::try_parse_error_message;
use codex_client::CodexHttpClient;
use codex_protocol::account::PlanType as AccountPlanType;
#[cfg(any(test, feature = "test-support"))]
use once_cell::sync::Lazy;
use serde_json::Value;
#[cfg(any(test, feature = "test-support"))]
use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CodexAuth {
    chatgpt_key: Option<ChatGptKey>,
    pub(crate) auth_dot_json: Arc<Mutex<Option<AuthDotJson>>>,
    storage: Arc<dyn AuthStorageBackend>,
    pub(crate) client: CodexHttpClient,
}

#[derive(Debug, Clone)]
pub enum Auth {
    ChatGpt { handle: CodexAuth },
    ApiKey { handle: ApiKeyAuth },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyAuth {
    api_key: String,
}

impl ApiKeyAuth {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }

    pub fn bearer_token(&self) -> String {
        self.api_key.clone()
    }

    pub fn as_str(&self) -> &str {
        self.api_key.as_str()
    }
}

impl Auth {
    pub fn mode(&self) -> AuthMode {
        match self {
            Self::ChatGpt { .. } => AuthMode::ChatGPT,
            Self::ApiKey { .. } => AuthMode::ApiKey,
        }
    }

    pub fn account_id(&self) -> Option<String> {
        match self {
            Self::ChatGpt { handle } => handle.get_account_id(),
            Self::ApiKey { .. } => None,
        }
    }

    pub fn account_email(&self) -> Option<String> {
        match self {
            Self::ChatGpt { handle } => handle.get_account_email(),
            Self::ApiKey { .. } => None,
        }
    }

    pub async fn bearer_token(&self) -> Result<String, std::io::Error> {
        match self {
            Self::ChatGpt { handle } => handle.get_token().await,
            Self::ApiKey { handle } => Ok(handle.bearer_token()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChatGptKey {
    account_id: String,
    chatgpt_user_id: String,
}

impl ChatGptKey {
    fn from_tokens(tokens: &TokenData) -> Option<Self> {
        let account_id = tokens
            .account_id
            .clone()
            .or_else(|| tokens.id_token.chatgpt_account_id.clone())?;
        let chatgpt_user_id = tokens.id_token.chatgpt_user_id.clone()?;
        Some(Self {
            account_id,
            chatgpt_user_id,
        })
    }
}

// TODO(pakrym): use token exp field to check for expiration instead
const TOKEN_REFRESH_INTERVAL: i64 = 8;

const REFRESH_TOKEN_EXPIRED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token has expired. Please log out and sign in again.";
const REFRESH_TOKEN_REUSED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again.";
const REFRESH_TOKEN_INVALIDATED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token was revoked. Please log out and sign in again.";
const REFRESH_TOKEN_UNKNOWN_MESSAGE: &str =
    "Your access token could not be refreshed. Please log out and sign in again.";
const REFRESH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR: &str = "CODEX_REFRESH_TOKEN_URL_OVERRIDE";

#[cfg(any(test, feature = "test-support"))]
static TEST_AUTH_TEMP_DIRS: Lazy<Mutex<Vec<TempDir>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Debug, Error)]
pub enum RefreshTokenError {
    #[error("{0}")]
    Permanent(#[from] RefreshTokenFailedError),
    #[error(transparent)]
    Transient(#[from] std::io::Error),
}

impl RefreshTokenError {
    pub fn failed_reason(&self) -> Option<RefreshTokenFailedReason> {
        match self {
            Self::Permanent(error) => Some(error.reason),
            Self::Transient(_) => None,
        }
    }
}

impl From<RefreshTokenError> for std::io::Error {
    fn from(err: RefreshTokenError) -> Self {
        match err {
            RefreshTokenError::Permanent(failed) => std::io::Error::other(failed),
            RefreshTokenError::Transient(inner) => inner,
        }
    }
}

fn account_plan_type_from_internal(plan: &InternalPlanType) -> AccountPlanType {
    match plan {
        InternalPlanType::Known(k) => match k {
            InternalKnownPlan::Free => AccountPlanType::Free,
            InternalKnownPlan::Plus => AccountPlanType::Plus,
            InternalKnownPlan::Pro => AccountPlanType::Pro,
            InternalKnownPlan::Team => AccountPlanType::Team,
            InternalKnownPlan::Business => AccountPlanType::Business,
            InternalKnownPlan::Enterprise => AccountPlanType::Enterprise,
            InternalKnownPlan::Edu => AccountPlanType::Edu,
        },
        InternalPlanType::Unknown(_) => AccountPlanType::Unknown,
    }
}

impl CodexAuth {
    pub async fn refresh_token(&self) -> Result<String, RefreshTokenError> {
        tracing::info!("Refreshing token");
        let updated = self.refresh_current_tokens(None).await?;
        Ok(updated.access_token)
    }

    async fn refresh_current_tokens(
        &self,
        timeout: Option<Duration>,
    ) -> Result<TokenData, RefreshTokenError> {
        let token_data = self.get_current_token_data().ok_or_else(|| {
            RefreshTokenError::Transient(std::io::Error::other("Token data is not available."))
        })?;

        let refresh = try_refresh_token(token_data.refresh_token.clone(), &self.client);
        let refresh_response = if let Some(timeout) = timeout {
            match tokio::time::timeout(timeout, refresh).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(RefreshTokenError::Transient(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "timed out while refreshing token",
                    )));
                }
            }
        } else {
            refresh.await?
        };
        let mut auth_dot_json = load_auth_dot_json_migrated(&self.storage)
            .map_err(RefreshTokenError::from)?
            .ok_or_else(|| {
                RefreshTokenError::Transient(std::io::Error::other("Token data is not available."))
            })?;

        let mut updated_tokens = token_data.clone();
        if let Some(id_token) = refresh_response.id_token {
            updated_tokens.id_token = parse_id_token(&id_token)
                .map_err(|err| RefreshTokenError::Transient(std::io::Error::other(err)))?;
            updated_tokens.account_id = updated_tokens
                .account_id
                .clone()
                .or_else(|| updated_tokens.id_token.chatgpt_account_id.clone());
        }
        if let Some(access_token) = refresh_response.access_token {
            updated_tokens.access_token = access_token;
        }
        if let Some(refresh_token) = refresh_response.refresh_token {
            updated_tokens.refresh_token = refresh_token;
        }

        let now = Utc::now();
        if self.chatgpt_key.is_some() {
            let entry = self
                .get_current_chatgpt_entry_mut(&mut auth_dot_json)
                .ok_or_else(|| {
                    RefreshTokenError::Transient(std::io::Error::other(
                        "Token data is not available.",
                    ))
                })?;
            entry.tokens = updated_tokens.clone();
            entry.last_refresh = Some(now);
        } else {
            auth_dot_json.tokens = Some(updated_tokens.clone());
            auth_dot_json.last_refresh = Some(now);
        }

        self.storage
            .save(&auth_dot_json)
            .map_err(RefreshTokenError::from)?;

        if let Ok(mut auth_lock) = self.auth_dot_json.lock() {
            *auth_lock = Some(auth_dot_json);
        }

        Ok(updated_tokens)
    }

    pub async fn get_token_data(&self) -> Result<TokenData, std::io::Error> {
        let auth_dot_json = self
            .get_current_auth_json()
            .ok_or(std::io::Error::other("Token data is not available."))?;

        let (tokens, last_refresh) =
            if let Some(entry) = self.get_current_chatgpt_entry(&auth_dot_json) {
                (entry.tokens.clone(), entry.last_refresh)
            } else {
                (
                    auth_dot_json
                        .tokens
                        .clone()
                        .ok_or(std::io::Error::other("Token data is not available."))?,
                    auth_dot_json.last_refresh,
                )
            };

        let Some(last_refresh) = last_refresh else {
            return Err(std::io::Error::other("Token data is not available."));
        };

        if last_refresh < Utc::now() - chrono::Duration::days(TOKEN_REFRESH_INTERVAL) {
            return self
                .refresh_current_tokens(Some(Duration::from_secs(60)))
                .await
                .map_err(std::io::Error::from);
        }

        Ok(tokens)
    }

    pub async fn get_token(&self) -> Result<String, std::io::Error> {
        Ok(self.get_token_data().await?.access_token)
    }

    pub fn get_account_id(&self) -> Option<String> {
        self.get_current_token_data().and_then(|t| t.account_id)
    }

    pub fn get_account_email(&self) -> Option<String> {
        self.get_current_token_data().and_then(|t| t.id_token.email)
    }

    /// Account-facing plan classification derived from the current token.
    /// Returns a high-level `AccountPlanType` (e.g., Free/Plus/Pro/Team/…)
    /// mapped from the ID token's internal plan value. Prefer this when you
    /// need to make UI or product decisions based on the user's subscription.
    pub fn account_plan_type(&self) -> Option<AccountPlanType> {
        self.get_current_token_data().and_then(|t| {
            t.id_token
                .chatgpt_plan_type
                .as_ref()
                .map(account_plan_type_from_internal)
        })
    }

    fn get_current_auth_json(&self) -> Option<AuthDotJson> {
        #[expect(clippy::unwrap_used)]
        self.auth_dot_json.lock().unwrap().clone()
    }

    fn get_current_chatgpt_entry<'a>(
        &self,
        auth_dot_json: &'a AuthDotJson,
    ) -> Option<&'a ChatGptAuthEntry> {
        let key = self.chatgpt_key.as_ref()?;
        auth_dot_json
            .chatgpt_entries
            .iter()
            .find(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *key))
    }

    fn get_current_chatgpt_entry_mut<'a>(
        &self,
        auth_dot_json: &'a mut AuthDotJson,
    ) -> Option<&'a mut ChatGptAuthEntry> {
        let key = self.chatgpt_key.as_ref()?;
        auth_dot_json
            .chatgpt_entries
            .iter_mut()
            .find(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *key))
    }

    fn get_current_token_data(&self) -> Option<TokenData> {
        let auth_dot_json = self.get_current_auth_json()?;
        if let Some(entry) = self.get_current_chatgpt_entry(&auth_dot_json) {
            return Some(entry.tokens.clone());
        }
        auth_dot_json.tokens
    }

    /// Consider this private to integration tests.
    pub fn create_dummy_chatgpt_auth_for_testing() -> Self {
        let auth_dot_json = AuthDotJson {
            openai_api_key: None,
            chatgpt_entries: Vec::new(),
            api_keys: Vec::new(),
            tokens: Some(TokenData {
                id_token: Default::default(),
                access_token: "Access Token".to_string(),
                refresh_token: "test".to_string(),
                account_id: Some("account_id".to_string()),
            }),
            last_refresh: Some(Utc::now()),
        };

        let auth_dot_json = Arc::new(Mutex::new(Some(auth_dot_json)));
        Self {
            storage: create_auth_storage(PathBuf::new(), AuthCredentialsStoreMode::File),
            auth_dot_json,
            chatgpt_key: None,
            client: crate::default_client::create_client(),
        }
    }
}

pub fn load_auth_from_storage(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<Option<Auth>> {
    load_auth(codex_home, false, auth_credentials_store_mode)
}

pub const OPENAI_API_KEY_ENV_VAR: &str = "OPENAI_API_KEY";
pub const CODEX_API_KEY_ENV_VAR: &str = "CODEX_API_KEY";

pub fn read_openai_api_key_from_env() -> Option<String> {
    env::var(OPENAI_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn read_codex_api_key_from_env() -> Option<String> {
    env::var(CODEX_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Delete the auth.json file inside `codex_home` if it exists. Returns `Ok(true)`
/// if a file was removed, `Ok(false)` if no auth file was present.
pub fn logout(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<bool> {
    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    storage.delete()
}

/// Writes an `auth.json` that contains only the API key.
pub fn login_with_api_key(
    codex_home: &Path,
    api_key: &str,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<()> {
    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    let mut auth_dot_json = load_auth_dot_json_migrated_or_default(&storage);

    if let Some(existing) = auth_dot_json
        .api_keys
        .iter_mut()
        .find(|entry| entry.api_key == api_key)
    {
        existing.api_key = api_key.to_string();
    } else {
        let id = next_global_entry_id(&auth_dot_json);
        auth_dot_json
            .api_keys
            .push(crate::auth::storage::ApiKeyAuthEntry {
                id,
                name: None,
                api_key: api_key.to_string(),
            });
    }

    auth_dot_json.openai_api_key = None;
    auth_dot_json.tokens = None;
    auth_dot_json.last_refresh = None;

    storage.save(&auth_dot_json)
}

pub fn persist_chatgpt_tokens(
    codex_home: &Path,
    id_token: String,
    access_token: String,
    refresh_token: String,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<()> {
    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    let mut auth_dot_json = load_auth_dot_json_migrated_or_default(&storage);

    let id_token_info = parse_id_token(&id_token).map_err(std::io::Error::other)?;
    let tokens = TokenData {
        account_id: id_token_info.chatgpt_account_id.clone(),
        id_token: id_token_info,
        access_token,
        refresh_token,
    };

    let key = ChatGptKey::from_tokens(&tokens)
        .ok_or_else(|| std::io::Error::other("ChatGPT tokens missing required identity fields"))?;

    if let Some(existing) = auth_dot_json
        .chatgpt_entries
        .iter_mut()
        .find(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == key))
    {
        existing.tokens = tokens;
        existing.last_refresh = Some(Utc::now());
    } else {
        let id = next_global_entry_id(&auth_dot_json);
        auth_dot_json.chatgpt_entries.push(ChatGptAuthEntry {
            id,
            name: None,
            tokens,
            last_refresh: Some(Utc::now()),
        });
    }

    auth_dot_json.openai_api_key = None;
    auth_dot_json.tokens = None;
    auth_dot_json.last_refresh = None;

    storage.save(&auth_dot_json)
}

fn next_global_entry_id(auth_dot_json: &AuthDotJson) -> u32 {
    let max_id = auth_dot_json
        .api_keys
        .iter()
        .map(|e| e.id)
        .chain(auth_dot_json.chatgpt_entries.iter().map(|e| e.id))
        .max()
        .unwrap_or(0);
    max_id.saturating_add(1)
}

fn migrate_legacy_auth_dot_json(auth_dot_json: &mut AuthDotJson) {
    if let Some(api_key) = auth_dot_json.openai_api_key.take()
        && auth_dot_json
            .api_keys
            .iter()
            .all(|entry| entry.api_key != api_key)
    {
        let id = next_global_entry_id(auth_dot_json);
        auth_dot_json
            .api_keys
            .push(crate::auth::storage::ApiKeyAuthEntry {
                id,
                name: None,
                api_key,
            });
    }

    if let Some(tokens) = auth_dot_json.tokens.take()
        && auth_dot_json
            .chatgpt_entries
            .iter()
            .all(|entry| entry.tokens != tokens)
    {
        let id = next_global_entry_id(auth_dot_json);
        auth_dot_json.chatgpt_entries.push(ChatGptAuthEntry {
            id,
            name: None,
            tokens,
            last_refresh: auth_dot_json.last_refresh,
        });
    }
    auth_dot_json.last_refresh = None;
}

fn load_auth_dot_json_migrated(
    storage: &Arc<dyn AuthStorageBackend>,
) -> std::io::Result<Option<AuthDotJson>> {
    let Some(mut auth_dot_json) = storage.load()? else {
        return Ok(None);
    };
    migrate_legacy_auth_dot_json(&mut auth_dot_json);
    Ok(Some(auth_dot_json))
}

fn load_auth_dot_json_migrated_or_default(storage: &Arc<dyn AuthStorageBackend>) -> AuthDotJson {
    let mut auth_dot_json = storage.load().ok().flatten().unwrap_or(AuthDotJson {
        openai_api_key: None,
        chatgpt_entries: Vec::new(),
        api_keys: Vec::new(),
        tokens: None,
        last_refresh: None,
    });
    migrate_legacy_auth_dot_json(&mut auth_dot_json);
    auth_dot_json
}

/// Persist the provided auth payload using the specified backend.
pub fn save_auth(
    codex_home: &Path,
    auth: &AuthDotJson,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<()> {
    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    storage.save(auth)
}

/// Load CLI auth data using the configured credential store backend.
/// Returns `None` when no credentials are stored. This function is
/// provided only for tests. Production code should not directly load
/// from the auth.json storage. It should use the AuthManager abstraction
/// instead.
pub fn load_auth_dot_json(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<Option<AuthDotJson>> {
    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    storage.load()
}

pub async fn enforce_login_restrictions(config: &Config) -> std::io::Result<()> {
    let Some(auth) = load_auth(
        &config.codex_home,
        true,
        config.cli_auth_credentials_store_mode,
    )?
    else {
        return Ok(());
    };

    if let Some(required_method) = config.forced_login_method {
        let method_violation = match (required_method, auth.mode()) {
            (ForcedLoginMethod::Api, AuthMode::ApiKey) => None,
            (ForcedLoginMethod::Chatgpt, AuthMode::ChatGPT) => None,
            (ForcedLoginMethod::Api, AuthMode::ChatGPT) => Some(
                "API key login is required, but ChatGPT is currently being used. Logging out."
                    .to_string(),
            ),
            (ForcedLoginMethod::Chatgpt, AuthMode::ApiKey) => Some(
                "ChatGPT login is required, but an API key is currently being used. Logging out."
                    .to_string(),
            ),
        };

        if let Some(message) = method_violation {
            return logout_with_message(
                &config.codex_home,
                message,
                config.cli_auth_credentials_store_mode,
            );
        }
    }

    Ok(())
}

fn logout_with_message(
    codex_home: &Path,
    message: String,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<()> {
    match logout(codex_home, auth_credentials_store_mode) {
        Ok(_) => Err(std::io::Error::other(message)),
        Err(err) => Err(std::io::Error::other(format!(
            "{message}. Failed to remove auth.json: {err}"
        ))),
    }
}

fn load_auth(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<Option<Auth>> {
    if enable_codex_api_key_env && let Some(api_key) = read_codex_api_key_from_env() {
        return Ok(Some(Auth::ApiKey {
            handle: ApiKeyAuth::new(api_key),
        }));
    }

    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);

    let client = crate::default_client::create_client();
    let Some(auth_dot_json) = load_auth_dot_json_migrated(&storage)? else {
        return Ok(None);
    };
    Ok(select_auth_from_auth_dot_json(
        auth_dot_json,
        storage,
        client,
    ))
}

#[derive(Debug)]
struct LoadedAuthState {
    auth: Option<Auth>,
    auth_dot_json: Option<AuthDotJson>,
    auth_load_error: Option<String>,
}

fn load_auth_state(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> LoadedAuthState {
    if enable_codex_api_key_env && let Some(api_key) = read_codex_api_key_from_env() {
        return LoadedAuthState {
            auth: Some(Auth::ApiKey {
                handle: ApiKeyAuth::new(api_key),
            }),
            auth_dot_json: None,
            auth_load_error: None,
        };
    }

    let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
    let client = crate::default_client::create_client();

    match load_auth_dot_json_migrated(&storage) {
        Ok(Some(auth_dot_json)) => {
            let auth = select_auth_from_auth_dot_json(auth_dot_json.clone(), storage, client);
            LoadedAuthState {
                auth,
                auth_dot_json: Some(auth_dot_json),
                auth_load_error: None,
            }
        }
        Ok(None) => LoadedAuthState {
            auth: None,
            auth_dot_json: None,
            auth_load_error: None,
        },
        Err(err) => LoadedAuthState {
            auth: None,
            auth_dot_json: None,
            auth_load_error: Some(err.to_string()),
        },
    }
}

fn select_auth_from_auth_dot_json(
    auth_dot_json: AuthDotJson,
    storage: Arc<dyn AuthStorageBackend>,
    client: CodexHttpClient,
) -> Option<Auth> {
    #[derive(Clone)]
    enum Candidate {
        ChatGpt(ChatGptKey),
        ApiKey(String),
    }

    let mut selected: Option<(u32, Candidate)> = None;

    for entry in &auth_dot_json.api_keys {
        let candidate = (entry.id, Candidate::ApiKey(entry.api_key.clone()));
        if selected.as_ref().is_none_or(|(id, _)| *id > candidate.0) {
            selected = Some(candidate);
        }
    }

    for entry in &auth_dot_json.chatgpt_entries {
        let Some(key) = ChatGptKey::from_tokens(&entry.tokens) else {
            continue;
        };
        let candidate = (entry.id, Candidate::ChatGpt(key));
        if selected.as_ref().is_none_or(|(id, _)| *id > candidate.0) {
            selected = Some(candidate);
        }
    }

    match selected.map(|(_, candidate)| candidate) {
        Some(Candidate::ApiKey(api_key)) => Some(Auth::ApiKey {
            handle: ApiKeyAuth::new(api_key),
        }),
        Some(Candidate::ChatGpt(chatgpt_key)) => Some(Auth::ChatGpt {
            handle: CodexAuth {
                storage,
                auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
                chatgpt_key: Some(chatgpt_key),
                client,
            },
        }),
        None => None,
    }
}

fn select_auth_from_auth_dot_json_with_override(
    auth_dot_json: AuthDotJson,
    active_override: &ActiveOverride,
    storage: Arc<dyn AuthStorageBackend>,
    client: CodexHttpClient,
) -> Option<Auth> {
    match active_override {
        ActiveOverride::ChatGpt(key) => {
            if auth_dot_json
                .chatgpt_entries
                .iter()
                .any(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *key))
            {
                Some(Auth::ChatGpt {
                    handle: CodexAuth {
                        storage,
                        auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
                        chatgpt_key: Some(key.clone()),
                        client,
                    },
                })
            } else {
                None
            }
        }
        ActiveOverride::ApiKeyFingerprint(fp) => auth_dot_json
            .api_keys
            .iter()
            .find(|entry| api_key_fingerprint(&entry.api_key) == *fp)
            .map(|entry| Auth::ApiKey {
                handle: ApiKeyAuth::new(entry.api_key.clone()),
            }),
    }
}

#[cfg(test)]
async fn update_tokens(
    storage: &Arc<dyn AuthStorageBackend>,
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
) -> std::io::Result<AuthDotJson> {
    let mut auth_dot_json = storage
        .load()?
        .ok_or(std::io::Error::other("Token data is not available."))?;

    let tokens = auth_dot_json.tokens.get_or_insert_with(TokenData::default);
    if let Some(id_token) = id_token {
        tokens.id_token = parse_id_token(&id_token).map_err(std::io::Error::other)?;
    }
    if let Some(access_token) = access_token {
        tokens.access_token = access_token;
    }
    if let Some(refresh_token) = refresh_token {
        tokens.refresh_token = refresh_token;
    }
    auth_dot_json.last_refresh = Some(Utc::now());
    storage.save(&auth_dot_json)?;
    Ok(auth_dot_json)
}

async fn try_refresh_token(
    refresh_token: String,
    client: &CodexHttpClient,
) -> Result<RefreshResponse, RefreshTokenError> {
    let refresh_request = RefreshRequest {
        client_id: CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token,
        scope: "openid profile email",
    };

    let endpoint = refresh_token_endpoint();

    // Use shared client factory to include standard headers
    let response = client
        .post(endpoint.as_str())
        .header("Content-Type", "application/json")
        .json(&refresh_request)
        .send()
        .await
        .map_err(|err| RefreshTokenError::Transient(std::io::Error::other(err)))?;

    let status = response.status();
    if status.is_success() {
        let refresh_response = response
            .json::<RefreshResponse>()
            .await
            .map_err(|err| RefreshTokenError::Transient(std::io::Error::other(err)))?;
        Ok(refresh_response)
    } else {
        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED {
            let failed = classify_refresh_token_failure(&body);
            Err(RefreshTokenError::Permanent(failed))
        } else {
            let message = try_parse_error_message(&body);
            Err(RefreshTokenError::Transient(std::io::Error::other(
                format!("Failed to refresh token: {status}: {message}"),
            )))
        }
    }
}

fn classify_refresh_token_failure(body: &str) -> RefreshTokenFailedError {
    let code = extract_refresh_token_error_code(body);

    let normalized_code = code.as_deref().map(str::to_ascii_lowercase);
    let reason = match normalized_code.as_deref() {
        Some("refresh_token_expired") => RefreshTokenFailedReason::Expired,
        Some("refresh_token_reused") => RefreshTokenFailedReason::Exhausted,
        Some("refresh_token_invalidated") => RefreshTokenFailedReason::Revoked,
        _ => RefreshTokenFailedReason::Other,
    };

    if reason == RefreshTokenFailedReason::Other {
        tracing::warn!(
            backend_code = normalized_code.as_deref(),
            backend_body = body,
            "Encountered unknown 401 response while refreshing token"
        );
    }

    let message = match reason {
        RefreshTokenFailedReason::Expired => REFRESH_TOKEN_EXPIRED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Exhausted => REFRESH_TOKEN_REUSED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Revoked => REFRESH_TOKEN_INVALIDATED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Other => REFRESH_TOKEN_UNKNOWN_MESSAGE.to_string(),
    };

    RefreshTokenFailedError::new(reason, message)
}

fn extract_refresh_token_error_code(body: &str) -> Option<String> {
    if body.trim().is_empty() {
        return None;
    }

    let Value::Object(map) = serde_json::from_str::<Value>(body).ok()? else {
        return None;
    };

    if let Some(error_value) = map.get("error") {
        match error_value {
            Value::Object(obj) => {
                if let Some(code) = obj.get("code").and_then(Value::as_str) {
                    return Some(code.to_string());
                }
            }
            Value::String(code) => {
                return Some(code.to_string());
            }
            _ => {}
        }
    }

    map.get("code").and_then(Value::as_str).map(str::to_string)
}

#[derive(Serialize)]
struct RefreshRequest {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: String,
    scope: &'static str,
}

#[derive(Deserialize, Clone)]
struct RefreshResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

// Shared constant for token refresh (client id used for oauth token refresh flow)
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

fn refresh_token_endpoint() -> String {
    std::env::var(REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR)
        .unwrap_or_else(|_| REFRESH_TOKEN_URL.to_string())
}

/// Internal cached auth state.
#[derive(Clone, Debug)]
struct CachedAuth {
    auth: Option<Auth>,
    auth_dot_json: Option<AuthDotJson>,
    auth_load_error: Option<String>,
    active_override: Option<ActiveOverride>,
    credential_unusable: HashMap<ActiveOverride, CredentialUnusable>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ActiveOverride {
    ChatGpt(ChatGptKey),
    ApiKeyFingerprint(String),
}

#[derive(Clone, Debug)]
enum CredentialUnusable {
    UsageNotIncluded,
    UsageLimitReached { message: String },
}

impl CredentialUnusable {
    fn message(&self) -> String {
        match self {
            Self::UsageNotIncluded => crate::error::CodexErr::UsageNotIncluded.to_string(),
            Self::UsageLimitReached { message } => message.clone(),
        }
    }
}

fn active_override_from_auth(auth: &Auth) -> Option<ActiveOverride> {
    match auth {
        Auth::ChatGpt { handle } => handle.chatgpt_key.clone().map(ActiveOverride::ChatGpt),
        Auth::ApiKey { handle } => Some(ActiveOverride::ApiKeyFingerprint(api_key_fingerprint(
            handle.as_str(),
        ))),
    }
}

fn api_key_fingerprint(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::FileAuthStorage;
    use crate::auth::storage::get_auth_file;
    use crate::config::Config;
    use crate::config::ConfigBuilder;
    use crate::token_data::IdTokenInfo;
    use crate::token_data::KnownPlan as InternalKnownPlan;
    use crate::token_data::PlanType as InternalPlanType;
    use codex_protocol::account::PlanType as AccountPlanType;

    use base64::Engine;
    use codex_protocol::config_types::ForcedLoginMethod;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_json::json;
    use tempfile::tempdir;

    #[tokio::test]
    async fn refresh_without_id_token() {
        let codex_home = tempdir().unwrap();
        let fake_jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "pro".to_string(),
                chatgpt_account_id: Some("account_id".to_string()),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let storage = create_auth_storage(
            codex_home.path().to_path_buf(),
            AuthCredentialsStoreMode::File,
        );
        let updated = super::update_tokens(
            &storage,
            None,
            Some("new-access-token".to_string()),
            Some("new-refresh-token".to_string()),
        )
        .await
        .expect("update_tokens should succeed");

        let tokens = updated.tokens.expect("tokens should exist");
        assert_eq!(tokens.id_token.raw_jwt, fake_jwt);
        assert_eq!(tokens.access_token, "new-access-token");
        assert_eq!(tokens.refresh_token, "new-refresh-token");
    }

    #[test]
    fn login_with_api_key_overwrites_existing_auth_json() {
        let dir = tempdir().unwrap();
        let _jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: Some("sk-old".to_string()),
                chatgpt_plan_type: "pro".to_string(),
                chatgpt_account_id: None,
            },
            dir.path(),
        )
        .expect("failed to write auth file");

        super::login_with_api_key(dir.path(), "sk-new", AuthCredentialsStoreMode::File)
            .expect("login_with_api_key should succeed");

        let storage = FileAuthStorage::new(dir.path().to_path_buf());
        let auth = storage
            .try_read_auth_json(&dir.path().join("auth.json"))
            .expect("auth.json should parse");
        assert!(
            auth.openai_api_key.is_none(),
            "legacy key should be migrated"
        );
        assert!(auth.tokens.is_none(), "legacy tokens should be migrated");
        assert!(
            auth.api_keys.iter().any(|entry| entry.api_key == "sk-new"),
            "new API key should be stored as an entry"
        );
        assert!(
            auth.api_keys.iter().any(|entry| entry.api_key == "sk-old"),
            "existing API key should be preserved as an entry"
        );
        assert!(
            !auth.chatgpt_entries.is_empty(),
            "existing ChatGPT tokens should be preserved as an entry"
        );
    }

    #[test]
    fn missing_auth_json_returns_none() {
        let dir = tempdir().unwrap();
        let auth = load_auth_from_storage(dir.path(), AuthCredentialsStoreMode::File)
            .expect("call should succeed");
        assert!(auth.is_none());
    }

    #[tokio::test]
    #[serial(codex_api_key)]
    async fn pro_account_with_no_api_key_uses_chatgpt_auth() {
        let codex_home = tempdir().unwrap();
        let fake_jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "pro".to_string(),
                chatgpt_account_id: Some("account_id".to_string()),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let mut auth_dot_json =
            super::load_auth_dot_json(codex_home.path(), AuthCredentialsStoreMode::File)
                .expect("load auth.json")
                .expect("auth.json should exist");
        let tokens = auth_dot_json.tokens.as_ref().expect("tokens should exist");
        assert!(
            tokens.id_token.chatgpt_user_id.is_some(),
            "id_token should include chatgpt_user_id"
        );
        assert!(
            tokens.account_id.is_some() || tokens.id_token.chatgpt_account_id.is_some(),
            "tokens should include an account id"
        );
        migrate_legacy_auth_dot_json(&mut auth_dot_json);
        let entry = auth_dot_json
            .chatgpt_entries
            .first()
            .expect("ChatGPT entry should exist after migration");
        assert!(
            ChatGptKey::from_tokens(&entry.tokens).is_some(),
            "ChatGPT entry should be keyable"
        );

        let CodexAuth { auth_dot_json, .. } =
            match super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
                .unwrap()
                .unwrap()
            {
                Auth::ChatGpt { handle } => handle,
                Auth::ApiKey { .. } => panic!("expected ChatGPT auth"),
            };

        let guard = auth_dot_json.lock().unwrap();
        let auth_dot_json = guard.as_ref().expect("AuthDotJson should exist");
        let entry = auth_dot_json
            .chatgpt_entries
            .first()
            .expect("ChatGPT entry should exist after migration");
        let last_refresh = entry
            .last_refresh
            .expect("last_refresh should be recorded on migrated entry");

        assert_eq!(
            &AuthDotJson {
                openai_api_key: None,
                chatgpt_entries: vec![ChatGptAuthEntry {
                    id: 1,
                    name: None,
                    tokens: TokenData {
                        id_token: IdTokenInfo {
                            email: Some("user@example.com".to_string()),
                            chatgpt_plan_type: Some(InternalPlanType::Known(
                                InternalKnownPlan::Pro
                            )),
                            chatgpt_account_id: Some("account_id".to_string()),
                            chatgpt_user_id: Some("user-12345".to_string()),
                            raw_jwt: fake_jwt,
                        },
                        access_token: "test-access-token".to_string(),
                        refresh_token: "test-refresh-token".to_string(),
                        account_id: Some("account_id".to_string()),
                    },
                    last_refresh: Some(last_refresh),
                }],
                api_keys: Vec::new(),
                tokens: None,
                last_refresh: None,
            },
            auth_dot_json
        );
    }

    #[tokio::test]
    #[serial(codex_api_key)]
    async fn loads_api_key_from_auth_json() {
        let dir = tempdir().unwrap();
        let auth_file = dir.path().join("auth.json");
        std::fs::write(
            auth_file,
            r#"{"OPENAI_API_KEY":"sk-test-key","tokens":null,"last_refresh":null}"#,
        )
        .unwrap();

        let auth = super::load_auth(dir.path(), false, AuthCredentialsStoreMode::File)
            .unwrap()
            .unwrap();
        let token = auth.bearer_token().await.unwrap();
        assert_eq!(token, "sk-test-key");

        let Auth::ApiKey { handle: api_key } = auth else {
            panic!("expected API key auth");
        };
        assert_eq!(api_key.as_str(), "sk-test-key");
    }

    #[test]
    fn logout_removes_auth_file() -> Result<(), std::io::Error> {
        let dir = tempdir()?;
        let auth_dot_json = AuthDotJson {
            openai_api_key: Some("sk-test-key".to_string()),
            chatgpt_entries: Vec::new(),
            api_keys: Vec::new(),
            tokens: None,
            last_refresh: None,
        };
        super::save_auth(dir.path(), &auth_dot_json, AuthCredentialsStoreMode::File)?;
        let auth_file = get_auth_file(dir.path());
        assert!(auth_file.exists());
        assert!(logout(dir.path(), AuthCredentialsStoreMode::File)?);
        assert!(!auth_file.exists());
        Ok(())
    }

    struct AuthFileParams {
        openai_api_key: Option<String>,
        chatgpt_plan_type: String,
        chatgpt_account_id: Option<String>,
    }

    fn write_auth_file(params: AuthFileParams, codex_home: &Path) -> std::io::Result<String> {
        let auth_file = get_auth_file(codex_home);
        // Create a minimal valid JWT for the id_token field.
        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }
        let header = Header {
            alg: "none",
            typ: "JWT",
        };
        let mut auth_payload = serde_json::json!({
            "chatgpt_plan_type": params.chatgpt_plan_type,
            "chatgpt_user_id": "user-12345",
            "user_id": "user-12345",
        });

        if let Some(chatgpt_account_id) = params.chatgpt_account_id.as_ref() {
            let org_value = serde_json::Value::String(chatgpt_account_id.clone());
            auth_payload["chatgpt_account_id"] = org_value;
        }

        let payload = serde_json::json!({
            "email": "user@example.com",
            "email_verified": true,
            "https://api.openai.com/auth": auth_payload,
        });
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header_b64 = b64(&serde_json::to_vec(&header)?);
        let payload_b64 = b64(&serde_json::to_vec(&payload)?);
        let signature_b64 = b64(b"sig");
        let fake_jwt = format!("{header_b64}.{payload_b64}.{signature_b64}");

        let mut tokens = json!({
            "id_token": fake_jwt,
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token"
        });
        if let Some(account_id) = params.chatgpt_account_id.as_ref() {
            tokens["account_id"] = serde_json::Value::String(account_id.clone());
        }

        let auth_json_data = json!({
            "OPENAI_API_KEY": params.openai_api_key,
            "tokens": tokens,
            "last_refresh": Utc::now(),
        });
        let auth_json = serde_json::to_string_pretty(&auth_json_data)?;
        std::fs::write(auth_file, auth_json)?;
        Ok(fake_jwt)
    }

    async fn build_config(
        codex_home: &Path,
        forced_login_method: Option<ForcedLoginMethod>,
    ) -> Config {
        let mut config = ConfigBuilder::default()
            .codex_home(codex_home.to_path_buf())
            .build()
            .await
            .expect("config should load");
        config.forced_login_method = forced_login_method;
        config
    }

    /// Use sparingly.
    /// TODO (gpeal): replace this with an injectable env var provider.
    #[cfg(test)]
    struct EnvVarGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    #[cfg(test)]
    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var_os(key);
            unsafe {
                env::set_var(key, value);
            }
            Self { key, original }
        }
    }

    #[cfg(test)]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.original {
                    Some(value) => env::set_var(self.key, value),
                    None => env::remove_var(self.key),
                }
            }
        }
    }

    #[tokio::test]
    async fn enforce_login_restrictions_logs_out_for_method_mismatch() {
        let codex_home = tempdir().unwrap();
        login_with_api_key(codex_home.path(), "sk-test", AuthCredentialsStoreMode::File)
            .expect("seed api key");

        let config = build_config(codex_home.path(), Some(ForcedLoginMethod::Chatgpt)).await;

        let err = super::enforce_login_restrictions(&config)
            .await
            .expect_err("expected method mismatch to error");
        assert!(err.to_string().contains("ChatGPT login is required"));
        assert!(
            !codex_home.path().join("auth.json").exists(),
            "auth.json should be removed on mismatch"
        );
    }

    #[tokio::test]
    #[serial(codex_api_key)]
    async fn enforce_login_restrictions_blocks_env_api_key_when_chatgpt_required() {
        let _guard = EnvVarGuard::set(CODEX_API_KEY_ENV_VAR, "sk-env");
        let codex_home = tempdir().unwrap();

        let config = build_config(codex_home.path(), Some(ForcedLoginMethod::Chatgpt)).await;

        let err = super::enforce_login_restrictions(&config)
            .await
            .expect_err("environment API key should not satisfy forced ChatGPT login");
        assert!(
            err.to_string()
                .contains("ChatGPT login is required, but an API key is currently being used.")
        );
    }

    #[test]
    fn plan_type_maps_known_plan() {
        let codex_home = tempdir().unwrap();
        let _jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "pro".to_string(),
                chatgpt_account_id: Some("account_id".to_string()),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
            .expect("load auth")
            .expect("auth available");

        let Auth::ChatGpt { handle } = auth else {
            panic!("expected ChatGPT auth");
        };
        pretty_assertions::assert_eq!(handle.account_plan_type(), Some(AccountPlanType::Pro));
    }

    #[test]
    fn plan_type_maps_unknown_to_unknown() {
        let codex_home = tempdir().unwrap();
        let _jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "mystery-tier".to_string(),
                chatgpt_account_id: Some("account_id".to_string()),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
            .expect("load auth")
            .expect("auth available");

        let Auth::ChatGpt { handle } = auth else {
            panic!("expected ChatGPT auth");
        };
        pretty_assertions::assert_eq!(handle.account_plan_type(), Some(AccountPlanType::Unknown));
    }
}

/// Central manager providing a single source of truth for auth.json derived
/// authentication data. It loads once (or on preference change) and then
/// hands out cloned `CodexAuth` values so the rest of the program has a
/// consistent snapshot.
///
/// External modifications to `auth.json` will NOT be observed until
/// `reload()` is called explicitly. This matches the design goal of avoiding
/// different parts of the program seeing inconsistent auth data mid‑run.
#[derive(Debug)]
pub struct AuthManager {
    codex_home: PathBuf,
    inner: RwLock<CachedAuth>,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
}

#[derive(Debug, Clone)]
pub struct CredentialListEntry {
    pub id: u32,
    pub name: Option<String>,
    pub mode: AuthMode,
    pub is_active: bool,
    pub chatgpt_email: Option<String>,
    pub chatgpt_plan: Option<AccountPlanType>,
}

impl AuthManager {
    /// Create a new manager loading the initial auth using the provided
    /// preferred auth method. Errors loading auth are swallowed; `auth()` will
    /// simply return `None` in that case so callers can treat it as an
    /// unauthenticated state.
    pub fn new(
        codex_home: PathBuf,
        enable_codex_api_key_env: bool,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
    ) -> Self {
        let loaded = load_auth_state(
            &codex_home,
            enable_codex_api_key_env,
            auth_credentials_store_mode,
        );
        let active_override = loaded.auth.as_ref().and_then(active_override_from_auth);
        Self {
            codex_home,
            inner: RwLock::new(CachedAuth {
                auth: loaded.auth,
                auth_dot_json: loaded.auth_dot_json,
                auth_load_error: loaded.auth_load_error,
                active_override,
                credential_unusable: HashMap::new(),
            }),
            enable_codex_api_key_env,
            auth_credentials_store_mode,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[expect(clippy::expect_used)]
    /// Create an AuthManager with a specific CodexAuth, for testing only.
    pub fn from_auth_for_testing(auth: CodexAuth) -> Arc<Self> {
        let cached = CachedAuth {
            auth: Some(Auth::ChatGpt { handle: auth }),
            auth_dot_json: None,
            auth_load_error: None,
            active_override: None,
            credential_unusable: HashMap::new(),
        };
        let temp_dir = tempfile::tempdir().expect("temp codex home");
        let codex_home = temp_dir.path().to_path_buf();
        TEST_AUTH_TEMP_DIRS
            .lock()
            .expect("lock test codex homes")
            .push(temp_dir);
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[expect(clippy::expect_used)]
    pub fn from_api_key_for_testing(api_key: &str) -> Arc<Self> {
        let cached = CachedAuth {
            auth: Some(Auth::ApiKey {
                handle: ApiKeyAuth::new(api_key.to_string()),
            }),
            auth_dot_json: None,
            auth_load_error: None,
            active_override: None,
            credential_unusable: HashMap::new(),
        };
        let temp_dir = tempfile::tempdir().expect("temp codex home");
        let codex_home = temp_dir.path().to_path_buf();
        TEST_AUTH_TEMP_DIRS
            .lock()
            .expect("lock test codex homes")
            .push(temp_dir);
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Create an AuthManager with a specific CodexAuth and codex home, for testing only.
    pub fn from_auth_for_testing_with_home(auth: CodexAuth, codex_home: PathBuf) -> Arc<Self> {
        let cached = CachedAuth {
            auth: Some(Auth::ChatGpt { handle: auth }),
            auth_dot_json: None,
            auth_load_error: None,
            active_override: None,
            credential_unusable: HashMap::new(),
        };
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_api_key_for_testing_with_home(api_key: &str, codex_home: PathBuf) -> Arc<Self> {
        let cached = CachedAuth {
            auth: Some(Auth::ApiKey {
                handle: ApiKeyAuth::new(api_key.to_string()),
            }),
            auth_dot_json: None,
            auth_load_error: None,
            active_override: None,
            credential_unusable: HashMap::new(),
        };
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        })
    }

    /// Current cached auth (clone). May be `None` if not logged in or load failed.
    pub fn auth(&self) -> Option<Auth> {
        self.inner.read().ok().and_then(|c| c.auth.clone())
    }

    pub fn auth_load_error(&self) -> Option<String> {
        self.inner
            .read()
            .ok()
            .and_then(|cached| cached.auth_load_error.clone())
    }

    pub fn active_credential_id(&self) -> Option<u32> {
        let guard = self.inner.read().ok()?;
        let auth_dot_json = guard.auth_dot_json.as_ref()?;
        let active = guard.active_override.as_ref()?;
        match active {
            ActiveOverride::ChatGpt(key) => auth_dot_json
                .chatgpt_entries
                .iter()
                .find(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *key))
                .map(|entry| entry.id),
            ActiveOverride::ApiKeyFingerprint(fp) => auth_dot_json
                .api_keys
                .iter()
                .find(|entry| api_key_fingerprint(&entry.api_key) == *fp)
                .map(|entry| entry.id),
        }
    }

    pub fn activate_credential_by_id(&self, id: u32) -> std::io::Result<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| std::io::Error::other("Auth manager lock poisoned"))?;
        let auth_dot_json = guard
            .auth_dot_json
            .clone()
            .ok_or_else(|| std::io::Error::other("Not logged in"))?;

        if let Some(entry) = auth_dot_json
            .chatgpt_entries
            .iter()
            .find(|entry| entry.id == id)
        {
            let key = ChatGptKey::from_tokens(&entry.tokens)
                .ok_or_else(|| std::io::Error::other("ChatGPT credential missing identity"))?;
            let storage =
                create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
            let client = crate::default_client::create_client();
            let auth = select_auth_from_auth_dot_json_with_override(
                auth_dot_json,
                &ActiveOverride::ChatGpt(key.clone()),
                storage,
                client,
            )
            .ok_or_else(|| std::io::Error::other("Credential not found"))?;
            guard.auth = Some(auth);
            guard.active_override = Some(ActiveOverride::ChatGpt(key));
            return Ok(());
        }

        if let Some(entry) = auth_dot_json.api_keys.iter().find(|entry| entry.id == id) {
            guard.auth = Some(Auth::ApiKey {
                handle: ApiKeyAuth::new(entry.api_key.clone()),
            });
            guard.active_override = Some(ActiveOverride::ApiKeyFingerprint(api_key_fingerprint(
                &entry.api_key,
            )));
            return Ok(());
        }

        Err(std::io::Error::other(format!(
            "Credential id {id} does not exist"
        )))
    }

    pub fn record_active_credential_usage_not_included(&self) -> Option<u32> {
        self.record_active_credential_unusable(CredentialUnusable::UsageNotIncluded)
    }

    pub fn record_active_credential_usage_limit_reached(&self, message: String) -> Option<u32> {
        self.record_active_credential_unusable(CredentialUnusable::UsageLimitReached { message })
    }

    pub fn credential_unusable_message_by_id(&self, id: u32) -> Option<String> {
        let guard = self.inner.read().ok()?;
        let auth_dot_json = guard.auth_dot_json.as_ref()?;

        if let Some(entry) = auth_dot_json
            .chatgpt_entries
            .iter()
            .find(|entry| entry.id == id)
        {
            let key = ChatGptKey::from_tokens(&entry.tokens)?;
            return guard
                .credential_unusable
                .get(&ActiveOverride::ChatGpt(key))
                .map(CredentialUnusable::message);
        }

        if let Some(entry) = auth_dot_json.api_keys.iter().find(|entry| entry.id == id) {
            let fp = api_key_fingerprint(&entry.api_key);
            return guard
                .credential_unusable
                .get(&ActiveOverride::ApiKeyFingerprint(fp))
                .map(CredentialUnusable::message);
        }

        None
    }

    fn record_active_credential_unusable(&self, unusable: CredentialUnusable) -> Option<u32> {
        let mut guard = self.inner.write().ok()?;
        let auth_dot_json = guard.auth_dot_json.clone()?;

        let active = guard
            .active_override
            .clone()
            .or_else(|| guard.auth.as_ref().and_then(active_override_from_auth))?;
        guard.credential_unusable.insert(active.clone(), unusable);

        let mut candidates: Vec<(u32, ActiveOverride)> =
            Vec::with_capacity(auth_dot_json.chatgpt_entries.len() + auth_dot_json.api_keys.len());
        for entry in &auth_dot_json.chatgpt_entries {
            let Some(key) = ChatGptKey::from_tokens(&entry.tokens) else {
                continue;
            };
            candidates.push((entry.id, ActiveOverride::ChatGpt(key)));
        }
        for entry in &auth_dot_json.api_keys {
            candidates.push((
                entry.id,
                ActiveOverride::ApiKeyFingerprint(api_key_fingerprint(&entry.api_key)),
            ));
        }
        candidates.sort_by_key(|(id, _)| *id);

        let active_index = candidates
            .iter()
            .position(|(_, candidate)| *candidate == active)?;

        for offset in 1..=candidates.len() {
            let idx = (active_index + offset) % candidates.len();
            let (id, candidate) = candidates[idx].clone();
            if candidate == active {
                continue;
            }
            if guard.credential_unusable.contains_key(&candidate) {
                continue;
            }

            let storage =
                create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
            let client = crate::default_client::create_client();
            let auth = select_auth_from_auth_dot_json_with_override(
                auth_dot_json,
                &candidate,
                storage,
                client,
            )?;
            guard.auth = Some(auth);
            guard.active_override = Some(candidate);
            return Some(id);
        }

        None
    }

    pub fn list_credentials(&self) -> Vec<CredentialListEntry> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };
        let Some(auth_dot_json) = guard.auth_dot_json.as_ref() else {
            return Vec::new();
        };

        let active_id = match guard.active_override.as_ref() {
            Some(ActiveOverride::ChatGpt(key)) => auth_dot_json
                .chatgpt_entries
                .iter()
                .find(|entry| ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *key))
                .map(|entry| entry.id),
            Some(ActiveOverride::ApiKeyFingerprint(fp)) => auth_dot_json
                .api_keys
                .iter()
                .find(|entry| api_key_fingerprint(&entry.api_key) == *fp)
                .map(|entry| entry.id),
            None => None,
        };

        let mut entries =
            Vec::with_capacity(auth_dot_json.chatgpt_entries.len() + auth_dot_json.api_keys.len());
        for entry in &auth_dot_json.chatgpt_entries {
            let plan = entry
                .tokens
                .id_token
                .chatgpt_plan_type
                .as_ref()
                .map(account_plan_type_from_internal);

            entries.push(CredentialListEntry {
                id: entry.id,
                name: entry.name.clone(),
                mode: AuthMode::ChatGPT,
                is_active: active_id == Some(entry.id),
                chatgpt_email: entry.tokens.id_token.email.clone(),
                chatgpt_plan: plan,
            });
        }
        for entry in &auth_dot_json.api_keys {
            entries.push(CredentialListEntry {
                id: entry.id,
                name: entry.name.clone(),
                mode: AuthMode::ApiKey,
                is_active: active_id == Some(entry.id),
                chatgpt_email: None,
                chatgpt_plan: None,
            });
        }
        entries.sort_by_key(|entry| entry.id);
        entries
    }

    pub fn auth_for_credential_by_id(&self, id: u32) -> Option<Auth> {
        let auth_dot_json = self
            .inner
            .read()
            .ok()
            .and_then(|guard| guard.auth_dot_json.clone())?;

        if let Some(entry) = auth_dot_json
            .chatgpt_entries
            .iter()
            .find(|entry| entry.id == id)
        {
            let key = ChatGptKey::from_tokens(&entry.tokens)?;
            let storage =
                create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
            let client = crate::default_client::create_client();
            return Some(Auth::ChatGpt {
                handle: CodexAuth {
                    storage,
                    auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
                    chatgpt_key: Some(key),
                    client,
                },
            });
        }

        auth_dot_json
            .api_keys
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| Auth::ApiKey {
                handle: ApiKeyAuth::new(entry.api_key.clone()),
            })
    }

    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    /// Force a reload of the auth information from auth.json. Returns
    /// whether the auth value changed.
    pub fn reload(&self) -> bool {
        let loaded = load_auth_state(
            &self.codex_home,
            self.enable_codex_api_key_env,
            self.auth_credentials_store_mode,
        );
        if let Ok(mut guard) = self.inner.write() {
            let changed = guard.auth_load_error != loaded.auth_load_error
                || guard.auth_dot_json != loaded.auth_dot_json;
            let mut next_auth = loaded.auth;
            if let Some(active_override) = guard.active_override.as_ref()
                && let Some(auth_dot_json) = loaded.auth_dot_json.clone()
            {
                let storage =
                    create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
                let client = crate::default_client::create_client();
                if let Some(overridden) = select_auth_from_auth_dot_json_with_override(
                    auth_dot_json,
                    active_override,
                    storage,
                    client,
                ) {
                    next_auth = Some(overridden);
                } else {
                    guard.active_override = None;
                }
            }

            guard.auth = next_auth;
            guard.auth_dot_json = loaded.auth_dot_json;
            guard.auth_load_error = loaded.auth_load_error;

            if let Some(auth_dot_json) = guard.auth_dot_json.clone() {
                guard.credential_unusable.retain(|key, _| match key {
                    ActiveOverride::ChatGpt(active_key) => {
                        auth_dot_json.chatgpt_entries.iter().any(|entry| {
                            ChatGptKey::from_tokens(&entry.tokens).is_some_and(|k| k == *active_key)
                        })
                    }
                    ActiveOverride::ApiKeyFingerprint(fp) => auth_dot_json
                        .api_keys
                        .iter()
                        .any(|entry| api_key_fingerprint(&entry.api_key) == *fp),
                });
            } else {
                guard.credential_unusable.clear();
            }

            if guard.active_override.is_none()
                && let Some(auth) = guard.auth.as_ref()
            {
                guard.active_override = active_override_from_auth(auth);
            }
            changed
        } else {
            false
        }
    }

    /// Convenience constructor returning an `Arc` wrapper.
    pub fn shared(
        codex_home: PathBuf,
        enable_codex_api_key_env: bool,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
    ) -> Arc<Self> {
        Arc::new(Self::new(
            codex_home,
            enable_codex_api_key_env,
            auth_credentials_store_mode,
        ))
    }

    /// Attempt to refresh the current auth token (if any). On success, reload
    /// the auth state from disk so other components observe refreshed token.
    /// If the token refresh fails in a permanent (non‑transient) way, logs out
    /// to clear invalid auth state.
    pub async fn refresh_token(&self) -> Result<Option<String>, RefreshTokenError> {
        let Some(auth) = self.auth() else {
            return Ok(None);
        };
        let Auth::ChatGpt { handle } = auth else {
            return Ok(None);
        };
        match handle.refresh_token().await {
            Ok(token) => {
                // Reload to pick up persisted changes.
                self.reload();
                Ok(Some(token))
            }
            Err(e) => {
                tracing::error!("Failed to refresh token: {}", e);
                Err(e)
            }
        }
    }

    /// Log out by deleting the on‑disk auth.json (if present). Returns Ok(true)
    /// if a file was removed, Ok(false) if no auth file existed. On success,
    /// reloads the in‑memory auth cache so callers immediately observe the
    /// unauthenticated state.
    pub fn logout(&self) -> std::io::Result<bool> {
        let removed = super::auth::logout(&self.codex_home, self.auth_credentials_store_mode)?;
        // Always reload to clear any cached auth (even if file absent).
        self.reload();
        Ok(removed)
    }

    pub fn get_auth_mode(&self) -> Option<AuthMode> {
        self.auth().map(|a| a.mode())
    }

    pub fn rename_credential_by_id(&self, id: u32, name: Option<String>) -> std::io::Result<()> {
        let storage =
            create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
        let mut auth_dot_json = load_auth_dot_json_migrated(&storage)?
            .ok_or_else(|| std::io::Error::other("Not logged in"))?;

        if let Some(entry) = auth_dot_json
            .chatgpt_entries
            .iter_mut()
            .find(|entry| entry.id == id)
        {
            entry.name = name;
            storage.save(&auth_dot_json)?;
            self.reload();
            return Ok(());
        }

        if let Some(entry) = auth_dot_json
            .api_keys
            .iter_mut()
            .find(|entry| entry.id == id)
        {
            entry.name = name;
            storage.save(&auth_dot_json)?;
            self.reload();
            return Ok(());
        }

        Err(std::io::Error::other(format!(
            "Credential id {id} does not exist"
        )))
    }

    pub fn logout_credential_by_id(&self, id: u32) -> std::io::Result<bool> {
        let storage =
            create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
        let Some(mut auth_dot_json) = load_auth_dot_json_migrated(&storage)? else {
            return Ok(false);
        };

        let before = auth_dot_json.chatgpt_entries.len() + auth_dot_json.api_keys.len();

        auth_dot_json.chatgpt_entries.retain(|entry| entry.id != id);
        auth_dot_json.api_keys.retain(|entry| entry.id != id);

        let after = auth_dot_json.chatgpt_entries.len() + auth_dot_json.api_keys.len();
        if before == after {
            return Err(std::io::Error::other(format!(
                "Credential id {id} does not exist"
            )));
        }

        renumber_credentials(&mut auth_dot_json);

        if auth_dot_json.chatgpt_entries.is_empty()
            && auth_dot_json.api_keys.is_empty()
            && auth_dot_json.tokens.is_none()
            && auth_dot_json.openai_api_key.is_none()
        {
            storage.delete()?;
        } else {
            storage.save(&auth_dot_json)?;
        }

        self.reload();
        Ok(true)
    }

    pub fn logout_all_credentials(&self) -> std::io::Result<bool> {
        let storage =
            create_auth_storage(self.codex_home.clone(), self.auth_credentials_store_mode);
        let removed = storage.delete()?;
        self.reload();
        Ok(removed)
    }
}

fn renumber_credentials(auth_dot_json: &mut AuthDotJson) {
    #[derive(Clone)]
    enum Entry {
        ChatGpt(ChatGptAuthEntry),
        ApiKey(crate::auth::storage::ApiKeyAuthEntry),
    }

    let mut all: Vec<Entry> = auth_dot_json
        .chatgpt_entries
        .drain(..)
        .map(Entry::ChatGpt)
        .chain(auth_dot_json.api_keys.drain(..).map(Entry::ApiKey))
        .collect();
    all.sort_by_key(|entry| match entry {
        Entry::ChatGpt(inner) => inner.id,
        Entry::ApiKey(inner) => inner.id,
    });

    for (idx, entry) in all.iter_mut().enumerate() {
        let id = (idx as u32).saturating_add(1);
        match entry {
            Entry::ChatGpt(inner) => inner.id = id,
            Entry::ApiKey(inner) => inner.id = id,
        }
    }

    for entry in all {
        match entry {
            Entry::ChatGpt(inner) => auth_dot_json.chatgpt_entries.push(inner),
            Entry::ApiKey(inner) => auth_dot_json.api_keys.push(inner),
        }
    }
}
