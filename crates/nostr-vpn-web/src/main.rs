use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header, uri::Authority};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
#[cfg(test)]
use nostr_vpn_app_core::NativeNetworkDnsRole;
use nostr_vpn_app_core::{FfiApp, NativeAppAction, NativeAppState, SettingsPatch};
use nostr_vpn_core::build_info::version_with_build_commit;
use nostr_vpn_core::config::{AppConfig, maybe_autoconfigure_node, npub_for_pubkey_hex};
use qrcode::QrCode;
use serde_json::{Value, json};
use tower_http::services::{ServeDir, ServeFile};

mod ui_types;

use crate::ui_types::{
    AliasRequest, EndpointHintsRequest, ImportJoinRequest, JoinRequestAction, ManualNetworkRequest,
    NameRequest, NetworkDnsRequest, NetworkDnsRoleRequest, NetworkEnabledRequest, NetworkIdRequest,
    NetworkMeshRequest, NetworkNameRequest, NetworkPeerRequest, ParticipantRequest,
    QrMatrixRequest, QrMatrixResponse,
};

const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const DEFAULT_STATIC_DIR: &str = "/usr/share/nostr-vpn/web";

#[derive(Debug, Parser)]
#[command(name = "nvpn-web")]
#[command(about = "HTTP API for the nostr-vpn web UI")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8081")]
    listen: SocketAddr,
    /// Declare that a non-loopback listener is isolated behind an authenticated platform proxy.
    #[arg(long)]
    behind_trusted_proxy: bool,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    nvpn: Option<PathBuf>,
    #[arg(long)]
    static_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct ServerState {
    core: Arc<FfiApp>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;
type UiStateResponse = Json<Value>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nostr_vpn_web=info".into()),
        )
        .init();

    let args = Args::parse();
    validate_web_exposure(&args)?;
    let Args {
        listen,
        behind_trusted_proxy,
        config,
        nvpn,
        static_dir,
    } = args;
    let config_path = config.unwrap_or_else(default_config_path);
    ensure_config_exists(&config_path)?;
    let nvpn_bin = resolve_nvpn_cli_path(nvpn)?;
    let static_dir = static_dir.or_else(discover_static_dir);

    let state = ServerState {
        core: FfiApp::new_with_config_path(
            config_path,
            version_with_build_commit(env!("CARGO_PKG_VERSION")),
            Some(nvpn_bin),
        ),
    };

    let mut app = Router::new()
        .route("/api/health", get(health))
        .route("/api/tick", post(tick))
        .route("/api/connect_vpn", post(connect_vpn))
        .route("/api/disconnect_vpn", post(disconnect_vpn))
        .route("/api/add_network", post(add_network))
        .route("/api/manual_add_network", post(manual_add_network))
        .route("/api/rename_network", post(rename_network))
        .route("/api/set_network_mesh_id", post(set_network_mesh_id))
        .route("/api/remove_network", post(remove_network))
        .route("/api/set_network_enabled", post(set_network_enabled))
        .route("/api/set_network_dns", post(set_network_dns))
        .route("/api/set_network_dns_role", post(set_network_dns_role))
        .route(
            "/api/set_network_join_requests_enabled",
            post(set_network_join_requests_enabled),
        )
        .route("/api/add_participant", post(add_participant))
        .route("/api/add_admin", post(add_admin))
        .route("/api/import_join_request", post(import_join_request))
        .route("/api/remove_participant", post(remove_participant))
        .route("/api/remove_admin", post(remove_admin))
        .route("/api/accept_join_request", post(accept_join_request))
        .route("/api/reject_join_request", post(reject_join_request))
        .route("/api/set_participant_alias", post(set_participant_alias))
        .route(
            "/api/set_participant_endpoint_hints",
            post(set_participant_endpoint_hints),
        )
        .route("/api/qr_matrix", post(qr_matrix))
        .route("/api/update_settings", post(update_settings))
        .with_state(state.clone());

    if let Some(static_dir) = static_dir {
        let index_path = static_dir.join("index.html");
        if !index_path.exists() {
            return Err(anyhow!(
                "static web UI directory is missing {}",
                index_path.display()
            ));
        }
        tracing::info!("serving static web UI from {}", static_dir.display());
        app = app.fallback_service(
            ServeDir::new(static_dir).not_found_service(ServeFile::new(index_path)),
        );
    } else {
        tracing::info!("static web UI disabled");
    }
    app = app.layer(middleware::from_fn_with_state(
        behind_trusted_proxy,
        enforce_web_request_boundary,
    ));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("nostr-vpn web api listening on {}", listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

fn validate_web_exposure(args: &Args) -> Result<()> {
    if !args.listen.ip().is_loopback() && !args.behind_trusted_proxy {
        return Err(anyhow!(
            "refusing non-loopback web listener {}; pass --behind-trusted-proxy only when an authenticated platform proxy isolates this service",
            args.listen
        ));
    }
    Ok(())
}

async fn enforce_web_request_boundary(
    State(behind_trusted_proxy): State<bool>,
    request: Request,
    next: Next,
) -> Response {
    let mut hosts = request.headers().get_all(header::HOST).iter();
    let host = hosts.next().and_then(|value| value.to_str().ok());
    if hosts.next().is_some() || !web_host_allowed(host, behind_trusted_proxy) {
        return (StatusCode::FORBIDDEN, "request host rejected").into_response();
    }
    let mut origins = request.headers().get_all(header::ORIGIN).iter();
    let origin = match origins.next().map(HeaderValue::to_str).transpose() {
        Ok(origin) if origins.next().is_none() => origin,
        _ => return (StatusCode::FORBIDDEN, "invalid origin rejected").into_response(),
    };
    if !web_origin_allowed(origin, host) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }

    let api_request = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    if api_request {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn web_host_allowed(host: Option<&str>, behind_trusted_proxy: bool) -> bool {
    let Some(host) = host else {
        return false;
    };
    let Ok(authority) = host.parse::<Authority>() else {
        return false;
    };
    if host.contains('@') {
        return false;
    }
    // Matching Origin to Host alone permits DNS rebinding: both headers can name
    // an attacker-controlled domain that has started resolving to loopback.
    // An authenticated platform proxy owns this boundary when explicitly enabled.
    behind_trusted_proxy
        || authority.host().eq_ignore_ascii_case("localhost")
        || authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn web_origin_allowed(origin: Option<&str>, host: Option<&str>) -> bool {
    let Some(origin) = origin.map(str::trim) else {
        return true;
    };
    let Some(host) = host.map(str::trim).filter(|host| !host.is_empty()) else {
        return false;
    };
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    !authority.contains('/') && authority.eq_ignore_ascii_case(host)
}

async fn tick(State(state): State<ServerState>) -> ApiResult<UiStateResponse> {
    state_response(&state, NativeAppAction::Tick, false)
}

async fn connect_vpn(State(state): State<ServerState>) -> ApiResult<UiStateResponse> {
    dispatch(&state, NativeAppAction::ConnectVpn)
}

async fn disconnect_vpn(State(state): State<ServerState>) -> ApiResult<UiStateResponse> {
    dispatch(&state, NativeAppAction::DisconnectVpn)
}

async fn add_network(
    State(state): State<ServerState>,
    Json(request): Json<NameRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(&state, NativeAppAction::AddNetwork { name: request.name })
}

async fn manual_add_network(
    State(state): State<ServerState>,
    Json(request): Json<ManualNetworkRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::ManualAddNetwork {
            admin_npub: request.admin_npub,
            mesh_network_id: request.mesh_network_id,
        },
    )
}

async fn rename_network(
    State(state): State<ServerState>,
    Json(request): Json<NetworkNameRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::RenameNetwork {
            network_id: request.network_id,
            name: request.name,
        },
    )
}

async fn set_network_mesh_id(
    State(state): State<ServerState>,
    Json(request): Json<NetworkMeshRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetNetworkMeshId {
            network_id: request.network_id,
            mesh_id: request.mesh_id,
        },
    )
}

async fn remove_network(
    State(state): State<ServerState>,
    Json(request): Json<NetworkIdRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::RemoveNetwork {
            network_id: request.network_id,
        },
    )
}

async fn set_network_enabled(
    State(state): State<ServerState>,
    Json(request): Json<NetworkEnabledRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetNetworkEnabled {
            network_id: request.network_id,
            enabled: request.enabled,
        },
    )
}

async fn set_network_dns(
    State(state): State<ServerState>,
    Json(request): Json<NetworkDnsRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetNetworkDns {
            network_id: request.network_id,
            npub: request.npub,
            dns_override: request.dns_override,
        },
    )
}

/// Make one device the network's DNS box, a backup DNS box, or neither: the
/// Mac app's Make DNS box / Make backup DNS box / Remove DNS buttons.
async fn set_network_dns_role(
    State(state): State<ServerState>,
    Json(request): Json<NetworkDnsRoleRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetNetworkDnsRole {
            network_id: request.network_id,
            npub: request.npub,
            role: request.role,
        },
    )
}

async fn set_network_join_requests_enabled(
    State(state): State<ServerState>,
    Json(request): Json<NetworkEnabledRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetNetworkJoinRequestsEnabled {
            network_id: request.network_id,
            enabled: request.enabled,
        },
    )
}

async fn add_participant(
    State(state): State<ServerState>,
    Json(request): Json<ParticipantRequest>,
) -> ApiResult<UiStateResponse> {
    let ParticipantRequest {
        network_id,
        npub,
        alias,
        dns_backup,
    } = request;
    let action = if dns_backup {
        NativeAppAction::AddParticipantAsDnsBackup {
            network_id,
            npub,
            alias,
        }
    } else {
        NativeAppAction::AddParticipant {
            network_id,
            npub,
            alias,
        }
    };
    dispatch(&state, action)
}

async fn add_admin(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::AddAdmin {
            network_id: request.network_id,
            npub: request.npub,
        },
    )
}

async fn import_join_request(
    State(state): State<ServerState>,
    Json(request): Json<ImportJoinRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::ImportJoinRequest {
            request: request.request,
        },
    )
}

async fn remove_participant(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::RemoveParticipant {
            network_id: request.network_id,
            npub: request.npub,
        },
    )
}

async fn remove_admin(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::RemoveAdmin {
            network_id: request.network_id,
            npub: request.npub,
        },
    )
}

async fn accept_join_request(
    State(state): State<ServerState>,
    Json(request): Json<JoinRequestAction>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::AcceptJoinRequest {
            network_id: request.network_id,
            requester_npub: request.requester_npub,
        },
    )
}

async fn reject_join_request(
    State(state): State<ServerState>,
    Json(request): Json<JoinRequestAction>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::RejectJoinRequest {
            network_id: request.network_id,
            requester_npub: request.requester_npub,
        },
    )
}

async fn set_participant_alias(
    State(state): State<ServerState>,
    Json(request): Json<AliasRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetParticipantAlias {
            npub: request.npub,
            alias: request.alias,
        },
    )
}

async fn set_participant_endpoint_hints(
    State(state): State<ServerState>,
    Json(request): Json<EndpointHintsRequest>,
) -> ApiResult<UiStateResponse> {
    dispatch(
        &state,
        NativeAppAction::SetParticipantEndpointHints {
            npub: request.npub,
            endpoint_hints: request.endpoint_hints,
        },
    )
}

async fn update_settings(
    State(state): State<ServerState>,
    Json(patch): Json<SettingsPatch>,
) -> ApiResult<UiStateResponse> {
    dispatch(&state, NativeAppAction::UpdateSettings { patch })
}

async fn qr_matrix(Json(request): Json<QrMatrixRequest>) -> ApiResult<Json<QrMatrixResponse>> {
    Ok(Json(build_qr_matrix(&request.text).map_err(bad_request)?))
}

fn dispatch(state: &ServerState, action: NativeAppAction) -> ApiResult<UiStateResponse> {
    state_response(state, action, true)
}

/// Runs `action` and encodes the resulting state. The removed devices come
/// from the runtime's in-memory config, so every network the state lists
/// carries `removedDevices` and no poll reads the config (or its secrets)
/// off disk.
fn state_response(
    state: &ServerState,
    action: NativeAppAction,
    fail_on_error: bool,
) -> ApiResult<UiStateResponse> {
    let value = state.core.dispatch_with_config(action, |next, config| {
        let error = next.error.trim();
        if fail_on_error && !error.is_empty() {
            return Err(ApiError::bad_request(error));
        }
        let mut value = umbrel_state_value(next)?;
        attach_removed_devices(&mut value, config);
        Ok(value)
    })?;
    Ok(Json(value))
}

/// Add `removedDevices` to each network: the devices this admin removed, so
/// a dashboard can offer them back. The app state
/// has no such list (the removals are local tombstones, not roster data).
/// A network the config does not know gets no key.
fn attach_removed_devices(value: &mut Value, config: &AppConfig) {
    let Some(networks) = value.get_mut("networks").and_then(Value::as_array_mut) else {
        return;
    };
    for network in networks {
        let Some(object) = network.as_object_mut() else {
            continue;
        };
        let Some(entry) = object
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| config.network_by_id(id))
        else {
            continue;
        };
        let removed = entry
            .removed_devices
            .iter()
            .map(|pubkey| {
                json!({
                    "npub": npub_for_pubkey_hex(pubkey),
                    "alias": config.peer_alias(pubkey).unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        object.insert("removedDevices".to_string(), Value::Array(removed));
    }
}

fn umbrel_state_value(state: NativeAppState) -> ApiResult<Value> {
    let mut value = serde_json::to_value(state).map_err(internal_error)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ApiError::internal("failed to encode app state"))?;

    let vpn_enabled = object
        .get("vpnEnabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let vpn_active = object
        .get("vpnActive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let vpn_status = object
        .get("vpnStatus")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !vpn_enabled
        && !vpn_active
        && (vpn_status.is_empty()
            || vpn_status == "Disconnected"
            || vpn_status == "Daemon running"
            || vpn_status == "Daemon not running"
            || vpn_status == "Listening for join requests"
            || vpn_status == "Paused")
    {
        object.insert("vpnStatus".to_string(), json!("VPN off"));
    }

    object.insert("platform".to_string(), json!("umbrel"));
    object.insert("mobile".to_string(), json!(false));
    object.insert("vpnControlSupported".to_string(), json!(true));
    object.insert("cliInstallSupported".to_string(), json!(false));
    object.insert("startupSettingsSupported".to_string(), json!(false));
    object.insert("trayBehaviorSupported".to_string(), json!(false));
    object.insert("runtimeStatusDetail".to_string(), json!(""));
    object.insert("cliInstalled".to_string(), json!(false));
    object.insert("serviceSupported".to_string(), json!(false));
    object.insert("serviceEnablementSupported".to_string(), json!(false));
    object.insert("serviceInstalled".to_string(), json!(false));
    object.insert("serviceDisabled".to_string(), json!(false));
    object.insert("serviceRunning".to_string(), json!(false));
    object.insert(
        "serviceStatusDetail".to_string(),
        json!("Managed directly by the Umbrel app"),
    );
    for field in [
        "wireguardExitPrivateKey",
        "wireguardExitPeerPresharedKey",
        "wireguardExitConfig",
    ] {
        object.insert(field.to_string(), json!(""));
    }
    Ok(value)
}

fn build_qr_matrix(text: &str) -> Result<QrMatrixResponse> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(QrMatrixResponse {
            width: 0,
            cells: Vec::new(),
        });
    }

    let code = QrCode::new(trimmed.as_bytes())?;
    let width = code.width();
    let cells = code
        .to_colors()
        .into_iter()
        .map(|color| matches!(color, qrcode::Color::Dark))
        .collect();
    Ok(QrMatrixResponse { width, cells })
}

fn ensure_config_exists(path: &Path) -> Result<()> {
    let mut config = if path.exists() {
        AppConfig::load(path).with_context(|| format!("failed to load {}", path.display()))?
    } else {
        generated_umbrel_config()
    };
    prepare_config_for_save(&mut config);
    config
        .save(path)
        .with_context(|| format!("failed to save {}", path.display()))
}

fn generated_umbrel_config() -> AppConfig {
    let mut config = AppConfig::generated_without_networks();
    config.add_network("Network 1");
    config
}

fn prepare_config_for_save(config: &mut AppConfig) {
    config.ensure_defaults();
    maybe_autoconfigure_node(config);
    ensure_first_owned_network_selected(config);
    if config.self_magic_dns_name().is_none() && config.ensure_self_magic_dns_alias().is_ok() {
        config.ensure_defaults();
    }
}

fn ensure_first_owned_network_selected(config: &mut AppConfig) {
    if config.active_network_opt().is_some() || config.networks.len() != 1 {
        return;
    }

    let Ok(own_pubkey) = config.own_nostr_pubkey_hex() else {
        return;
    };
    let network = &config.networks[0];
    if !network.devices.is_empty() || !network.admins.iter().any(|admin| admin == &own_pubkey) {
        return;
    }

    let network_id = network.id.clone();
    let _ = config.set_network_enabled(&network_id, true);
}

fn default_config_path() -> PathBuf {
    dirs::config_dir().map_or_else(
        || PathBuf::from("nvpn.toml"),
        |dir| dir.join("nvpn").join("config.toml"),
    )
}

fn discover_static_dir() -> Option<PathBuf> {
    let path = PathBuf::from(DEFAULT_STATIC_DIR);
    path.join("index.html").exists().then_some(path)
}

fn resolve_nvpn_cli_path(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return validate_executable(&path);
    }
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        return validate_executable(&PathBuf::from(path));
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(nvpn_binary_name());
            if candidate.exists()
                && let Ok(validated) = validate_executable(&candidate)
            {
                return Ok(validated);
            }
        }
    }
    Err(anyhow!(
        "nvpn CLI binary not found; set {} or add nvpn to PATH",
        NVPN_BIN_ENV
    ))
}

#[cfg(target_os = "windows")]
fn nvpn_binary_name() -> &'static str {
    "nvpn.exe"
}

#[cfg(not(target_os = "windows"))]
fn nvpn_binary_name() -> &'static str {
    "nvpn"
}

fn validate_executable(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(anyhow!("{} is not executable", canonical.display()));
        }
    }
    Ok(canonical)
}

fn bad_request(error: anyhow::Error) -> ApiError {
    ApiError::bad_request(error.to_string())
}

fn internal_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn dns_role_request_takes_the_three_roles_and_nothing_else() {
        for (text, role) in [
            ("primary", NativeNetworkDnsRole::Primary),
            ("backup", NativeNetworkDnsRole::Backup),
            ("none", NativeNetworkDnsRole::None),
        ] {
            let request: NetworkDnsRoleRequest = serde_json::from_str(&format!(
                r#"{{"networkId":"network-1","npub":"npub1x","role":"{text}"}}"#
            ))
            .expect("role request");
            assert_eq!(request.role, role);
            assert_eq!(request.network_id, "network-1");
        }
        for bad in ["Primary", "dns", ""] {
            assert!(
                serde_json::from_str::<NetworkDnsRoleRequest>(&format!(
                    r#"{{"networkId":"network-1","npub":"npub1x","role":"{bad}"}}"#
                ))
                .is_err(),
                "accepted role {bad:?}"
            );
        }
    }

    async fn boundary_response(behind_trusted_proxy: bool, headers: &str) -> String {
        let app = Router::new()
            .route("/api/qr_matrix", post(qr_matrix))
            .layer(middleware::from_fn_with_state(
                behind_trusted_proxy,
                enforce_web_request_boundary,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind web test server");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect to web test server");
            let body = r#"{"text":"hello"}"#;
            let request = format!(
                "POST /api/qr_matrix HTTP/1.1\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .await
                .expect("send API request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read API response");
            response
        })
        .await;
        server.abort();
        response.expect("API request completed")
    }

    #[tokio::test]
    async fn web_boundary_rejects_dns_rebinding_before_api_dispatch() {
        for origin in ["", "Origin: http://attacker.example:8081\r\n"] {
            let response =
                boundary_response(false, &format!("Host: attacker.example:8081\r\n{origin}")).await;
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
            assert!(!response.contains("\"cells\""));
        }
    }

    #[tokio::test]
    async fn web_boundary_accepts_loopback_api_requests() {
        for host in ["127.0.0.1:8081", "localhost:8081", "[::1]:8081"] {
            let response =
                boundary_response(false, &format!("Host: {host}\r\nOrigin: http://{host}\r\n"))
                    .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.contains("cache-control: no-store\r\n"));
            assert!(response.contains("\"cells\""));
        }
        let response = boundary_response(false, "Host: localhost:8081\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    #[tokio::test]
    async fn web_boundary_preserves_trusted_proxy_origin_checks() {
        let response =
            boundary_response(true, "Host: vpn.example\r\nOrigin: https://vpn.example\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        for origin in [
            "Origin: https://attacker.example\r\n",
            "Origin: null\r\n",
            "Origin: https://vpn.example\r\nOrigin: https://attacker.example\r\n",
            "Origin: https://vpn.example/\u{80}\r\n",
        ] {
            let response = boundary_response(true, &format!("Host: vpn.example\r\n{origin}")).await;
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        }
    }

    #[test]
    fn default_listen_address_is_loopback() {
        let args = Args::parse_from(["nvpn-web"]);

        assert!(args.listen.ip().is_loopback());
        assert_eq!(args.listen.port(), 8081);
        assert!(!args.behind_trusted_proxy);
        assert!(validate_web_exposure(&args).is_ok());
    }

    #[test]
    fn non_loopback_listen_requires_explicit_trusted_proxy() {
        let args = Args::parse_from(["nvpn-web", "--listen", "0.0.0.0:38080"]);

        let error = validate_web_exposure(&args).expect_err("public bind must be explicit");

        assert!(error.to_string().contains("--behind-trusted-proxy"));
    }

    #[test]
    fn trusted_proxy_allows_non_loopback_listen() {
        let args = Args::parse_from([
            "nvpn-web",
            "--listen",
            "0.0.0.0:38080",
            "--behind-trusted-proxy",
        ]);

        assert!(validate_web_exposure(&args).is_ok());
    }

    #[test]
    fn browser_origin_must_match_request_host() {
        assert!(web_origin_allowed(
            Some("https://vpn.example"),
            Some("vpn.example")
        ));
        assert!(web_origin_allowed(
            Some("http://vpn.example"),
            Some("vpn.example")
        ));
        assert!(web_origin_allowed(None, Some("vpn.example")));
        assert!(!web_origin_allowed(
            Some("https://attacker.example"),
            Some("vpn.example")
        ));
        assert!(!web_origin_allowed(Some("null"), Some("vpn.example")));
    }

    #[test]
    fn qr_matrix_encodes_join_request_text() {
        let matrix = build_qr_matrix("nvpn://join-request/example").expect("qr matrix");

        assert!(matrix.width > 0);
        assert_eq!(matrix.cells.len(), matrix.width * matrix.width);
        assert!(matrix.cells.iter().any(|cell| *cell));
    }

    #[test]
    fn add_participant_request_reads_dns_backup_and_defaults_it_off() {
        let plain: ParticipantRequest =
            serde_json::from_str(r#"{"networkId":"n","npub":"npub1x","alias":null}"#)
                .expect("plain add");
        assert!(!plain.dns_backup);
        let backup: ParticipantRequest = serde_json::from_str(
            r#"{"networkId":"n","npub":"npub1x","alias":"pi","dnsBackup":true}"#,
        )
        .expect("backup add");
        assert!(backup.dns_backup);
    }

    #[test]
    fn removed_devices_are_listed_per_network_by_entry_id() {
        let mut config = AppConfig::generated_without_networks();
        config.add_network("Home");
        config.add_network("Work");
        let gone = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        config.networks[0].removed_devices = vec![gone.to_string()];
        let home = config.networks[0].id.clone();
        let work = config.networks[1].id.clone();
        let mut value = json!({
            "networks": [{ "id": work }, { "id": home }, { "id": "not-in-config" }],
        });

        attach_removed_devices(&mut value, &config);

        assert_eq!(value["networks"][0]["removedDevices"], json!([]));
        assert_eq!(
            value["networks"][1]["removedDevices"][0]["npub"],
            npub_for_pubkey_hex(gone)
        );
        assert!(value["networks"][2].get("removedDevices").is_none());
    }

    /// The removed devices come from the runtime, not a reload: with the
    /// config file gone from disk, every network still carries the key.
    #[test]
    fn state_response_lists_removed_devices_without_reading_the_config_file() {
        let dir = std::env::temp_dir().join(format!(
            "nvpn-web-removed-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        let state = ServerState {
            core: FfiApp::new_with_config_path(config_path.clone(), String::new(), None),
        };
        let _ = dispatch(
            &state,
            NativeAppAction::AddNetwork {
                name: "Home".to_string(),
            },
        )
        .expect("add network");
        let _ = fs::remove_file(&config_path);

        let Json(value) = state_response(&state, NativeAppAction::Tick, false).expect("tick");

        let networks = value["networks"].as_array().expect("networks");
        assert!(!networks.is_empty());
        for network in networks {
            assert_eq!(network["removedDevices"], json!([]), "{network}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn umbrel_state_hides_desktop_service_controls() {
        let state = NativeAppState {
            platform: "desktop".to_string(),
            cli_install_supported: true,
            startup_settings_supported: true,
            tray_behavior_supported: true,
            service_supported: true,
            service_enablement_supported: true,
            service_installed: true,
            service_running: true,
            vpn_status: "Paused".to_string(),
            ..NativeAppState::default()
        };

        let value = umbrel_state_value(state).expect("state value");

        assert_eq!(value["platform"], "umbrel");
        assert_eq!(value["vpnStatus"], "VPN off");
        assert_eq!(value["cliInstallSupported"], false);
        assert_eq!(value["startupSettingsSupported"], false);
        assert_eq!(value["trayBehaviorSupported"], false);
        assert_eq!(value["serviceSupported"], false);
        assert_eq!(value["serviceEnablementSupported"], false);
        assert_eq!(value["serviceInstalled"], false);
        assert_eq!(value["serviceRunning"], false);
        assert_eq!(
            value["serviceStatusDetail"],
            "Managed directly by the Umbrel app"
        );
    }

    #[test]
    fn web_state_does_not_serialize_network_credentials() {
        let state = NativeAppState {
            wireguard_exit_private_key: "private-key".to_string(),
            wireguard_exit_peer_preshared_key: "preshared-key".to_string(),
            wireguard_exit_config: "[Interface]\nPrivateKey = private-key".to_string(),
            ..NativeAppState::default()
        };

        let value = umbrel_state_value(state).expect("state value");
        let encoded = serde_json::to_string(&value).expect("state JSON");

        assert_eq!(value["wireguardExitPrivateKey"], "");
        assert_eq!(value["wireguardExitPeerPresharedKey"], "");
        assert_eq!(value["wireguardExitConfig"], "");
        assert!(!encoded.contains("private-key"));
        assert!(!encoded.contains("preshared-key"));
    }

    #[test]
    fn umbrel_state_shows_vpn_off_while_join_listener_is_idle() {
        let state = NativeAppState {
            vpn_enabled: false,
            vpn_active: false,
            vpn_status: "Listening for join requests".to_string(),
            ..NativeAppState::default()
        };

        let value = umbrel_state_value(state).expect("state value");

        assert_eq!(value["vpnStatus"], "VPN off");
    }

    #[test]
    fn generated_umbrel_config_seeds_self_magic_dns_name() {
        let mut config = generated_umbrel_config();
        prepare_config_for_save(&mut config);

        let name = config
            .self_magic_dns_name()
            .expect("first-run Umbrel config should have a self MagicDNS name");

        assert!(name.ends_with(".nvpn"));
    }

    #[test]
    fn existing_daemon_created_config_gets_self_magic_dns_name() {
        let mut config = AppConfig::generated();
        config.ensure_defaults();
        assert!(config.active_network_opt().is_none());
        assert!(config.self_magic_dns_name().is_none());

        prepare_config_for_save(&mut config);

        assert!(config.active_network_opt().is_some());
        let name = config
            .self_magic_dns_name()
            .expect("web bootstrap should seed missing self MagicDNS names");
        assert!(name.ends_with(".nvpn"));
    }

    #[test]
    fn existing_joined_config_keeps_disabled_network_unselected() {
        let mut config = AppConfig::generated();
        config.ensure_defaults();
        let own_pubkey = config.own_nostr_pubkey_hex().expect("own pubkey");
        config.networks[0].devices.push(own_pubkey);
        assert!(config.active_network_opt().is_none());

        prepare_config_for_save(&mut config);

        assert!(config.active_network_opt().is_none());
    }
}
