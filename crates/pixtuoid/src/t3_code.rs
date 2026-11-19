//! Read-only T3 Code observer: exchanges a one-time pairing credential for an
//! `orchestration:read` token and polls thread lifecycle without reading prompts.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use pixtuoid_core::AgentId;
use pixtuoid_core::source::{AgentEvent, Resolution, Source, TaggedSender, ToolDetail, Transport};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) const SOURCE_NAME: &str = "t3-code";
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_SCOPE: &str = "orchestration:read";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const BOOTSTRAP_TOKEN_TYPE: &str = "urn:t3:params:oauth:token-type:environment-bootstrap";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const PROTOCOL_HEADER: &str = "x-t3-orchestration-protocol";
const PROTOCOL_VERSION: &str = "2";
const MAX_THREAD_ID_BYTES: usize = 256;
const MAX_CREDENTIAL_BYTES: u64 = 8 * 1024;
const MAX_SHELL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
// Bound the path copied into each queued `SessionStart` event.
const MAX_WORKSPACE_ROOT_BYTES: usize = 128 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = MAX_CREDENTIAL_BYTES as usize;
const OBSERVED_CALL_ID: &str = "t3-observed-turn";
const OBSERVED_TOOL_NAME: &str = "T3";
const OBSERVED_TOOL_DETAIL: &str = "Working in T3 Code";
const PERMISSION_REASON: &str = "T3 Code is waiting for permission";
const INPUT_REASON: &str = "T3 Code is waiting for input";

#[derive(Clone)]
pub(crate) struct T3CodeCredential {
    base_url: String,
    token: String,
    expires_at_ms: u64,
}

impl fmt::Debug for T3CodeCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("T3CodeCredential")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential {
    base_url: String,
    token: String,
    expires_at_ms: u64,
    scope: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservedStatus {
    Active,
    Permission,
    Input,
    Done,
}

struct ObservedThread {
    id: String,
    project_dir: Arc<str>,
    status: ObservedStatus,
}

#[derive(Clone, Copy)]
struct TrackedThread {
    agent_id: AgentId,
    status: ObservedStatus,
}

pub(crate) fn has_credential() -> bool {
    load_credential().is_some()
}

pub(crate) fn load_credential() -> Option<T3CodeCredential> {
    load_credential_at(&credential_path(), unix_time_ms().ok()?)
}

pub(crate) fn save_credential(credential: &T3CodeCredential) -> Result<()> {
    save_credential_at(&credential_path(), credential)
}

fn save_credential_at(path: &Path, credential: &T3CodeCredential) -> Result<()> {
    if credential.token.trim().is_empty()
        || credential.expires_at_ms <= unix_time_ms()?
        || shell_snapshot_url(&credential.base_url).is_err()
    {
        bail!("Cannot save an invalid or expired T3 Code credential.");
    }

    let mut serialized = serde_json::to_vec(&StoredCredential {
        base_url: credential.base_url.clone(),
        token: credential.token.clone(),
        expires_at_ms: credential.expires_at_ms,
        scope: TOKEN_SCOPE.to_owned(),
    })
    .context("serializing the T3 Code credential")?;
    serialized.push(b'\n');
    if serialized.len() > MAX_CREDENTIAL_BYTES as usize {
        bail!("T3 Code credential exceeds the {MAX_CREDENTIAL_BYTES}-byte storage limit.");
    }

    let directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("T3 Code credential path has no parent."))?;
    std::fs::create_dir_all(directory).context("creating the T3 Code credential directory")?;
    set_private_directory_permissions(directory)?;

    let mut temp = tempfile::NamedTempFile::new_in(directory)
        .context("creating a temporary T3 Code credential file")?;
    set_private_file_permissions(temp.path())?;
    temp.write_all(&serialized)
        .context("writing the T3 Code credential")?;
    temp.as_file()
        .sync_all()
        .context("syncing the T3 Code credential")?;
    temp.persist(path)
        .map_err(|error| error.error)
        .context("installing the T3 Code credential")?;
    set_private_file_permissions(path)?;
    Ok(())
}

pub(crate) fn disconnect() -> Result<()> {
    let path = credential_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "removing the T3 Code credential at {}",
                crate::display_path(&path)
            )
        }),
    }
}

fn credential_path() -> PathBuf {
    crate::config::config_path()
        .with_file_name("t3-code")
        .join("connection.json")
}

fn load_credential_at(path: &Path, now_ms: u64) -> Option<T3CodeCredential> {
    let file = std::fs::File::open(path).ok()?;
    let mut limited = file.take(MAX_CREDENTIAL_BYTES + 1);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut limited, &mut bytes).ok()?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return None;
    }
    let stored: StoredCredential = serde_json::from_slice(&bytes).ok()?;
    if stored.scope != TOKEN_SCOPE
        || stored.token.trim().is_empty()
        || stored.expires_at_ms <= now_ms
        || shell_snapshot_url(&stored.base_url).is_err()
    {
        return None;
    }
    Some(T3CodeCredential {
        base_url: stored.base_url,
        token: stored.token,
        expires_at_ms: stored.expires_at_ms,
    })
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .context("restricting T3 Code credential directory permissions")
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("restricting T3 Code credential file permissions")
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn unix_time_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis(),
    )
    .context("system clock is outside the supported range")
}

fn validate_base_url(input: &str) -> Result<Url> {
    let url = Url::parse(input).context("T3 Code URL must be an absolute HTTP(S) URL.")?;
    let host = url.host_str().unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("T3 Code URL must use HTTPS, or HTTP on loopback, without embedded credentials.");
    }
    Ok(url)
}

fn parse_pairing_url(input: &str) -> Result<(String, String)> {
    let mut url = Url::parse(input).context("T3 Code pairing URL must be absolute.")?;
    let fragment = url.fragment().unwrap_or_default().to_owned();
    url.set_fragment(None);
    if url.query().is_some() {
        bail!("T3 Code pairing URL must not contain a query.");
    }
    let trimmed_path = url.path().trim_end_matches('/').to_owned();
    if !trimmed_path.ends_with("/pair") && trimmed_path != "pair" {
        bail!("T3 Code pairing URL must point to a /pair page.");
    }

    let mut fragment_query = url.clone();
    fragment_query.set_query(Some(&fragment));
    let token = fragment_query
        .query_pairs()
        .find_map(|(key, value)| (key == "token").then(|| value.trim().to_owned()))
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("T3 Code pairing URL is missing its one-time token."))?;

    url.set_query(None);
    let base_path = trimmed_path
        .strip_suffix("/pair")
        .or_else(|| trimmed_path.strip_suffix("pair"))
        .unwrap_or_default()
        .to_owned();
    url.set_path(if base_path.is_empty() {
        "/"
    } else {
        &base_path
    });
    validate_base_url(url.as_str())?;
    let base_url = url.as_str().trim_end_matches('/').to_owned();
    Ok((base_url, token))
}

pub(crate) enum PairingInput {
    Url(String),
    Code(String),
}

pub(crate) fn parse_pairing_input(input: &str) -> Result<PairingInput> {
    let input = input.trim();
    if input.is_empty() {
        bail!("T3 Code pairing URL or code is required.");
    }
    if input.contains("://") {
        parse_pairing_url(input)?;
        Ok(PairingInput::Url(input.to_owned()))
    } else {
        if input.chars().any(char::is_whitespace) {
            bail!("T3 Code pairing code must not contain whitespace.");
        }
        Ok(PairingInput::Code(input.to_owned()))
    }
}

fn shell_snapshot_url(base_url: &str) -> Result<String> {
    let mut url = validate_base_url(base_url)?;
    let base_path = url.path().trim_end_matches('/');
    let endpoint = format!("{base_path}/api/orchestration/shell");
    url.set_path(&endpoint);
    Ok(url.to_string())
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the T3 Code HTTP client")
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    limit: usize,
    description: &str,
) -> Result<Vec<u8>> {
    let declared_length = response.content_length();
    if declared_length.is_some_and(|length| length > limit as u64) {
        bail!("T3 Code {description} response exceeds the {limit}-byte limit.");
    }
    let capacity = declared_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default();
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading T3 Code {description} response"))?
    {
        if chunk.len() > limit - body.len() {
            bail!("T3 Code {description} response exceeds the {limit}-byte limit.");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) async fn exchange_pairing_url(input: &str) -> Result<T3CodeCredential> {
    let (base_url, bootstrap_token) = parse_pairing_url(input)?;
    exchange_pairing_token(base_url, &bootstrap_token).await
}

pub(crate) async fn exchange_pairing_code(
    server_url: &str,
    pairing_code: &str,
) -> Result<T3CodeCredential> {
    let code = pairing_code.trim();
    if code.is_empty() || code.chars().any(char::is_whitespace) {
        bail!("T3 Code pairing code must not be empty or contain whitespace.");
    }
    let server_url = validate_base_url(server_url)?;
    let base_url = server_url.as_str().trim_end_matches('/').to_owned();
    exchange_pairing_token(base_url, code).await
}

async fn exchange_pairing_token(
    base_url: String,
    bootstrap_token: &str,
) -> Result<T3CodeCredential> {
    let client = http_client()?;
    let response = client
        .post(format!("{base_url}/oauth/token"))
        .form(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", bootstrap_token),
            ("subject_token_type", BOOTSTRAP_TOKEN_TYPE),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("scope", TOKEN_SCOPE),
            ("client_label", "pixtuoid observer"),
        ])
        .send()
        .await
        .context("requesting a T3 Code read-only token")?;
    if !response.status().is_success() {
        bail!(
            "T3 Code token exchange failed (HTTP {}).",
            response.status().as_u16()
        );
    }

    let bytes = read_bounded_response(response, MAX_TOKEN_RESPONSE_BYTES, "token exchange")
        .await
        .context("reading the T3 Code token exchange response")?;
    let body: Value =
        serde_json::from_slice(&bytes).context("T3 Code token exchange returned invalid JSON")?;
    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("T3 Code did not issue an access token."))?;
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| anyhow::anyhow!("T3 Code returned an invalid token lifetime."))?;
    if body.get("token_type").and_then(Value::as_str) != Some("Bearer")
        || body.get("scope").and_then(Value::as_str) != Some(TOKEN_SCOPE)
    {
        bail!("T3 Code did not issue an orchestration:read bearer token.");
    }
    let lifetime_ms = expires_in
        .checked_mul(1_000)
        .ok_or_else(|| anyhow::anyhow!("T3 Code token lifetime is outside the supported range."))?;
    let expires_at_ms = unix_time_ms()?
        .checked_add(lifetime_ms)
        .ok_or_else(|| anyhow::anyhow!("T3 Code token expiry is outside the supported range."))?;

    Ok(T3CodeCredential {
        base_url,
        token: token.to_owned(),
        expires_at_ms,
    })
}

fn string_field(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn timestamp_field(value: Option<&Value>, field: &str) -> Result<Option<i64>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let timestamp = if let Some(timestamp) = value.as_i64() {
        timestamp
    } else if let Some(text) = value.as_str() {
        chrono::DateTime::parse_from_rfc3339(text)
            .with_context(|| format!("invalid T3 Code {field}"))?
            .timestamp_millis()
    } else {
        bail!("invalid T3 Code {field}");
    };
    Ok(Some(timestamp))
}

fn is_settled(thread: &Map<String, Value>) -> Result<bool> {
    if thread.get("settledOverride").and_then(Value::as_str) == Some("settled") {
        return Ok(true);
    }
    if thread.get("settledOverride").and_then(Value::as_str) == Some("active") {
        return Ok(false);
    }
    let settled_at = timestamp_field(thread.get("settledAt"), "settledAt")?;
    let unsettled_at = timestamp_field(thread.get("unsettledAt"), "unsettledAt")?;
    Ok(settled_at.is_some_and(|settled| unsettled_at.is_none_or(|unsettled| settled >= unsettled)))
}

fn normalize_shell_snapshot(raw: Value) -> Result<Vec<ObservedThread>> {
    let root = raw
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid T3 Code shell snapshot"))?;
    let projects = root
        .get("projects")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("invalid T3 Code shell snapshot"))?;
    let threads = root
        .get("threads")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("invalid T3 Code shell snapshot"))?;
    let mut project_dirs = HashMap::new();
    for project in projects {
        let project = project
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code project entry"))?;
        let id = string_field(project.get("id"))
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code project identity"))?;
        let workspace_root = string_field(project.get("workspaceRoot"))
            .filter(|path| path.len() <= MAX_WORKSPACE_ROOT_BYTES)
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code project identity"))?;
        project_dirs.insert(id.to_owned(), Arc::<str>::from(workspace_root));
    }

    let mut observed = Vec::new();
    let mut expanded_workspace_root_bytes = 0usize;
    for value in threads {
        let thread = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code thread entry"))?;
        let id = string_field(thread.get("id"))
            .filter(|id| id.len() <= MAX_THREAD_ID_BYTES)
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code thread identity"))?;
        if thread
            .get("archivedAt")
            .is_some_and(|value| !value.is_null())
            || thread
                .get("deletedAt")
                .is_some_and(|value| !value.is_null())
            || is_settled(thread)?
        {
            continue;
        }

        let status = thread
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("invalid T3 Code thread status"))?;
        if !matches!(
            status,
            "idle" | "running" | "completed" | "failed" | "interrupted"
        ) {
            bail!("invalid T3 Code thread status");
        }
        if status == "failed" {
            continue;
        }
        let has_provider_thread = string_field(thread.get("activeProviderThreadId")).is_some();
        let has_active_run = string_field(thread.get("activeRunId")).is_some();
        if !has_provider_thread && !has_active_run && status != "running" {
            continue;
        }

        let observed_status = if thread.get("hasPendingApprovals") == Some(&Value::Bool(true)) {
            ObservedStatus::Permission
        } else if thread.get("hasPendingUserInput") == Some(&Value::Bool(true)) {
            ObservedStatus::Input
        } else if status == "running"
            || thread.get("activityRunStatus").and_then(Value::as_str) == Some("running")
            || has_active_run
        {
            ObservedStatus::Active
        } else {
            ObservedStatus::Done
        };
        let project_id = string_field(thread.get("projectId")).unwrap_or_default();
        let project_dir = project_dirs
            .get(project_id)
            .cloned()
            .unwrap_or_else(|| Arc::from(""));
        // The reducer retains one cwd per agent, so shared roots still expand per thread.
        if !project_dir.is_empty() {
            expanded_workspace_root_bytes = expanded_workspace_root_bytes
                .checked_add(project_dir.len())
                .filter(|size| *size <= MAX_SHELL_RESPONSE_BYTES)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "T3 Code shell snapshot expands workspace roots beyond the response size limit"
                    )
                })?;
        }
        observed.push(ObservedThread {
            id: id.to_owned(),
            project_dir,
            status: observed_status,
        });
    }
    Ok(observed)
}

fn transition_events(
    agent_id: AgentId,
    previous: Option<ObservedStatus>,
    next: ObservedStatus,
) -> Vec<AgentEvent> {
    if previous == Some(next) {
        return Vec::new();
    }
    let was_waiting = matches!(
        previous,
        Some(ObservedStatus::Permission | ObservedStatus::Input)
    );
    let mut events = Vec::new();
    if was_waiting && matches!(next, ObservedStatus::Active | ObservedStatus::Done) {
        events.push(AgentEvent::UserActionResolved {
            agent_id,
            by: Resolution::Call(OBSERVED_CALL_ID.to_owned()),
        });
    }
    if previous == Some(ObservedStatus::Active)
        && matches!(
            next,
            ObservedStatus::Permission | ObservedStatus::Input | ObservedStatus::Done
        )
    {
        events.push(AgentEvent::ToolUseEnd {
            agent_id,
            tool_use_id: Some(OBSERVED_CALL_ID.to_owned()),
        });
    }
    events.extend(status_events(agent_id, next));
    events
}

fn status_events(agent_id: AgentId, status: ObservedStatus) -> Vec<AgentEvent> {
    match status {
        ObservedStatus::Active => vec![AgentEvent::tool_use_start(
            agent_id,
            Some(OBSERVED_CALL_ID.to_owned()),
            Some(ToolDetail::Generic {
                display: OBSERVED_TOOL_DETAIL.to_owned(),
            }),
        )],
        ObservedStatus::Permission | ObservedStatus::Input => {
            vec![AgentEvent::UserActionRequest {
                agent_id,
                reason: Some(
                    if status == ObservedStatus::Permission {
                        PERMISSION_REASON
                    } else {
                        INPUT_REASON
                    }
                    .to_owned(),
                ),
                tool_use_id: Some(OBSERVED_CALL_ID.to_owned()),
                tool_name: Some(OBSERVED_TOOL_NAME.to_owned()),
                turn: None,
            }]
        }
        ObservedStatus::Done => vec![AgentEvent::TurnEnd {
            agent_id,
            turn: None,
        }],
    }
}

pub(crate) struct T3CodeSource {
    credential: T3CodeCredential,
}

impl T3CodeSource {
    pub(crate) fn new(credential: T3CodeCredential) -> Self {
        Self { credential }
    }

    async fn poll(&self, client: &reqwest::Client, endpoint: &str) -> Result<Vec<ObservedThread>> {
        let response = client
            .get(endpoint)
            .bearer_auth(&self.credential.token)
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION)
            .send()
            .await
            .context("requesting a T3 Code shell snapshot")?;
        if !response.status().is_success() {
            bail!(
                "T3 Code shell snapshot failed (HTTP {}).",
                response.status().as_u16()
            );
        }
        let bytes = read_bounded_response(response, MAX_SHELL_RESPONSE_BYTES, "shell snapshot")
            .await
            .context("reading the T3 Code shell snapshot response")?;
        normalize_shell_snapshot(
            serde_json::from_slice(&bytes)
                .context("T3 Code returned invalid shell snapshot JSON")?,
        )
    }

    async fn send_session_start(
        &self,
        tx: &TaggedSender,
        thread: &ObservedThread,
        agent_id: AgentId,
    ) -> Result<bool> {
        let cwd = if thread.project_dir.is_empty() {
            PathBuf::from("T3 Code")
        } else {
            PathBuf::from(thread.project_dir.as_ref())
        };
        send_event(
            tx,
            AgentEvent::SessionStart {
                agent_id,
                source: SOURCE_NAME.to_owned(),
                session_id: thread.id.clone(),
                cwd,
                parent_id: None,
            },
        )
        .await
    }

    async fn reconcile(
        &self,
        threads: Vec<ObservedThread>,
        tracked: &mut HashMap<String, TrackedThread>,
        tx: &TaggedSender,
        reconnected: bool,
    ) -> Result<bool> {
        let mut seen = HashSet::new();
        for thread in threads {
            seen.insert(thread.id.clone());
            let tracked_thread = match tracked.get(&thread.id).copied() {
                Some(tracked_thread) => {
                    if reconnected
                        && !self
                            .send_session_start(tx, &thread, tracked_thread.agent_id)
                            .await?
                    {
                        return Ok(false);
                    }
                    tracked_thread
                }
                None => {
                    let agent_id = AgentId::from_parts(SOURCE_NAME, &thread.id);
                    if !self.send_session_start(tx, &thread, agent_id).await? {
                        return Ok(false);
                    }
                    let tracked_thread = TrackedThread {
                        agent_id,
                        status: ObservedStatus::Done,
                    };
                    tracked.insert(thread.id.clone(), tracked_thread);
                    tracked_thread
                }
            };

            let mut events = transition_events(
                tracked_thread.agent_id,
                Some(tracked_thread.status),
                thread.status,
            );
            if reconnected && tracked_thread.status == thread.status {
                events.extend(status_events(tracked_thread.agent_id, thread.status));
            }
            for event in events {
                if !send_event(tx, event).await? {
                    return Ok(false);
                }
            }
            tracked
                .get_mut(&thread.id)
                .ok_or_else(|| anyhow::anyhow!("T3 Code tracking entry was not inserted"))?
                .status = thread.status;
            if !send_event(
                tx,
                AgentEvent::ProofOfLife {
                    agent_id: tracked_thread.agent_id,
                },
            )
            .await?
            {
                return Ok(false);
            }
        }

        let removed: Vec<String> = tracked
            .keys()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect();
        for id in removed {
            if let Some(thread) = tracked.remove(&id) {
                for event in
                    transition_events(thread.agent_id, Some(thread.status), ObservedStatus::Done)
                {
                    if !send_event(tx, event).await? {
                        return Ok(false);
                    }
                }
                if !send_event(
                    tx,
                    AgentEvent::SessionEnd {
                        agent_id: thread.agent_id,
                        as_child: false,
                    },
                )
                .await?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Source for T3CodeSource {
    fn name(&self) -> &str {
        SOURCE_NAME
    }

    async fn run(self: Box<Self>, tx: TaggedSender) -> Result<()> {
        let endpoint = shell_snapshot_url(&self.credential.base_url)?;
        let client = http_client()?;
        let mut tracked = HashMap::new();
        let mut warning_shown = false;
        loop {
            if tx.is_closed() {
                return Ok(());
            }
            match self.poll(&client, &endpoint).await {
                Ok(threads) => {
                    if !self
                        .reconcile(threads, &mut tracked, &tx, warning_shown)
                        .await?
                    {
                        return Ok(());
                    }
                    if warning_shown {
                        tracing::info!("T3 Code observation reconnected");
                        warning_shown = false;
                    }
                }
                Err(error) => {
                    if !warning_shown {
                        tracing::warn!(error = ?error, "T3 Code observation unavailable; retrying");
                        warning_shown = true;
                    }
                }
            }
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    }
}

async fn send_event(tx: &TaggedSender, event: AgentEvent) -> Result<bool> {
    match tx.send((Transport::Observer, event)).await {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use pixtuoid_core::state::ActivityState;
    use pixtuoid_core::state::reducer::{EXIT_GRACE_WINDOW, STALE_TOOL_TIMEOUT};
    use pixtuoid_core::{Reducer, SceneState};
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use super::{
        AgentEvent, MAX_CREDENTIAL_BYTES, MAX_SHELL_RESPONSE_BYTES, MAX_TOKEN_RESPONSE_BYTES,
        MAX_WORKSPACE_ROOT_BYTES, ObservedStatus, ObservedThread, PairingInput, T3CodeCredential,
        T3CodeSource, TrackedThread, Transport, normalize_shell_snapshot, parse_pairing_input,
        parse_pairing_url, save_credential_at, shell_snapshot_url, transition_events,
    };

    fn credential(token: &str) -> T3CodeCredential {
        T3CodeCredential {
            base_url: "https://t3.example".to_owned(),
            token: token.to_owned(),
            expires_at_ms: super::unix_time_ms().expect("clock") + 60_000,
        }
    }

    fn drain(
        receiver: &mut mpsc::Receiver<(Transport, AgentEvent)>,
    ) -> Vec<(Transport, AgentEvent)> {
        let mut events = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }
        events
    }

    async fn serve_once(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local HTTP listener");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept local request");
            let request = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write local response");
            request
        });
        (base_url, task)
    }

    async fn serve_once_without_content_length(
        body: String,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local HTTP listener");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept local request");
            let request = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write local response");
            request
        });
        (base_url, task)
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut byte = [0; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream
                .read_exact(&mut byte)
                .await
                .expect("read HTTP request headers");
            bytes.push(byte[0]);
        }
        let headers = String::from_utf8(bytes.clone()).expect("HTTP headers are UTF-8");
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("valid content length"))
            })
            .unwrap_or(0);
        let mut body = vec![0; content_length];
        stream
            .read_exact(&mut body)
            .await
            .expect("read HTTP request body");
        bytes.extend(body);
        String::from_utf8(bytes).expect("HTTP request is UTF-8")
    }

    #[test]
    fn credential_store_round_trips_restricts_permissions_and_replaces_atomically() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("connection.json");
        let first = credential("first-secret");
        save_credential_at(&path, &first).expect("save first credential");
        let loaded = super::load_credential_at(&path, super::unix_time_ms().expect("clock"))
            .expect("load saved credential");
        assert_eq!(loaded.token, "first-secret");
        assert!(!format!("{loaded:?}").contains("first-secret"));

        let second = credential("second-secret");
        save_credential_at(&path, &second).expect("replace credential");
        let loaded = super::load_credential_at(&path, super::unix_time_ms().expect("clock"))
            .expect("load replacement");
        assert_eq!(loaded.token, "second-secret");

        let oversized = credential(&"x".repeat(MAX_CREDENTIAL_BYTES as usize));
        assert!(save_credential_at(&path, &oversized).is_err());
        let loaded = super::load_credential_at(&path, super::unix_time_ms().expect("clock"))
            .expect("oversized replacement must preserve the saved credential");
        assert_eq!(loaded.token, "second-secret");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("credential metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(directory.path())
                    .expect("directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn credential_store_rejects_wrong_scope_expired_and_oversized_data() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("connection.json");
        let now = super::unix_time_ms().expect("clock");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "base_url": "https://t3.example",
                "token": "secret",
                "expires_at_ms": now + 60_000,
                "scope": "orchestration:write"
            }))
            .expect("serialize wrong-scope credential"),
        )
        .expect("write wrong-scope credential");
        assert!(super::load_credential_at(&path, now).is_none());

        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "base_url": "https://t3.example",
                "token": "secret",
                "expires_at_ms": now,
                "scope": "orchestration:read"
            }))
            .expect("serialize expired credential"),
        )
        .expect("write expired credential");
        assert!(super::load_credential_at(&path, now).is_none());

        std::fs::write(&path, vec![b' '; MAX_CREDENTIAL_BYTES as usize + 1])
            .expect("write oversized credential");
        assert!(super::load_credential_at(&path, now).is_none());
    }

    #[test]
    fn snapshot_keeps_only_project_identity_and_live_wait_state() {
        let snapshot = json!({
            "projects": [{
                "id": "project-1",
                "workspaceRoot": "/work/demo",
                "title": "private project title"
            }],
            "threads": [
                {
                    "id": "active",
                    "projectId": "project-1",
                    "status": "running",
                    "activityRunStatus": "running",
                    "activeRunId": "run-1",
                    "activeProviderThreadId": "provider-1",
                    "title": "private thread title",
                    "hasPendingApprovals": false,
                    "hasPendingUserInput": false,
                    "archivedAt": null,
                    "deletedAt": null
                },
                {
                    "id": "approval",
                    "projectId": "project-1",
                    "status": "completed",
                    "activeRunId": null,
                    "activeProviderThreadId": "provider-2",
                    "hasPendingApprovals": true,
                    "hasPendingUserInput": false
                },
                {
                    "id": "input",
                    "projectId": "project-1",
                    "status": "completed",
                    "activeRunId": null,
                    "activeProviderThreadId": "provider-3",
                    "hasPendingApprovals": false,
                    "hasPendingUserInput": true
                },
                {
                    "id": "settled",
                    "projectId": "project-1",
                    "status": "completed",
                    "activeRunId": null,
                    "activeProviderThreadId": null
                }
            ]
        });

        let threads = normalize_shell_snapshot(snapshot).expect("valid snapshot");
        assert_eq!(
            threads
                .iter()
                .map(|thread| (thread.id.as_str(), thread.status))
                .collect::<Vec<_>>(),
            [
                ("active", ObservedStatus::Active),
                ("approval", ObservedStatus::Permission),
                ("input", ObservedStatus::Input)
            ]
        );
        assert_eq!(threads[0].project_dir.as_ref(), "/work/demo");
        assert_eq!(
            threads[0].project_dir.as_ptr(),
            threads[1].project_dir.as_ptr()
        );
        let serialized = serde_json::to_string(
            &threads
                .iter()
                .map(|thread| (&thread.id, thread.project_dir.as_ref()))
                .collect::<Vec<_>>(),
        )
        .expect("normalized values serialize");
        assert!(!serialized.contains("private project title"));
        assert!(!serialized.contains("private thread title"));
        assert!(!serialized.contains("run-1"));
    }

    #[test]
    fn snapshot_accepts_workspace_roots_at_the_size_limit() {
        let workspace_root = "x".repeat(MAX_WORKSPACE_ROOT_BYTES);
        let snapshot = json!({
            "projects": [{
                "id": "project-1",
                "workspaceRoot": workspace_root.clone()
            }],
            "threads": [
                {"id": "thread-1", "projectId": "project-1", "status": "running"}
            ]
        });
        let threads = normalize_shell_snapshot(snapshot).expect("workspace root at limit");
        assert_eq!(threads[0].project_dir.as_ref(), workspace_root.as_str());
    }

    #[test]
    fn snapshot_rejects_oversized_workspace_roots_before_expanding_threads() {
        let snapshot = json!({
            "projects": [{
                "id": "project-1",
                "workspaceRoot": "x".repeat(MAX_WORKSPACE_ROOT_BYTES + 1)
            }],
            "threads": [
                {"id": "thread-1", "projectId": "project-1", "status": "running"},
                {"id": "thread-2", "projectId": "project-1", "status": "running"}
            ]
        });
        assert!(
            serde_json::to_vec(&snapshot)
                .expect("serialize snapshot")
                .len()
                < MAX_SHELL_RESPONSE_BYTES
        );
        assert!(normalize_shell_snapshot(snapshot).is_err());
    }

    #[test]
    fn snapshot_bounds_workspace_root_bytes_across_live_threads() {
        let workspace_root = "x".repeat(MAX_WORKSPACE_ROOT_BYTES);
        let threads_at_limit = MAX_SHELL_RESPONSE_BYTES / workspace_root.len();
        let snapshot_with_threads = |thread_count| {
            json!({
                "projects": [{
                    "id": "project-1",
                    "workspaceRoot": workspace_root.clone()
                }],
                "threads": (0..thread_count)
                    .map(|index| json!({
                        "id": format!("thread-{index}"),
                        "projectId": "project-1",
                        "status": "running"
                    }))
                    .collect::<Vec<_>>()
            })
        };

        let at_limit = snapshot_with_threads(threads_at_limit);
        assert!(
            serde_json::to_vec(&at_limit)
                .expect("serialize snapshot")
                .len()
                < MAX_SHELL_RESPONSE_BYTES
        );
        assert_eq!(
            normalize_shell_snapshot(at_limit)
                .expect("workspace-root expansion at the limit")
                .len(),
            threads_at_limit
        );

        let over_limit = snapshot_with_threads(threads_at_limit + 1);
        assert!(
            serde_json::to_vec(&over_limit)
                .expect("serialize snapshot")
                .len()
                < MAX_SHELL_RESPONSE_BYTES
        );
        assert!(normalize_shell_snapshot(over_limit).is_err());
    }

    #[test]
    fn snapshot_url_requires_tls_except_on_loopback() {
        assert_eq!(
            shell_snapshot_url("http://127.0.0.1:3773").expect("loopback"),
            "http://127.0.0.1:3773/api/orchestration/shell"
        );
        assert_eq!(
            shell_snapshot_url("https://t3.example/t3").expect("https"),
            "https://t3.example/t3/api/orchestration/shell"
        );
        assert!(shell_snapshot_url("http://t3.example").is_err());
        assert!(shell_snapshot_url("https://user:pass@t3.example").is_err());
        assert!(shell_snapshot_url("https://t3.example/?token=secret").is_err());
    }

    #[test]
    fn pairing_url_extracts_only_the_fragment_token() {
        assert_eq!(
            parse_pairing_url("http://127.0.0.1:3773/pair#token=one-time").expect("pair URL"),
            ("http://127.0.0.1:3773".to_owned(), "one-time".to_owned())
        );
        assert!(parse_pairing_url("https://t3.example/?token=secret").is_err());
        assert!(parse_pairing_url("http://t3.example/pair#token=secret").is_err());
        assert!(parse_pairing_url("https://t3.example/other#token=secret").is_err());
    }

    #[test]
    fn pairing_url_accepts_ipv6_loopback() {
        assert_eq!(
            parse_pairing_url("http://[::1]:3773/pair#token=one-time").expect("IPv6 pair URL"),
            ("http://[::1]:3773".to_owned(), "one-time".to_owned())
        );
    }

    #[test]
    fn pairing_input_accepts_a_code_or_url() {
        assert!(matches!(
            parse_pairing_input(" 0123456789AB \n"),
            Ok(PairingInput::Code(code)) if code == "0123456789AB"
        ));
        assert!(matches!(
            parse_pairing_input(" http://127.0.0.1:3773/pair#token=one-time \n"),
            Ok(PairingInput::Url(url)) if url == "http://127.0.0.1:3773/pair#token=one-time"
        ));
        assert!(parse_pairing_input(" \n").is_err());
    }

    #[tokio::test]
    async fn pairing_exchange_requests_only_the_read_scope() {
        let (base_url, server) = serve_once(
            r#"{"access_token":"read-token","token_type":"Bearer","scope":"orchestration:read","expires_in":60}"#,
        )
        .await;
        let pairing_url = format!("{base_url}/pair#token=one-time-secret");
        let credential = super::exchange_pairing_url(&pairing_url)
            .await
            .expect("exchange pairing token");
        let request = server.await.expect("local HTTP server");

        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        for field in [
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            "subject_token=one-time-secret",
            "subject_token_type=urn%3At3%3Aparams%3Aoauth%3Atoken-type%3Aenvironment-bootstrap",
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            "scope=orchestration%3Aread",
        ] {
            assert!(
                request.contains(field),
                "request missing {field:?} in {request:?}"
            );
        }
        assert_eq!(credential.token, "read-token");
        assert!(!format!("{credential:?}").contains("read-token"));
    }

    #[tokio::test]
    async fn pairing_code_exchange_uses_the_supplied_server_url() {
        let (base_url, server) = serve_once(
            r#"{"access_token":"read-token","token_type":"Bearer","scope":"orchestration:read","expires_in":60}"#,
        )
        .await;
        let credential = super::exchange_pairing_code(&base_url, "0123456789AB")
            .await
            .expect("exchange pairing code");
        let request = server.await.expect("local HTTP server");

        assert!(request.starts_with("POST /oauth/token HTTP/1.1"));
        assert!(request.contains("subject_token=0123456789AB"));
        assert_eq!(credential.base_url, base_url);
        assert_eq!(credential.token, "read-token");
    }

    #[tokio::test]
    async fn shell_poll_sends_the_bearer_and_protocol_version() {
        let (base_url, server) = serve_once(r#"{"projects":[],"threads":[]}"#).await;
        let source = T3CodeSource::new(T3CodeCredential {
            base_url: base_url.clone(),
            token: "observer-secret".to_owned(),
            expires_at_ms: u64::MAX,
        });
        let endpoint = shell_snapshot_url(&base_url).expect("shell endpoint");
        let threads = source
            .poll(&super::http_client().expect("HTTP client"), &endpoint)
            .await
            .expect("shell poll");
        let request = server.await.expect("local HTTP server");

        assert!(threads.is_empty());
        assert!(request.starts_with("GET /api/orchestration/shell HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer observer-secret")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-t3-orchestration-protocol: 2")
        );
    }

    #[tokio::test]
    async fn shell_and_token_responses_without_content_length_are_bounded() {
        let snapshot_body =
            r#"{"projects":[],"threads":[]}"#.to_owned() + &" ".repeat(MAX_SHELL_RESPONSE_BYTES);
        let (base_url, server) = serve_once_without_content_length(snapshot_body).await;
        let source = T3CodeSource::new(T3CodeCredential {
            base_url: base_url.clone(),
            token: "observer-secret".to_owned(),
            expires_at_ms: u64::MAX,
        });
        let endpoint = shell_snapshot_url(&base_url).expect("shell endpoint");
        let error = match source
            .poll(&super::http_client().expect("HTTP client"), &endpoint)
            .await
        {
            Ok(_) => panic!("oversized snapshot must be rejected"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("exceeds"));
        server.await.expect("local HTTP server");

        let token_body = r#"{"access_token":"read-token","token_type":"Bearer","scope":"orchestration:read","expires_in":60}"#
            .to_owned()
            + &" ".repeat(MAX_TOKEN_RESPONSE_BYTES);
        let (base_url, server) = serve_once_without_content_length(token_body).await;
        let pairing_url = format!("{base_url}/pair#token=one-time-secret");
        let error = super::exchange_pairing_url(&pairing_url)
            .await
            .expect_err("oversized token response must be rejected");
        assert!(format!("{error:#}").contains("exceeds"));
        server.await.expect("local HTTP server");
    }

    #[test]
    fn status_transitions_emit_generic_activity_and_clear_waits() {
        let agent_id = pixtuoid_core::AgentId::from_parts("t3-code", "thread");
        let active = transition_events(agent_id, None, ObservedStatus::Active);
        assert!(matches!(
            active.as_slice(),
            [AgentEvent::ToolUseStart {
                detail: Some(pixtuoid_core::source::ToolDetail::Generic { display }),
                ..
            }] if display == "Working in T3 Code"
        ));

        let waiting = transition_events(
            agent_id,
            Some(ObservedStatus::Active),
            ObservedStatus::Permission,
        );
        assert!(matches!(
            waiting.as_slice(),
            [
                AgentEvent::ToolUseEnd { .. },
                AgentEvent::UserActionRequest { reason: Some(reason), .. }
            ] if reason == "T3 Code is waiting for permission"
        ));

        let resumed = transition_events(
            agent_id,
            Some(ObservedStatus::Permission),
            ObservedStatus::Active,
        );
        assert!(matches!(
            resumed.as_slice(),
            [
                AgentEvent::UserActionResolved {
                    by: pixtuoid_core::source::Resolution::Call(_),
                    ..
                },
                AgentEvent::ToolUseStart { .. }
            ]
        ));
    }

    #[tokio::test]
    async fn reconciliation_observes_wait_resume_and_thread_removal() {
        let source = T3CodeSource::new(credential("unused-in-reconcile-test"));
        let (tx, mut rx) = mpsc::channel(16);
        let mut tracked = std::collections::HashMap::<String, TrackedThread>::new();
        let waiting = ObservedThread {
            id: "thread-1".to_owned(),
            project_dir: "/work/demo".into(),
            status: ObservedStatus::Permission,
        };

        assert!(
            source
                .reconcile(vec![waiting], &mut tracked, &tx, false)
                .await
                .expect("initial reconcile")
        );
        let initial = drain(&mut rx);
        assert!(matches!(
            initial.as_slice(),
            [
                (Transport::Observer, AgentEvent::SessionStart { .. }),
                (Transport::Observer, AgentEvent::UserActionRequest { .. }),
                (Transport::Observer, AgentEvent::ProofOfLife { .. })
            ]
        ));

        let active = ObservedThread {
            id: "thread-1".to_owned(),
            project_dir: "/work/demo".into(),
            status: ObservedStatus::Active,
        };
        assert!(
            source
                .reconcile(vec![active], &mut tracked, &tx, false)
                .await
                .expect("resume reconcile")
        );
        let resumed = drain(&mut rx);
        assert!(matches!(
            resumed.as_slice(),
            [
                (Transport::Observer, AgentEvent::UserActionResolved { .. }),
                (Transport::Observer, AgentEvent::ToolUseStart { .. }),
                (Transport::Observer, AgentEvent::ProofOfLife { .. })
            ]
        ));

        assert!(
            source
                .reconcile(Vec::new(), &mut tracked, &tx, false)
                .await
                .expect("removal reconcile")
        );
        let removed = drain(&mut rx);
        assert!(matches!(
            removed.as_slice(),
            [
                (Transport::Observer, AgentEvent::ToolUseEnd { .. }),
                (Transport::Observer, AgentEvent::TurnEnd { .. }),
                (Transport::Observer, AgentEvent::SessionEnd { .. })
            ]
        ));
    }

    #[tokio::test]
    async fn recovery_reregisters_a_stale_removed_agent_from_the_same_snapshot() {
        let source = T3CodeSource::new(credential("unused-in-reconcile-test"));
        let (tx, mut rx) = mpsc::channel(16);
        let mut tracked = std::collections::HashMap::<String, TrackedThread>::new();
        let mut reducer = Reducer::new();
        let mut scene = SceneState::uniform(1);
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let snapshot = || {
            vec![ObservedThread {
                id: "thread-1".to_owned(),
                project_dir: "/work/demo".into(),
                status: ObservedStatus::Active,
            }]
        };
        let id = pixtuoid_core::AgentId::from_parts("t3-code", "thread-1");

        assert!(
            source
                .reconcile(snapshot(), &mut tracked, &tx, false)
                .await
                .expect("initial reconcile")
        );
        for (transport, event) in drain(&mut rx) {
            reducer.apply(&mut scene, event, t0, transport);
        }
        assert!(
            scene.agents.contains_key(&id),
            "initial observation registers"
        );

        let stale_at = t0 + STALE_TOOL_TIMEOUT + Duration::from_secs(1);
        reducer.tick(&mut scene, stale_at);
        reducer.tick(
            &mut scene,
            stale_at + EXIT_GRACE_WINDOW + Duration::from_secs(1),
        );
        assert!(
            !scene.agents.contains_key(&id),
            "the reducer removes the silent tracked agent during the outage"
        );

        let recovered_at = stale_at + EXIT_GRACE_WINDOW + Duration::from_secs(2);
        assert!(
            source
                .reconcile(snapshot(), &mut tracked, &tx, true)
                .await
                .expect("reconcile after the observation outage")
        );
        let events = drain(&mut rx);
        assert!(matches!(
            events.as_slice(),
            [
                (Transport::Observer, AgentEvent::SessionStart { .. }),
                (Transport::Observer, AgentEvent::ToolUseStart { .. }),
                (Transport::Observer, AgentEvent::ProofOfLife { .. })
            ]
        ));
        for (transport, event) in events {
            reducer.apply(&mut scene, event, recovered_at, transport);
        }
        assert!(matches!(
            scene.agents.get(&id).map(|slot| &slot.state),
            Some(ActivityState::Running { item: Some(_), .. })
        ));
    }
}
