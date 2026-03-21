use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Result, StargateError};

const ROUTE_USERNAME_MAX_LEN: usize = 128;
const TARGET_USERNAME_MAX_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    NativeSsh,
    BrowserTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalSessionMode {
    Browser,
    Native,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RouteMetadata {
    pub host_id: Option<String>,
    pub run_id: Option<String>,
    pub vm_id: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueTerminalSessionRequest {
    pub route_username: String,
    pub target_username: String,
    pub target_ip: String,
    pub target_port: u16,
    pub target_host_key_openssh: Option<String>,
    #[serde(with = "time::serde::timestamp")]
    pub route_expires_at: OffsetDateTime,
    pub mode: TerminalSessionMode,
    #[serde(default)]
    pub metadata: RouteMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserTerminalSession {
    pub websocket_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NativeTerminalSession {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    pub private_key_openssh: String,
    pub public_host_key_openssh: String,
    pub public_host_key_fingerprint_sha256: String,
    pub known_hosts_line: String,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueTerminalSessionResponse {
    pub route_username: String,
    #[serde(with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserTerminalSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeTerminalSession>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisteredRoute {
    pub route_username: String,
    pub target_username: String,
    pub target_ip: String,
    pub target_port: u16,
    pub native_client_public_key_openssh: Option<String>,
    pub target_host_key_openssh: Option<String>,
    #[serde(with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    pub metadata: RouteMetadata,
}

#[derive(Clone, Debug, Serialize)]
pub struct RouteRecord {
    pub route_username: String,
    pub target_username: String,
    pub target_ip: String,
    pub target_port: u16,
    pub native_client_public_key_openssh: Option<String>,
    pub target_host_key_openssh: String,
    #[serde(with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    pub metadata: RouteMetadata,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub updated_at: OffsetDateTime,
}

impl IssueTerminalSessionRequest {
    pub fn validate(self) -> Result<(RegisteredRoute, TerminalSessionMode)> {
        validate_route_username(&self.route_username)?;
        validate_target_username(&self.target_username)?;
        if self.target_port == 0 {
            return Err(StargateError::Validation(
                "target_port must be between 1 and 65535".to_owned(),
            ));
        }
        let _ = self
            .target_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| StargateError::Validation("target_ip must be a literal IP".to_owned()))?;
        if self.route_expires_at <= OffsetDateTime::now_utc() {
            return Err(StargateError::Validation(
                "route_expires_at must be in the future".to_owned(),
            ));
        }
        if let Some(target_host_key_openssh) = &self.target_host_key_openssh {
            let _ = russh::keys::ssh_key::PublicKey::from_openssh(target_host_key_openssh)
                .map_err(|_| {
                    StargateError::Validation("target_host_key_openssh is invalid".to_owned())
                })?;
        }

        let mode = self.mode;
        Ok((
            RegisteredRoute {
                route_username: self.route_username,
                target_username: self.target_username,
                target_ip: self.target_ip,
                target_port: self.target_port,
                native_client_public_key_openssh: None,
                target_host_key_openssh: self.target_host_key_openssh,
                expires_at: self.route_expires_at,
                metadata: self.metadata,
            },
            mode,
        ))
    }
}

impl RouteRecord {
    pub fn native_client_public_key(&self) -> Result<Option<russh::keys::ssh_key::PublicKey>> {
        match &self.native_client_public_key_openssh {
            Some(value) => Ok(Some(russh::keys::ssh_key::PublicKey::from_openssh(value)?)),
            None => Ok(None),
        }
    }

    pub fn target_host_key(&self) -> Result<russh::keys::ssh_key::PublicKey> {
        Ok(russh::keys::ssh_key::PublicKey::from_openssh(
            &self.target_host_key_openssh,
        )?)
    }

    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}

pub fn validate_route_username(username: &str) -> Result<()> {
    validate_username(username, ROUTE_USERNAME_MAX_LEN, "route_username")
}

pub fn validate_target_username(username: &str) -> Result<()> {
    validate_username(username, TARGET_USERNAME_MAX_LEN, "target_username")
}

fn validate_username(username: &str, max_len: usize, field: &str) -> Result<()> {
    if username.is_empty() || username.len() > max_len {
        return Err(StargateError::Validation(format!(
            "{field} must be 1..={max_len} characters"
        )));
    }
    let valid = username
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(StargateError::Validation(format!(
            "{field} may only contain ASCII letters, digits, '.', '_' and '-'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use russh::keys::ssh_key::{Algorithm, rand_core::OsRng};
    use time::OffsetDateTime;

    use super::{
        IssueTerminalSessionRequest, TerminalSessionMode, validate_route_username,
        validate_target_username,
    };

    #[test]
    fn username_validation_accepts_expected_values() {
        assert!(validate_route_username("run-01-web").is_ok());
        assert!(validate_target_username("ubuntu").is_ok());
    }

    #[test]
    fn username_validation_rejects_disallowed_values() {
        assert!(validate_route_username("worker@bad").is_err());
        assert!(validate_target_username("").is_err());
    }

    #[test]
    fn terminal_session_request_accepts_valid_payload() {
        let target_host_key =
            russh::keys::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("host key");

        let request = IssueTerminalSessionRequest {
            route_username: "run-01-worker".to_owned(),
            target_username: "ubuntu".to_owned(),
            target_ip: "127.0.0.1".to_owned(),
            target_port: 22,
            target_host_key_openssh: Some(target_host_key.public_key().to_openssh().expect("host")),
            route_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            mode: TerminalSessionMode::Browser,
            metadata: super::RouteMetadata::default(),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn terminal_session_request_rejects_invalid_target_ip() {
        let target_host_key =
            russh::keys::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("host key");

        let request = IssueTerminalSessionRequest {
            route_username: "run-01-worker".to_owned(),
            target_username: "ubuntu".to_owned(),
            target_ip: "worker.example.test".to_owned(),
            target_port: 22,
            target_host_key_openssh: Some(target_host_key.public_key().to_openssh().expect("host")),
            route_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            mode: TerminalSessionMode::Native,
            metadata: super::RouteMetadata::default(),
        };

        assert!(request.validate().is_err());
    }
}
