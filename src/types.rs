use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

impl AlertLevel {
    pub fn from_days(days: i64) -> Option<Self> {
        if days < 0 {
            Some(AlertLevel::Emergency)
        } else if days <= 7 {
            Some(AlertLevel::Critical)
        } else if days <= 30 {
            Some(AlertLevel::Warning)
        } else if days <= 60 {
            Some(AlertLevel::Info)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "CRITICAL",
            AlertLevel::Emergency => "EMERGENCY",
        }
    }

    pub fn threshold_days(&self) -> i64 {
        match self {
            AlertLevel::Info => 60,
            AlertLevel::Warning => 30,
            AlertLevel::Critical => 7,
            AlertLevel::Emergency => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub domain: String,
    pub subject: String,
    pub san_list: Vec<String>,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
    pub chain_complete: bool,
    pub ocsp_status: OcspStatus,
    pub source: String,
}

impl CertificateInfo {
    pub fn days_remaining(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub domain: String,
    pub cert: Option<CertificateInfo>,
    pub error: Option<String>,
    pub scanned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub level: AlertLevel,
    pub last_sent: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalHistory {
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub message: String,
    pub new_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainState {
    pub last_scan: Option<DateTime<Utc>>,
    pub last_renew: Option<DateTime<Utc>>,
    pub last_notifications: HashMap<AlertLevel, DateTime<Utc>>,
    pub renewal_history: Vec<RenewalHistory>,
    pub current_fingerprint: Option<String>,
}

impl Default for DomainState {
    fn default() -> Self {
        Self {
            last_scan: None,
            last_renew: None,
            last_notifications: HashMap::new(),
            renewal_history: Vec::new(),
            current_fingerprint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub domains: HashMap<String, DomainState>,
    pub updated_at: DateTime<Utc>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            domains: HashMap::new(),
            updated_at: Utc::now(),
        }
    }
}
