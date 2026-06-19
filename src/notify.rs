use crate::config::{Config, DingTalkConfig, SlackConfig, SmtpConfig};
use crate::state::StateManager;
use crate::types::{AlertLevel, CertificateInfo};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use lettre::message::Mailbox;
use lettre::{Message, SmtpTransport, Transport};

use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

pub struct Notifier {
    config: Arc<Config>,
    state_manager: StateManager,
    http_client: reqwest::Client,
}

impl Notifier {
    pub fn new(config: Arc<Config>, state_manager: StateManager) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            config,
            state_manager,
            http_client,
        }
    }

    pub async fn send_alert_if_needed(
        &mut self,
        cert: &CertificateInfo,
    ) -> Result<Vec<String>> {
        let days = cert.days_remaining();
        let Some(level) = AlertLevel::from_days(days) else {
            return Ok(Vec::new());
        };

        let debounce_hours = self.config.notification_debounce_hours();
        if !self
            .state_manager
            .should_send_notification(&cert.domain, &level, debounce_hours)
        {
            tracing::debug!(
                "跳过通知 {} (级别: {}, 防抖时间内)",
                cert.domain,
                level.as_str()
            );
            return Ok(Vec::new());
        }

        let channels = self.send_all_channels(cert, &level).await?;

        if !channels.is_empty() {
            self.state_manager
                .update_notification_time(&cert.domain, level.clone());
            self.state_manager.save()?;
        }

        Ok(channels)
    }

    async fn send_all_channels(
        &self,
        cert: &CertificateInfo,
        level: &AlertLevel,
    ) -> Result<Vec<String>> {
        let mut sent_channels = Vec::new();

        if let Some(smtp) = &self.config.global.smtp {
            match self.send_email(smtp, cert, level).await {
                Ok(_) => {
                    sent_channels.push("email".to_string());
                    tracing::info!("邮件通知已发送: {}", cert.domain);
                }
                Err(e) => {
                    tracing::error!("邮件通知失败 {}: {}", cert.domain, e);
                }
            }
        }

        if let Some(slack) = &self.config.global.slack {
            match self.send_slack(slack, cert, level).await {
                Ok(_) => {
                    sent_channels.push("slack".to_string());
                    tracing::info!("Slack通知已发送: {}", cert.domain);
                }
                Err(e) => {
                    tracing::error!("Slack通知失败 {}: {}", cert.domain, e);
                }
            }
        }

        if let Some(dingtalk) = &self.config.global.dingtalk {
            match self.send_dingtalk(dingtalk, cert, level).await {
                Ok(_) => {
                    sent_channels.push("dingtalk".to_string());
                    tracing::info!("钉钉通知已发送: {}", cert.domain);
                }
                Err(e) => {
                    tracing::error!("钉钉通知失败 {}: {}", cert.domain, e);
                }
            }
        }

        Ok(sent_channels)
    }

    async fn send_email(
        &self,
        smtp: &SmtpConfig,
        cert: &CertificateInfo,
        level: &AlertLevel,
    ) -> Result<()> {
        let subject = format!(
            "[{}] SSL证书预警: {} 剩余{}天",
            level.as_str(),
            cert.domain,
            cert.days_remaining()
        );

        let body = format!(
            "SSL证书到期预警通知\n\n\
            域名: {}\n\
            剩余天数: {}\n\
            预警级别: {}\n\
            证书主题: {}\n\
            颁发者: {}\n\
            有效期至: {}\n\
            SAN列表: {}\n\
            指纹(SHA256): {}\n\n\
            请及时处理!",
            cert.domain,
            cert.days_remaining(),
            level.as_str(),
            cert.subject,
            cert.issuer,
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
            cert.san_list.join(", "),
            cert.fingerprint_sha256
        );

        let from: Mailbox = smtp.from.parse().context("Invalid from address")?;
        let to: Vec<Mailbox> = smtp
            .to
            .iter()
            .map(|a| a.parse())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Invalid to address")?;

        let mut email_builder = Message::builder()
            .from(from.clone())
            .subject(subject);

        for addr in &to {
            email_builder = email_builder.to(addr.clone());
        }

        let email = email_builder
            .body(body)
            .context("Failed to build email body")?;

        let use_tls = smtp.use_tls.unwrap_or(true);
        let mailer = if use_tls {
            let tls_params = lettre::transport::smtp::client::TlsParameters::builder(
                    smtp.host.clone(),
                )
                .build()
                .context("Failed to build TLS parameters")?;
            SmtpTransport::relay(&smtp.host)
                .context("Failed to build SMTP transport")?
                .port(smtp.port)
                .credentials(lettre::transport::smtp::authentication::Credentials::new(
                    smtp.username.clone(),
                    smtp.password.clone(),
                ))
                .tls(lettre::transport::smtp::client::Tls::Required(tls_params))
                .build()
        } else {
            SmtpTransport::relay(&smtp.host)
                .context("Failed to build SMTP transport")?
                .port(smtp.port)
                .credentials(lettre::transport::smtp::authentication::Credentials::new(
                    smtp.username.clone(),
                    smtp.password.clone(),
                ))
                .tls(lettre::transport::smtp::client::Tls::None)
                .build()
        };

        mailer
            .send(&email)
            .map_err(|e| anyhow!("Failed to send email: {}", e))?;

        Ok(())
    }

    async fn send_slack(
        &self,
        slack: &SlackConfig,
        cert: &CertificateInfo,
        level: &AlertLevel,
    ) -> Result<()> {
        let color = match level {
            AlertLevel::Info => "#36a64f",
            AlertLevel::Warning => "#ffa500",
            AlertLevel::Critical => "#ff0000",
            AlertLevel::Emergency => "#dc143c",
        };

        let days = cert.days_remaining();
        let text = if days < 0 {
            format!("证书已过期 {} 天", days.abs())
        } else {
            format!("剩余 {} 天过期", days)
        };

        let mut payload = serde_json::json!({
            "text": format!("[{}] SSL证书预警: {}", level.as_str(), cert.domain),
            "attachments": [
                {
                    "color": color,
                    "title": cert.domain,
                    "fields": [
                        {
                            "title": "预警级别",
                            "value": level.as_str(),
                            "short": true
                        },
                        {
                            "title": "到期时间",
                            "value": text,
                            "short": true
                        },
                        {
                            "title": "颁发者",
                            "value": cert.issuer,
                            "short": false
                        },
                        {
                            "title": "有效期至",
                            "value": cert.not_after.format("%Y-%m-%d %H:%M UTC").to_string(),
                            "short": false
                        },
                        {
                            "title": "SAN列表",
                            "value": cert.san_list.join(", "),
                            "short": false
                        },
                        {
                            "title": "证书指纹",
                            "value": cert.fingerprint_sha256.clone(),
                            "short": false
                        }
                    ]
                }
            ]
        });

        if let Some(channel) = &slack.channel {
            payload["channel"] = serde_json::Value::String(channel.clone());
        }

        let response = self
            .http_client
            .post(&slack.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Slack webhook")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Slack webhook failed ({}): {}", status, text));
        }

        Ok(())
    }

    async fn send_dingtalk(
        &self,
        dingtalk: &DingTalkConfig,
        cert: &CertificateInfo,
        level: &AlertLevel,
    ) -> Result<()> {
        let mut webhook_url = dingtalk.webhook_url.clone();

        if let Some(secret) = &dingtalk.secret {
            let timestamp = Utc::now().timestamp_millis();
            let string_to_sign = format!("{}\n{}", timestamp, secret);
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            let sign = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
            let sign_encoded = percent_encoding::percent_encode(
                sign.as_bytes(),
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string();
            webhook_url = format!(
                "{}&timestamp={}&sign={}",
                webhook_url, timestamp, sign_encoded
            );
        }

        let days = cert.days_remaining();
        let status_text = if days < 0 {
            format!("已过期 {} 天", days.abs())
        } else {
            format!("剩余 {} 天", days)
        };

        let title = format!("[{}] SSL证书预警: {}", level.as_str(), cert.domain);
        let text = format!(
            "### SSL证书到期预警\n\n\
            **域名**: {}\n\n\
            **预警级别**: {}\n\n\
            **到期状态**: {}\n\n\
            **证书主题**: {}\n\n\
            **颁发者**: {}\n\n\
            **有效期至**: {}\n\n\
            **SAN列表**: {}\n\n\
            **指纹(SHA256)**: {}\n\n\
            > 请及时处理!",
            cert.domain,
            level.as_str(),
            status_text,
            cert.subject,
            cert.issuer,
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC"),
            cert.san_list.join(", "),
            cert.fingerprint_sha256
        );

        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text
            },
            "at": {
                "isAtAll": true
            }
        });

        let response = self
            .http_client
            .post(&webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send DingTalk webhook")?;

        if !response.status().is_success() {
            let status = response.status();
            let resp_text = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "DingTalk webhook failed ({}): {}",
                status,
                resp_text
            ));
        }

        let resp_json: serde_json::Value = response.json().await.unwrap_or_default();
        if resp_json["errcode"].as_i64().unwrap_or(-1) != 0 {
            return Err(anyhow!(
                "DingTalk webhook returned error: {}",
                resp_json["errmsg"].as_str().unwrap_or("unknown")
            ));
        }

        Ok(())
    }
}
