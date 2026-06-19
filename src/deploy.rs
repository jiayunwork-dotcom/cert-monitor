use crate::config::{Config, DomainConfig};
use crate::scanner::Scanner;
use crate::types::CertificateInfo;
use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::Duration;

pub struct Deployer {
    config: Arc<Config>,
    scanner: Scanner,
}

impl Deployer {
    pub fn new(config: Arc<Config>, scanner: Scanner) -> Self {
        Self { config, scanner }
    }

    pub async fn deploy_domain(
        &self,
        domain_config: &DomainConfig,
        expected_fingerprint: Option<&str>,
    ) -> Result<DeployResultInner> {
        let domain = &domain_config.name;
        tracing::info!("开始部署: {}", domain);

        let mut results = Vec::new();

        if let Some(hooks) = &domain_config.deployment_hooks {
            for (i, hook) in hooks.iter().enumerate() {
                tracing::debug!("执行部署钩子 [{}]: {}", i, hook);
                match self.execute_hook(hook).await {
                    Ok(output) => {
                        tracing::info!("钩子执行成功 [{}]: {}", i, hook);
                        results.push(HookResult {
                            command: hook.clone(),
                            success: true,
                            output,
                        });
                    }
                    Err(e) => {
                        tracing::error!("钩子执行失败 [{}] {}: {}", i, hook, e);
                        results.push(HookResult {
                            command: hook.clone(),
                            success: false,
                            output: e.to_string(),
                        });
                    }
                }
            }
        }

        let verification_result = if domain_config.verification_hook.unwrap_or(false) {
            match expected_fingerprint {
                Some(fp) => {
                    let result = self
                        .verify_deployment(domain_config, fp)
                        .await;
                    Some(result)
                }
                None => {
                    tracing::warn!("跳过验证钩子: 没有预期指纹");
                    None
                }
            }
        } else {
            None
        };

        Ok(DeployResultInner {
            domain: domain.clone(),
            hooks: results,
            verification: verification_result,
        })
    }

    async fn execute_hook(&self, command: &str) -> Result<String> {
        let timeout = Duration::from_secs(self.config.hook_timeout_secs());

        let output = tokio::time::timeout(timeout, async {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            let output = tokio::process::Command::new(shell)
                .arg("-c")
                .arg(command)
                .output()
                .await
                .with_context(|| format!("Failed to execute command: {}", command))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Err(anyhow!(
                    "Command failed with exit code {:?}\nstdout: {}\nstderr: {}",
                    output.status.code(),
                    stdout,
                    stderr
                ));
            }

            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
        .await
        .with_context(|| format!("Command timed out after {}s: {}", self.config.hook_timeout_secs(), command))??;

        Ok(output)
    }

    async fn verify_deployment(
        &self,
        domain_config: &DomainConfig,
        expected_fingerprint: &str,
    ) -> Result<bool> {
        let domain = &domain_config.name;
        tracing::info!("验证部署: {}", domain);

        tokio::time::sleep(Duration::from_secs(5)).await;

        let scan_result = self.scanner.scan_domain(domain).await;

        match scan_result.cert {
            Some(cert) => {
                let matches = cert.fingerprint_sha256 == expected_fingerprint;
                if matches {
                    tracing::info!(
                        "部署验证成功: {} 指纹匹配 ({})",
                        domain,
                        expected_fingerprint
                    );
                    Ok(true)
                } else {
                    tracing::warn!(
                        "部署验证失败: {} 指纹不匹配 (期望: {}, 实际: {})",
                        domain,
                        expected_fingerprint,
                        cert.fingerprint_sha256
                    );
                    Ok(false)
                }
            }
            None => {
                tracing::error!(
                    "部署验证失败: 无法获取 {} 的证书: {}",
                    domain,
                    scan_result.error.unwrap_or_else(|| "Unknown error".to_string())
                );
                Ok(false)
            }
        }
    }

    pub async fn send_verification_failure_alert(
        &self,
        _domain: &str,
        _cert: &CertificateInfo,
    ) -> Result<Vec<String>> {
        let _notifier = crate::notify::Notifier::new(
            self.config.clone(),
            crate::state::StateManager::new(self.config.get_state_file_path())?,
        );

        // This would send notification about verification failure
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone)]
pub struct HookResult {
    pub command: String,
    pub success: bool,
    pub output: String,
}

pub type DeployResult = DeployResultInner;

#[derive(Debug)]
pub struct DeployResultInner {
    pub domain: String,
    pub hooks: Vec<HookResult>,
    pub verification: Option<Result<bool>>,
}

impl DeployResultInner {
    pub fn all_hooks_successful(&self) -> bool {
        self.hooks.iter().all(|h| h.success)
    }

    pub fn verification_passed(&self) -> bool {
        matches!(self.verification, Some(Ok(true)))
    }

    pub fn has_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for hook in &self.hooks {
            if !hook.success {
                errors.push(format!("Hook '{}' failed: {}", hook.command, hook.output));
            }
        }
        if let Some(verification) = &self.verification {
            match verification {
                Ok(false) => errors.push("Verification failed: certificate fingerprint mismatch".to_string()),
                Err(e) => errors.push(format!("Verification error: {}", e)),
                _ => {}
            }
        }
        errors
    }
}
