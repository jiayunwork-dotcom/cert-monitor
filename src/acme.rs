use crate::config::{Config, DnsProviderConfig, DomainConfig, ValidationMethod};
use crate::types::{CertificateInfo, RenewalHistory};
use acme_lib::order::{CsrOrder, NewOrder};
use acme_lib::{Directory, DirectoryUrl};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::Utc;
use hmac::Mac;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct AcmeClient {
    config: Arc<Config>,
    http_client: reqwest::Client,
}

impl AcmeClient {
    pub fn new(config: Arc<Config>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            config,
            http_client,
        }
    }

    pub fn needs_renewal(&self, cert: &CertificateInfo) -> bool {
        let days = cert.days_remaining();
        days <= self.config.renew_threshold_days()
    }

    pub async fn renew_certificate(
        &self,
        domain_config: &DomainConfig,
    ) -> Result<RenewalHistory> {
        let domain = &domain_config.name;
        tracing::info!("开始续签证书: {}", domain);

        let result = self
            .renew_certificate_internal(domain_config)
            .await;

        match result {
            Ok(new_fingerprint) => {
                tracing::info!("证书续签成功: {}", domain);
                Ok(RenewalHistory {
                    timestamp: Utc::now(),
                    success: true,
                    message: "Certificate renewed successfully".to_string(),
                    new_fingerprint: Some(new_fingerprint),
                })
            }
            Err(e) => {
                tracing::error!("证书续签失败 {}: {}", domain, e);
                Ok(RenewalHistory {
                    timestamp: Utc::now(),
                    success: false,
                    message: e.to_string(),
                    new_fingerprint: None,
                })
            }
        }
    }

    async fn renew_certificate_internal(
        &self,
        domain_config: &DomainConfig,
    ) -> Result<String> {
        let domain = &domain_config.name;
        let email = &self.config.global.acme_account_email;
        let directory_url = self.config.acme_directory_url();

        let persist_path = self.get_acme_persist_path(domain)?;
        std::fs::create_dir_all(&persist_path)
            .with_context(|| format!("Failed to create ACME persist dir: {}", persist_path.display()))?;

        let persist = acme_lib::persist::FilePersist::new(&persist_path);
        let url = DirectoryUrl::Other(&directory_url);
        let dir = Directory::from_url(persist, url)
            .map_err(|e| anyhow!("Failed to create ACME directory: {:?}", e))?;

        let acc = dir
            .account(email)
            .map_err(|e| anyhow!("Failed to get/create ACME account: {:?}", e))?;

        let mut alt_names = vec![domain.clone()];
        if !domain.starts_with("*.") {
            alt_names.push(format!("*.{}", domain));
        }

        let alt_names_ref: Vec<&str> = alt_names.iter().map(|s| s.as_str()).collect();
        let order = acc
            .new_order(domain, &alt_names_ref)
            .map_err(|e| anyhow!("Failed to create order: {:?}", e))?;

        let csr_order = self.complete_challenges(order, domain_config).await?;

        let pkey = acme_lib::create_p384_key();
        let order = csr_order
            .finalize_pkey(pkey, 5000)
            .map_err(|e| anyhow!("Failed to finalize order: {:?}", e))?;

        let cert = order
            .download_and_save_cert()
            .map_err(|e| anyhow!("Failed to download certificate: {:?}", e))?;

        let new_fingerprint = self.save_certificates(&cert, domain_config)?;

        Ok(new_fingerprint)
    }

    fn get_acme_persist_path(&self, domain: &str) -> Result<PathBuf> {
        let base = dirs::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory"))?
            .join(".cert-monitor")
            .join("acme")
            .join(domain);
        Ok(base)
    }

    async fn complete_challenges(
        &self,
        order: NewOrder<acme_lib::persist::FilePersist>,
        domain_config: &DomainConfig,
    ) -> Result<CsrOrder<acme_lib::persist::FilePersist>> {
        let validation_method = domain_config
            .validation_method
            .as_ref()
            .ok_or_else(|| anyhow!("No validation method configured for {}", domain_config.name))?;

        let order = match validation_method {
            ValidationMethod::Http01 => {
                self.complete_http01_challenges(order, domain_config).await?
            }
            ValidationMethod::Dns01 => {
                self.complete_dns01_challenges(order, domain_config).await?
            }
        };

        Ok(order)
    }

    async fn complete_http01_challenges(
        &self,
        mut order: NewOrder<acme_lib::persist::FilePersist>,
        domain_config: &DomainConfig,
    ) -> Result<CsrOrder<acme_lib::persist::FilePersist>> {
        let challenge_dir = domain_config
            .http_challenge_dir
            .as_ref()
            .ok_or_else(|| anyhow!("No HTTP challenge directory configured"))?;

        std::fs::create_dir_all(challenge_dir)
            .with_context(|| format!("Failed to create challenge dir: {}", challenge_dir))?;

        let auths = order.authorizations()
            .map_err(|e| anyhow!("Failed to get authorizations: {:?}", e))?;
        for auth in auths {
            let challenge = auth.http_challenge();

            let token = challenge.http_token();
            let proof = challenge.http_proof();

            let challenge_file = Path::new(challenge_dir).join(token);
            std::fs::write(&challenge_file, proof)
                .with_context(|| format!("Failed to write challenge file: {:?}", challenge_file))?;

            challenge
                .validate(5000)
                .map_err(|e| anyhow!("Failed to validate challenge: {:?}", e))?;
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        order.refresh()
            .map_err(|e| anyhow!("Failed to refresh order: {:?}", e))?;

        let order = order
            .confirm_validations()
            .ok_or_else(|| anyhow!("Failed to confirm validations"))?;

        Ok(order)
    }

    async fn complete_dns01_challenges(
        &self,
        mut order: NewOrder<acme_lib::persist::FilePersist>,
        domain_config: &DomainConfig,
    ) -> Result<CsrOrder<acme_lib::persist::FilePersist>> {
        let dns_provider = domain_config
            .dns_provider
            .as_ref()
            .ok_or_else(|| anyhow!("No DNS provider configured"))?;

        let mut record_ids = Vec::new();

        let auths = order.authorizations()
            .map_err(|e| anyhow!("Failed to get authorizations: {:?}", e))?;
        for auth in auths {
            let challenge = auth.dns_challenge();
            let dns_name = format!("_acme-challenge.{}", auth.domain_name());
            let dns_value = challenge.dns_proof();

            let record_id = match dns_provider {
                DnsProviderConfig::Cloudflare { api_token, zone_id } => {
                    self.cloudflare_add_txt(api_token, zone_id.as_deref(), &dns_name, &dns_value)
                        .await?
                }
                DnsProviderConfig::Aliyun {
                    access_key_id,
                    access_key_secret,
                    region,
                } => {
                    self.aliyun_add_txt(
                        access_key_id,
                        access_key_secret,
                        region.as_deref(),
                        &dns_name,
                        &dns_value,
                    )
                    .await?
                }
            };
            record_ids.push((dns_provider.clone(), dns_name, record_id));

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            challenge
                .validate(5000)
                .map_err(|e| anyhow!("Failed to validate challenge: {:?}", e))?;
        }

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let order = order
            .confirm_validations()
            .ok_or_else(|| anyhow!("Failed to confirm validations"))?;

        for (provider, name, id) in record_ids {
            if let Err(e) = self.cleanup_dns_record(&provider, &name, &id).await {
                tracing::warn!("Failed to cleanup DNS record {}: {}", name, e);
            }
        }

        Ok(order)
    }



    fn save_certificates(
        &self,
        cert: &acme_lib::Certificate,
        domain_config: &DomainConfig,
    ) -> Result<String> {
        let fullchain_path = domain_config
            .fullchain_path
            .clone()
            .or_else(|| {
                domain_config
                    .cert_storage_path
                    .as_deref()
                    .map(|p| format!("{}/fullchain.pem", p))
            })
            .ok_or_else(|| anyhow!("No fullchain path configured for {}", domain_config.name))?;

        let privkey_path = domain_config
            .privkey_path
            .clone()
            .or_else(|| {
                domain_config
                    .cert_storage_path
                    .as_deref()
                    .map(|p| format!("{}/privkey.pem", p))
            })
            .ok_or_else(|| anyhow!("No privkey path configured for {}", domain_config.name))?;

        if let Some(parent) = Path::new(&fullchain_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create cert directory: {:?}", parent))?;
        }

        if let Some(parent) = Path::new(&privkey_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create cert directory: {:?}", parent))?;
        }

        std::fs::write(&fullchain_path, cert.certificate())
            .with_context(|| format!("Failed to write fullchain: {}", fullchain_path))?;
        std::fs::write(&privkey_path, cert.private_key())
            .with_context(|| format!("Failed to write privkey: {}", privkey_path))?;

        use sha2::{Digest, Sha256};
        use x509_certificate::certificate::X509Certificate;

        let cert = X509Certificate::from_pem(cert.certificate().as_bytes())
            .map_err(|e| anyhow!("Failed to parse new certificate: {:?}", e))?;
        let der_bytes = cert.encode_der()
            .map_err(|e| anyhow!("Failed to encode DER: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&der_bytes);
        let result = hasher.finalize();
        let fingerprint = result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");

        Ok(fingerprint)
    }

    async fn cloudflare_add_txt(
        &self,
        api_token: &str,
        zone_id: Option<&str>,
        name: &str,
        content: &str,
    ) -> Result<String> {
        let zone = zone_id
            .ok_or_else(|| anyhow!("Cloudflare zone_id is required"))?;

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone
        );

        let payload = serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 120,
            "proxied": false
        });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .context("Failed to call Cloudflare API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Cloudflare API failed ({}): {}", status, text));
        }

        let resp_json: serde_json::Value = response.json().await.unwrap_or_default();
        let record_id = resp_json["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get record ID from Cloudflare response"))?
            .to_string();

        Ok(record_id)
    }

    async fn aliyun_add_txt(
        &self,
        access_key_id: &str,
        access_key_secret: &str,
        region: Option<&str>,
        name: &str,
        content: &str,
    ) -> Result<String> {
        let _region = region.unwrap_or("cn-hangzhou");
        let domain = self.extract_root_domain(name)?;
        let rr = name.strip_suffix(&format!(".{}", domain))
            .unwrap_or(name)
            .to_string();

        let params = serde_json::json!({
            "Action": "AddDomainRecord",
            "Version": "2015-01-09",
            "Format": "JSON",
            "AccessKeyId": access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0",
            "SignatureNonce": format!("{}", rand::random::<u64>()),
            "Timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "DomainName": domain,
            "RR": rr,
            "Type": "TXT",
            "Value": content,
            "TTL": "600"
        });

        let signature = self.aliyun_sign(access_key_secret, "POST", &params)?;

        let mut signed_params = params.as_object().unwrap().clone();
        signed_params.insert("Signature".to_string(), serde_json::Value::String(signature));

        let url = format!("https://alidns.aliyuncs.com/");
        let form = serde_urlencoded::to_string(&signed_params)
            .map_err(|e| anyhow!("Failed to encode form: {}", e))?;

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .context("Failed to call Aliyun DNS API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Aliyun DNS API failed ({}): {}", status, text));
        }

        let resp_json: serde_json::Value = response.json().await.unwrap_or_default();
        let record_id = resp_json["RecordId"]
            .as_str()
            .ok_or_else(|| {
                let msg = resp_json["Message"].as_str().unwrap_or("unknown error");
                anyhow!("Failed to get RecordId from Aliyun response: {}", msg)
            })?
            .to_string();

        Ok(record_id)
    }

    fn extract_root_domain(&self, name: &str) -> Result<String> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid domain name: {}", name));
        }
        let n = parts.len();
        Ok(format!("{}.{}", parts[n - 2], parts[n - 1]))
    }

    fn aliyun_sign(
        &self,
        secret: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<String> {
        let mut sorted_params: Vec<(String, String)> = params
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect();
        sorted_params.sort_by(|a, b| a.0.cmp(&b.0));

        let encoded_params: Vec<String> = sorted_params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    percent_encoding::percent_encode(
                        k.as_bytes(),
                        percent_encoding::NON_ALPHANUMERIC
                    ),
                    percent_encoding::percent_encode(
                        v.as_bytes(),
                        percent_encoding::NON_ALPHANUMERIC
                    )
                )
            })
            .collect();

        let query_string = encoded_params.join("&");

        let string_to_sign = format!(
            "{}&{}&{}",
            method,
            percent_encoding::percent_encode(b"/", percent_encoding::NON_ALPHANUMERIC),
            percent_encoding::percent_encode(
                query_string.as_bytes(),
                percent_encoding::NON_ALPHANUMERIC
            )
        );

        let key = format!("{}&", secret);
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key.as_bytes())
            .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
        mac.update(string_to_sign.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        Ok(signature)
    }

    async fn cleanup_dns_record(
        &self,
        provider: &DnsProviderConfig,
        name: &str,
        record_id: &str,
    ) -> Result<()> {
        match provider {
            DnsProviderConfig::Cloudflare { api_token, zone_id } => {
                let zone = zone_id.clone()
                    .ok_or_else(|| anyhow!("Cloudflare zone_id is required for cleanup"))?;
                let url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    zone, record_id
                );
                let _ = self
                    .http_client
                    .delete(&url)
                    .header("Authorization", format!("Bearer {}", api_token))
                    .send()
                    .await;
            }
            DnsProviderConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region,
            } => {
                let _region = region.as_deref().unwrap_or("cn-hangzhou");
                let params = serde_json::json!({
                    "Action": "DeleteDomainRecord",
                    "Version": "2015-01-09",
                    "Format": "JSON",
                    "AccessKeyId": access_key_id,
                    "SignatureMethod": "HMAC-SHA1",
                    "SignatureVersion": "1.0",
                    "SignatureNonce": format!("{}", rand::random::<u64>()),
                    "Timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    "RecordId": record_id
                });
                let signature = self.aliyun_sign(access_key_secret, "POST", &params)?;
                let mut signed_params = params.as_object().unwrap().clone();
                signed_params.insert(
                    "Signature".to_string(),
                    serde_json::Value::String(signature),
                );
                let url = format!("https://alidns.aliyuncs.com/");
                let form = serde_urlencoded::to_string(&signed_params)
                    .map_err(|e| anyhow!("Failed to encode form: {}", e))?;
                let _ = self
                    .http_client
                    .post(&url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form)
                    .send()
                    .await;
            }
        }
        tracing::debug!("Cleaned up DNS record: {}", name);
        Ok(())
    }
}
