use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub domains: Vec<DomainConfig>,
    pub sources: Option<SourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub state_file: Option<String>,
    pub concurrency: Option<u32>,
    pub connect_timeout: Option<u64>,
    pub acme_account_email: String,
    pub acme_directory: Option<String>,
    pub default_dns_provider: Option<String>,
    pub renew_threshold_days: Option<i64>,
    pub hook_timeout: Option<u64>,
    pub notification_debounce_hours: Option<i64>,
    pub smtp: Option<SmtpConfig>,
    pub slack: Option<SlackConfig>,
    pub dingtalk: Option<DingTalkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    pub domain_list: Option<Vec<String>>,
    pub ip_ranges: Option<Vec<IpRangeConfig>>,
    pub pem_directories: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRangeConfig {
    pub cidr: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DingTalkConfig {
    pub webhook_url: String,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub name: String,
    pub validation_method: Option<ValidationMethod>,
    pub dns_provider: Option<DnsProviderConfig>,
    pub cert_storage_path: Option<String>,
    pub fullchain_path: Option<String>,
    pub privkey_path: Option<String>,
    pub http_challenge_dir: Option<String>,
    pub deployment_hooks: Option<Vec<String>>,
    pub verification_hook: Option<bool>,
    pub auto_renew: bool,
    pub ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMethod {
    Http01,
    Dns01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsProviderConfig {
    Cloudflare {
        api_token: String,
        zone_id: Option<String>,
    },
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
        region: Option<String>,
    },
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML config: {}", path.display()))?;
        Ok(config)
    }

    pub fn get_state_file_path(&self) -> PathBuf {
        self.global
            .state_file
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| {
                dirs::home_dir().map(|h| h.join(".cert-monitor").join("state.json"))
            })
            .unwrap_or_else(|| PathBuf::from("cert-monitor-state.json"))
    }

    pub fn concurrency(&self) -> u32 {
        self.global.concurrency.unwrap_or(20)
    }

    pub fn connect_timeout_secs(&self) -> u64 {
        self.global.connect_timeout.unwrap_or(10)
    }

    pub fn renew_threshold_days(&self) -> i64 {
        self.global.renew_threshold_days.unwrap_or(30)
    }

    pub fn hook_timeout_secs(&self) -> u64 {
        self.global.hook_timeout.unwrap_or(60)
    }

    pub fn notification_debounce_hours(&self) -> i64 {
        self.global.notification_debounce_hours.unwrap_or(24)
    }

    pub fn acme_directory_url(&self) -> String {
        self.global
            .acme_directory
            .clone()
            .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string())
    }
}

pub fn generate_default_config_template() -> String {
    let mut s = String::new();
    s.push_str("# cert-monitor 配置文件模板\n");
    s.push_str("global:\n");
    s.push_str("  # 状态文件路径\n");
    s.push_str("  state_file: \"~/.cert-monitor/state.json\"\n");
    s.push_str("  # 并发连接数\n");
    s.push_str("  concurrency: 20\n");
    s.push_str("  # 连接超时时间(秒)\n");
    s.push_str("  connect_timeout: 10\n");
    s.push_str("  # ACME 账户邮箱\n");
    s.push_str("  acme_account_email: \"admin@example.com\"\n");
    s.push_str("  # ACME 目录URL (默认使用Let's Encrypt生产环境)\n");
    s.push_str("  acme_directory: \"https://acme-v02.api.letsencrypt.org/directory\"\n");
    s.push_str("  # 续签阈值(天),小于此值才触发续签\n");
    s.push_str("  renew_threshold_days: 30\n");
    s.push_str("  # 部署钩子超时时间(秒)\n");
    s.push_str("  hook_timeout: 60\n");
    s.push_str("  # 通知防抖时间(小时)\n");
    s.push_str("  notification_debounce_hours: 24\n");
    s.push_str("\n");
    s.push_str("  # 邮件通知配置\n");
    s.push_str("  smtp:\n");
    s.push_str("    host: \"smtp.example.com\"\n");
    s.push_str("    port: 465\n");
    s.push_str("    username: \"alert@example.com\"\n");
    s.push_str("    password: \"your-smtp-password\"\n");
    s.push_str("    from: \"alert@example.com\"\n");
    s.push_str("    to:\n");
    s.push_str("      - \"admin@example.com\"\n");
    s.push_str("    use_tls: true\n");
    s.push_str("\n");
    s.push_str("  # Slack 通知配置\n");
    s.push_str("  slack:\n");
    s.push_str("    webhook_url: \"https://hooks.slack.com/services/xxx/yyy/zzz\"\n");
    s.push_str("    channel: \"#alerts\"\n");
    s.push_str("\n");
    s.push_str("  # 钉钉通知配置\n");
    s.push_str("  dingtalk:\n");
    s.push_str("    webhook_url: \"https://oapi.dingtalk.com/robot/send?access_token=xxx\"\n");
    s.push_str("    secret: \"your-sign-secret\"\n");
    s.push_str("\n");
    s.push_str("# 扫描数据源配置(可选)\n");
    s.push_str("sources:\n");
    s.push_str("  # 直接指定域名列表\n");
    s.push_str("  domain_list:\n");
    s.push_str("    - \"example.com\"\n");
    s.push_str("    - \"api.example.com\"\n");
    s.push_str("  # IP段扫描\n");
    s.push_str("  ip_ranges:\n");
    s.push_str("    - cidr: \"192.168.1.0/24\"\n");
    s.push_str("      port: 443\n");
    s.push_str("  # 从本地目录读取PEM文件\n");
    s.push_str("  pem_directories:\n");
    s.push_str("    - \"/etc/nginx/ssl\"\n");
    s.push_str("    - \"/etc/traefik/certs\"\n");
    s.push_str("\n");
    s.push_str("# 域名列表配置\n");
    s.push_str("domains:\n");
    s.push_str("  - name: \"example.com\"\n");
    s.push_str("    # 验证方式: http01 或 dns01\n");
    s.push_str("    validation_method: \"dns01\"\n");
    s.push_str("    # DNS 提供商配置\n");
    s.push_str("    dns_provider:\n");
    s.push_str("      type: \"cloudflare\"\n");
    s.push_str("      api_token: \"your-cloudflare-api-token\"\n");
    s.push_str("    # 证书存储路径\n");
    s.push_str("    cert_storage_path: \"/etc/nginx/ssl/example.com\"\n");
    s.push_str("    fullchain_path: \"/etc/nginx/ssl/example.com/fullchain.pem\"\n");
    s.push_str("    privkey_path: \"/etc/nginx/ssl/example.com/privkey.pem\"\n");
    s.push_str("    # HTTP-01 挑战文件目录\n");
    s.push_str("    http_challenge_dir: \"/var/www/html/.well-known/acme-challenge\"\n");
    s.push_str("    # 部署钩子命令\n");
    s.push_str("    deployment_hooks:\n");
    s.push_str("      - \"nginx -s reload\"\n");
    s.push_str("    # 部署完成后验证证书\n");
    s.push_str("    verification_hook: true\n");
    s.push_str("    # 是否启用自动续签\n");
    s.push_str("    auto_renew: true\n");
    s.push_str("\n");
    s.push_str("  - name: \"api.example.com\"\n");
    s.push_str("    validation_method: \"dns01\"\n");
    s.push_str("    dns_provider:\n");
    s.push_str("      type: \"aliyun\"\n");
    s.push_str("      access_key_id: \"your-aliyun-access-key\"\n");
    s.push_str("      access_key_secret: \"your-aliyun-secret\"\n");
    s.push_str("      region: \"cn-hangzhou\"\n");
    s.push_str("    fullchain_path: \"/etc/nginx/ssl/api.example.com/fullchain.pem\"\n");
    s.push_str("    privkey_path: \"/etc/nginx/ssl/api.example.com/privkey.pem\"\n");
    s.push_str("    deployment_hooks:\n");
    s.push_str("      - \"systemctl reload nginx\"\n");
    s.push_str("    verification_hook: true\n");
    s.push_str("    auto_renew: true\n");
    s
}
