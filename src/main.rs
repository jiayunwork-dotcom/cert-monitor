mod acme;
mod config;
mod deploy;
mod notify;
mod report;
mod scanner;
mod state;
mod types;

use crate::config::Config;
use crate::deploy::{Deployer, DeployResultInner};
use crate::notify::Notifier;
use crate::report::ReportGenerator;
use crate::scanner::Scanner;
use crate::state::StateManager;
use crate::types::{AlertLevel, ScanResult};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "cert-monitor",
    version = "1.0.0",
    about = "SSL证书到期监控与自动续签编排工具",
    long_about = "用来帮运维团队统一管理分散在各处的HTTPS证书,及时预警快过期的证书并自动完成续签流程"
)]
struct Cli {
    #[arg(
        short,
        long,
        global = true,
        default_value = "config.yaml",
        help = "配置文件路径"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "扫描所有配置的域名并输出监控报告")]
    Scan {
        #[arg(long, help = "输出JSON格式报告到指定文件")]
        json_output: Option<PathBuf>,

        #[arg(long, help = "扫描后自动执行通知")]
        notify: bool,
    },

    #[command(about = "对符合条件的域名执行证书续签")]
    Renew {
        #[arg(long, help = "指定域名续签(不指定则续签所有符合条件的)")]
        domain: Option<String>,

        #[arg(long, help = "续签成功后自动执行部署钩子")]
        deploy: bool,

        #[arg(long, help = "即使未到续签阈值也强制续签")]
        force: bool,
    },

    #[command(about = "对指定域名执行部署钩子")]
    Deploy {
        #[arg(help = "要部署的域名")]
        domain: String,

        #[arg(long, help = "预期的证书指纹用于验证")]
        expected_fingerprint: Option<String>,
    },

    #[command(about = "展示所有域名当前状态摘要")]
    Status {
        #[arg(long, help = "输出JSON格式")]
        json: bool,
    },

    #[command(about = "交互式生成配置文件模板")]
    Init {
        #[arg(long, help = "输出文件路径", default_value = "config.yaml")]
        output: PathBuf,

        #[arg(long, help = "覆盖已存在的文件")]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { output, force } => {
            cmd_init(&output, force).await?;
        }
        Commands::Scan {
            json_output,
            notify,
        } => {
            let config = load_config(&cli.config)?;
            cmd_scan(Arc::new(config), json_output, notify).await?;
        }
        Commands::Renew {
            domain,
            deploy,
            force,
        } => {
            let config = load_config(&cli.config)?;
            cmd_renew(Arc::new(config), domain.as_deref(), deploy, force).await?;
        }
        Commands::Deploy {
            domain,
            expected_fingerprint,
        } => {
            let config = load_config(&cli.config)?;
            cmd_deploy(Arc::new(config), &domain, expected_fingerprint.as_deref()).await?;
        }
        Commands::Status { json } => {
            let config = load_config(&cli.config)?;
            cmd_status(Arc::new(config), json).await?;
        }
    }

    Ok(())
}

fn load_config(path: &PathBuf) -> Result<Config> {
    Config::load_from_file(path)
        .with_context(|| format!("加载配置文件失败: {}", path.display()))
}

fn prompt_input(prompt: &str, default: Option<&str>) -> Result<String> {
    use std::io::{self, Write};

    match default {
        Some(d) => print!("{} [{}]: ", prompt, d),
        None => print!("{}: ", prompt),
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

    if input.is_empty() {
        if let Some(d) = default {
            Ok(d.to_string())
        } else {
            Err(anyhow!("输入不能为空"))
        }
    } else {
        Ok(input)
    }
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    use std::io::{self, Write};

    let default_str = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", prompt, default_str);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        Ok(default)
    } else {
        Ok(input == "y" || input == "yes")
    }
}

async fn cmd_init(output: &PathBuf, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(anyhow!(
            "文件 {} 已存在, 使用 --force 覆盖",
            output.display()
        ));
    }

    println!("{}", "╔══════════════════════════════════════════════════════════════╗".bold().cyan());
    println!("{}", "║          cert-monitor 配置文件交互式生成向导                ║".bold().cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".bold().cyan());
    println!();
    println!("请回答以下问题来生成配置文件 (方括号内为默认值,直接回车使用默认值)");
    println!();

    println!("{}", "━━━ 基本配置 ━━━".bold().cyan());
    let acme_email = prompt_input("ACME账户邮箱", Some("admin@example.com"))?;
    let state_file = prompt_input("状态文件路径", Some("~/.cert-monitor/state.json"))?;
    let concurrency: u32 = prompt_input("并发连接数", Some("20"))?.parse()?;
    let connect_timeout: u64 = prompt_input("连接超时(秒)", Some("10"))?.parse()?;

    println!();
    println!("{}", "━━━ 续签配置 ━━━".bold().cyan());
    let renew_threshold: i64 = prompt_input("续签阈值(天)", Some("30"))?.parse()?;
    let hook_timeout: u64 = prompt_input("部署钩子超时(秒)", Some("60"))?.parse()?;
    let notification_debounce: i64 = prompt_input("通知防抖时间(小时)", Some("24"))?.parse()?;

    let use_staging = prompt_yes_no("使用Let's Encrypt测试环境?", false)?;
    let acme_directory = if use_staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
    } else {
        "https://acme-v02.api.letsencrypt.org/directory".to_string()
    };

    println!();
    println!("{}", "━━━ 通知渠道配置 ━━━".bold().cyan());
    let configure_smtp = prompt_yes_no("配置SMTP邮件通知?", false)?;
    let (smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, smtp_to) = if configure_smtp {
        let host = prompt_input("SMTP服务器地址", Some("smtp.example.com"))?;
        let port: u16 = prompt_input("SMTP端口", Some("465"))?.parse()?;
        let user = prompt_input("SMTP用户名", Some("alert@example.com"))?;
        let pass = prompt_input("SMTP密码", Some("your-smtp-password"))?;
        let from = prompt_input("发件人地址", Some("alert@example.com"))?;
        let to = prompt_input("收件人地址(多个用逗号分隔)", Some("admin@example.com"))?;
        let to_list = to.split(',').map(|s| s.trim().to_string()).collect();
        (Some(host), Some(port), Some(user), Some(pass), Some(from), Some(to_list))
    } else {
        (None, None, None, None, None, None)
    };

    let configure_slack = prompt_yes_no("配置Slack通知?", false)?;
    let (slack_webhook, slack_channel) = if configure_slack {
        let webhook = prompt_input("Slack Webhook URL", Some("https://hooks.slack.com/services/xxx/yyy/zzz"))?;
        let channel = prompt_input("Slack频道", Some("#alerts"))?;
        (Some(webhook), Some(channel))
    } else {
        (None, None)
    };

    let configure_dingtalk = prompt_yes_no("配置钉钉通知?", false)?;
    let (dingtalk_webhook, dingtalk_secret) = if configure_dingtalk {
        let webhook = prompt_input("钉钉Webhook URL", Some("https://oapi.dingtalk.com/robot/send?access_token=xxx"))?;
        let secret = prompt_input("钉钉签名密钥(可选)", Some(""))?;
        let secret_opt = if secret.is_empty() { None } else { Some(secret) };
        (Some(webhook), secret_opt)
    } else {
        (None, None)
    };

    println!();
    println!("{}", "━━━ 域名配置 ━━━".bold().cyan());
    let domain_count: usize = prompt_input("要监控的域名数量", Some("1"))?.parse()?;

    let mut domains = Vec::new();
    for i in 0..domain_count {
        println!();
        println!("{} {}", "第".cyan(), (i + 1).to_string().cyan().bold());
        let name = prompt_input("域名", None)?;

        let validation_str = prompt_input("验证方式 (http01/dns01)", Some("dns01"))?.to_lowercase();
        let validation_method = if validation_str == "http01" {
            crate::config::ValidationMethod::Http01
        } else {
            crate::config::ValidationMethod::Dns01
        };

        let dns_provider = if matches!(validation_method, crate::config::ValidationMethod::Dns01) {
            let provider_str = prompt_input("DNS提供商 (cloudflare/aliyun)", Some("cloudflare"))?.to_lowercase();
            if provider_str == "aliyun" {
                let access_key = prompt_input("阿里云AccessKey ID", Some("your-access-key-id"))?;
                let access_secret = prompt_input("阿里云AccessKey Secret", Some("your-access-key-secret"))?;
                let region = prompt_input("阿里云区域", Some("cn-hangzhou"))?;
                Some(crate::config::DnsProviderConfig::Aliyun {
                    access_key_id: access_key,
                    access_key_secret: access_secret,
                    region: Some(region),
                })
            } else {
                let api_token = prompt_input("Cloudflare API Token", Some("your-cloudflare-api-token"))?;
                let zone_id = prompt_input("Cloudflare Zone ID(可选)", Some(""))?;
                let zone_id_opt = if zone_id.is_empty() { None } else { Some(zone_id) };
                Some(crate::config::DnsProviderConfig::Cloudflare {
                    api_token,
                    zone_id: zone_id_opt,
                })
            }
        } else {
            None
        };

        let http_challenge_dir = if matches!(validation_method, crate::config::ValidationMethod::Http01) {
            Some(prompt_input("HTTP挑战文件目录", Some("/var/www/html/.well-known/acme-challenge"))?)
        } else {
            None
        };

        let default_cert_path = format!("/etc/nginx/ssl/{}", name);
        let cert_path = prompt_input("证书存储目录", Some(&default_cert_path))?;
        let auto_renew = prompt_yes_no("启用自动续签?", true)?;
        let deploy_hook = prompt_input("部署钩子命令(可选,如: nginx -s reload)", Some(""))?;
        let deploy_hooks = if deploy_hook.is_empty() { None } else { Some(vec![deploy_hook]) };
        let verification_hook = prompt_yes_no("部署后验证证书?", true)?;

        domains.push(crate::config::DomainConfig {
            name: name.clone(),
            validation_method: Some(validation_method),
            dns_provider,
            cert_storage_path: Some(cert_path.clone()),
            fullchain_path: Some(format!("{}/fullchain.pem", cert_path)),
            privkey_path: Some(format!("{}/privkey.pem", cert_path)),
            http_challenge_dir,
            deployment_hooks: deploy_hooks,
            verification_hook: Some(verification_hook),
            auto_renew,
            ports: None,
        });
    }

    println!();
    println!("{}", "━━━ 生成配置 ━━━".bold().cyan());

    let config = crate::config::Config {
        global: crate::config::GlobalConfig {
            state_file: Some(state_file),
            concurrency: Some(concurrency),
            connect_timeout: Some(connect_timeout),
            acme_account_email: acme_email,
            acme_directory: Some(acme_directory),
            default_dns_provider: None,
            renew_threshold_days: Some(renew_threshold),
            hook_timeout: Some(hook_timeout),
            notification_debounce_hours: Some(notification_debounce),
            smtp: smtp_host.map(|host| crate::config::SmtpConfig {
                host,
                port: smtp_port.unwrap_or(465),
                username: smtp_user.unwrap_or_default(),
                password: smtp_pass.unwrap_or_default(),
                from: smtp_from.unwrap_or_default(),
                to: smtp_to.unwrap_or_default(),
                use_tls: Some(true),
            }),
            slack: slack_webhook.map(|webhook| crate::config::SlackConfig {
                webhook_url: webhook,
                channel: slack_channel,
            }),
            dingtalk: dingtalk_webhook.map(|webhook| crate::config::DingTalkConfig {
                webhook_url: webhook,
                secret: dingtalk_secret,
            }),
        },
        domains,
        sources: None,
    };

    let yaml = serde_yaml::to_string(&config)
        .with_context(|| "序列化配置失败")?;

    let yaml_with_comments = format!(
        "# cert-monitor 配置文件\n# 由交互式向导生成于 {}\n\n{}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        yaml
    );

    if let Some(parent) = output.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建目录失败: {}", parent.display()))?;
        }
    }

    std::fs::write(output, yaml_with_comments)
        .with_context(|| format!("写入配置文件失败: {}", output.display()))?;

    println!();
    println!(
        "{} {}",
        "✓ 配置文件已生成:".green().bold(),
        output.display()
    );
    println!();
    println!("您可以随时编辑该文件修改配置。配置完成后,使用以下命令开始扫描:");
    println!("  {} ./cert-monitor scan --notify", "➜".yellow());
    println!();
    println!("如需添加更多数据源(IP段扫描、PEM目录扫描等),请手动编辑配置文件。");

    Ok(())
}

async fn cmd_scan(
    config: Arc<Config>,
    json_output: Option<PathBuf>,
    send_notifications: bool,
) -> Result<Vec<ScanResult>> {
    let state_path = config.get_state_file_path();
    let mut state_manager = StateManager::new(&state_path)?;

    let scanner = Scanner::new(config.clone());
    let mut notifier = Notifier::new(config.clone(), state_manager.clone());

    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "                       SSL 证书监控扫描报告".bold().cyan()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!();

    let results = scanner.scan_all().await;

    for result in &results {
        state_manager.update_scan_time(&result.domain);
        if let Some(cert) = &result.cert {
            state_manager.update_fingerprint(
                &result.domain,
                cert.fingerprint_sha256.clone(),
            );
        }
    }
    state_manager.save()?;

    println!("{}", ReportGenerator::format_terminal_table(&results));
    println!("{}", ReportGenerator::format_summary(&results));

    let mut alerts_sent = Vec::new();
    if send_notifications {
        println!("{}", "发送预警通知...".yellow().bold());
        for result in &results {
            if let Some(cert) = &result.cert {
                if !cert.chain_complete {
                    tracing::warn!("证书链不完整: {}", cert.domain);
                }
                let channels = notifier.send_alert_if_needed(cert).await?;
                if !channels.is_empty() {
                    alerts_sent.push((cert.domain.clone(), channels));
                }
            }
        }

        if alerts_sent.is_empty() {
            println!("{}", "✓ 无需发送通知 (所有域名在防抖周期内)".green());
        } else {
            println!();
            println!("{}", "已发送通知:".green().bold());
            for (domain, channels) in &alerts_sent {
                println!(
                    "  {} → {}",
                    domain,
                    channels.join(", ")
                );
            }
        }
    }

    if let Some(json_path) = json_output {
        let json = ReportGenerator::to_json(&results)?;
        std::fs::write(&json_path, json)
            .with_context(|| format!("写入JSON报告失败: {}", json_path.display()))?;
        println!();
        println!(
            "{} {}",
            "✓ JSON报告已保存:".green().bold(),
            json_path.display()
        );
    }

    println!();
    println!(
        "{} {}",
        "状态文件:".blue(),
        state_path.display()
    );

    Ok(results)
}

async fn cmd_renew(
    config: Arc<Config>,
    domain_filter: Option<&str>,
    auto_deploy: bool,
    force: bool,
) -> Result<()> {
    let state_path = config.get_state_file_path();
    let mut state_manager = StateManager::new(&state_path)?;

    let scanner = Scanner::new(config.clone());
    let acme_client = crate::acme::AcmeClient::new(config.clone());
    let deployer = Deployer::new(config.clone(), scanner.clone());

    let domain_configs: Vec<_> = config
        .domains
        .iter()
        .filter(|dc| match domain_filter {
            Some(d) => dc.name == d,
            None => dc.auto_renew,
        })
        .collect();

    if domain_configs.is_empty() {
        println!("{}", "没有找到需要续签的域名".yellow());
        return Ok(());
    }

    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "                         SSL 证书自动续签".bold().cyan()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!();

    let scan_results = scanner.scan_all().await;
    let cert_map: std::collections::HashMap<_, _> = scan_results
        .into_iter()
        .filter_map(|r| r.cert.map(|c| (c.domain.clone(), c)))
        .collect();

    for dc in domain_configs {
        let cert = cert_map.get(&dc.name);

        let needs_renewal = if force {
            println!(
                "{} {} (强制续签)",
                "→".yellow().bold(),
                dc.name.bold()
            );
            true
        } else {
            match cert {
                Some(c) => {
                    let needs = acme_client.needs_renewal(c);
                    if needs {
                        println!(
                            "{} {} (剩余 {} 天, 阈值 {} 天)",
                            "→".yellow().bold(),
                            dc.name.bold(),
                            c.days_remaining().to_string().red().bold(),
                            config.renew_threshold_days()
                        );
                    } else {
                        println!(
                            "{} {} (剩余 {} 天, 无需续签)",
                            "✓".green(),
                            dc.name,
                            c.days_remaining().to_string().green()
                        );
                    }
                    needs
                }
                None => {
                    println!(
                        "{} {} (无法获取证书信息, 跳过)",
                        "✗".red(),
                        dc.name
                    );
                    false
                }
            }
        };

        if !needs_renewal {
            continue;
        }

        println!();
        println!("  开始续签流程...");

        let history = acme_client.renew_certificate(dc).await?;
        state_manager.add_renewal_history(&dc.name, history.clone());

        if history.success {
            state_manager.update_renew_time(&dc.name);
            if let Some(fp) = &history.new_fingerprint {
                state_manager.update_fingerprint(&dc.name, fp.clone());
            }
            state_manager.save()?;

            println!(
                "  {} 续签成功! 新指纹: {}",
                "✓".green().bold(),
                history
                    .new_fingerprint
                    .as_deref()
                    .unwrap_or("N/A")
            );

            if auto_deploy {
                println!();
                println!("  执行部署钩子...");

                let deploy_result = deployer
                    .deploy_domain(dc, history.new_fingerprint.as_deref())
                    .await?;

                print_deploy_result(&deploy_result, 2);

                if !deploy_result.all_hooks_successful()
                    || !deploy_result.verification_passed()
                {
                    if let Some(cert_info) = cert {
                        let mut _notifier =
                            Notifier::new(config.clone(), state_manager.clone());
                        if let Some(level) =
                            AlertLevel::from_days(cert_info.days_remaining())
                        {
                            if state_manager.should_send_notification(
                                &dc.name,
                                &level,
                                config.notification_debounce_hours(),
                            ) {
                                println!(
                                    "  {} 发送部署失败预警通知...",
                                    "⚠️".yellow()
                                );
                            }
                        }
                    }
                }
            }
        } else {
            println!(
                "  {} 续签失败: {}",
                "✗".red().bold(),
                history.message
            );
        }
        println!();
    }

    state_manager.save()?;
    println!();
    println!(
        "{} {}",
        "状态文件:".blue(),
        state_path.display()
    );

    Ok(())
}

async fn cmd_deploy(
    config: Arc<Config>,
    domain: &str,
    expected_fingerprint: Option<&str>,
) -> Result<()> {
    let state_path = config.get_state_file_path();
    let state_manager = StateManager::new(&state_path)?;

    let scanner = Scanner::new(config.clone());
    let deployer = Deployer::new(config.clone(), scanner.clone());

    let dc = config
        .domains
        .iter()
        .find(|d| d.name == domain)
        .ok_or_else(|| anyhow!("配置中未找到域名: {}", domain))?;

    let domain_state = state_manager.get_domain_state(domain);
    let fp = expected_fingerprint.or_else(|| {
        domain_state
            .current_fingerprint
            .as_deref()
    });

    if fp.is_none() {
        println!(
            "{}",
            "⚠️  未提供预期指纹, 将跳过验证钩子"
                .yellow()
                .bold()
        );
    }

    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "                           部署钩子执行".bold().cyan()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!();
    println!("{}: {}", "目标域名".bold(), domain);
    if let Some(fp) = fp {
        println!("{}: {}", "预期指纹".bold(), fp);
    }
    println!();

    let result = deployer.deploy_domain(dc, fp).await?;
    print_deploy_result(&result, 0);

    let errors = result.has_errors();
    if errors.is_empty() {
        println!();
        println!("{}", "✓ 部署完成".green().bold());
    } else {
        println!();
        println!("{}", "⚠️  部署过程中出现错误:".yellow().bold());
        for error in &errors {
            println!("  - {}", error);
        }
    }

    Ok(())
}

async fn cmd_status(config: Arc<Config>, json_output: bool) -> Result<()> {
    let state_path = config.get_state_file_path();
    let state_manager = StateManager::new(&state_path)?;
    let state = state_manager.state();

    if json_output {
        let json = serde_json::to_string_pretty(state)?;
        println!("{}", json);
        return Ok(());
    }

    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "                         域名状态摘要".bold().cyan()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bold()
            .cyan()
    );
    println!();
    println!(
        "{} {}",
        "上次更新时间:".blue(),
        state.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "{} {}",
        "监控域名数:".blue(),
        state.domains.len().to_string().bold()
    );
    println!();

    let mut table = comfy_table::Table::new();
    table.set_content_arrangement(comfy_table::ContentArrangement::Dynamic);
    table.set_header(vec![
        comfy_table::Cell::new("域名")
            .add_attribute(comfy_table::Attribute::Bold)
            .fg(comfy_table::Color::Blue),
        comfy_table::Cell::new("上次扫描")
            .add_attribute(comfy_table::Attribute::Bold)
            .fg(comfy_table::Color::Blue),
        comfy_table::Cell::new("上次续签")
            .add_attribute(comfy_table::Attribute::Bold)
            .fg(comfy_table::Color::Blue),
        comfy_table::Cell::new("当前指纹")
            .add_attribute(comfy_table::Attribute::Bold)
            .fg(comfy_table::Color::Blue),
        comfy_table::Cell::new("续签记录")
            .add_attribute(comfy_table::Attribute::Bold)
            .fg(comfy_table::Color::Blue),
    ]);

    let mut domains: Vec<_> = state.domains.iter().collect();
    domains.sort_by(|a, b| a.0.cmp(b.0));

    for (domain, ds) in domains {
        let last_scan = ds
            .last_scan
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "-".to_string());
        let last_renew = ds
            .last_renew
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "-".to_string());
        let fingerprint = ds
            .current_fingerprint
            .as_ref()
            .map(|f| {
                if f.len() > 20 {
                    f.chars().take(17).collect::<String>() + "..."
                } else {
                    f.clone()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let success_count = ds.renewal_history.iter().filter(|h| h.success).count();
        let history_str = format!(
            "{}/{} (最近5次)",
            success_count,
            ds.renewal_history.len()
        );

        table.add_row(vec![
            comfy_table::Cell::new(domain),
            comfy_table::Cell::new(last_scan),
            comfy_table::Cell::new(last_renew),
            comfy_table::Cell::new(fingerprint),
            comfy_table::Cell::new(history_str),
        ]);
    }

    println!("{}", table);

    println!();
    println!(
        "{} {}",
        "状态文件:".blue(),
        state_path.display()
    );

    Ok(())
}

fn print_deploy_result(result: &DeployResultInner, indent: usize) {
    let prefix = " ".repeat(indent);

    for (i, hook) in result.hooks.iter().enumerate() {
        let status = if hook.success {
            "✓".green().to_string()
        } else {
            "✗".red().to_string()
        };
        println!(
            "{}{} [{}] {}",
            prefix,
            status,
            i,
            hook.command
        );
        if !hook.success {
            println!("{}   错误: {}", prefix, hook.output.red());
        }
    }

    if let Some(verification) = &result.verification {
        match verification {
            Ok(true) => {
                println!(
                    "{}{} 验证通过: 证书指纹匹配",
                    prefix,
                    "✓".green().bold()
                );
            }
            Ok(false) => {
                println!(
                    "{}{} 验证失败: 证书指纹不匹配",
                    prefix,
                    "✗".red().bold()
                );
            }
            Err(e) => {
                println!(
                    "{}{} 验证错误: {}",
                    prefix,
                    "✗".red().bold(),
                    e
                );
            }
        }
    }
}
