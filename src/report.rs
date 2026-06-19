use crate::types::{AlertLevel, CertificateInfo, ScanResult};
use colored::*;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn format_terminal_table(results: &[ScanResult]) -> String {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);

        table.set_header(vec![
            Cell::new("域名")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("剩余天数")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("状态")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("颁发者")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("有效期至")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("证书链")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
            Cell::new("指纹(SHA256)")
                .add_attribute(Attribute::Bold)
                .fg(Color::Blue),
        ]);

        let mut sorted_results: Vec<&ScanResult> = results.iter().collect();
        sorted_results.sort_by(|a, b| {
            let a_days = a
                .cert
                .as_ref()
                .map(|c| c.days_remaining())
                .unwrap_or(i64::MAX);
            let b_days = b
                .cert
                .as_ref()
                .map(|c| c.days_remaining())
                .unwrap_or(i64::MAX);
            a_days.cmp(&b_days)
        });

        for result in sorted_results {
            match &result.cert {
                Some(cert) => {
                    table.add_row(Self::format_cert_row(cert));
                }
                None => {
                    let error_msg = result
                        .error
                        .as_deref()
                        .unwrap_or("Unknown error");
                    table.add_row(vec![
                        Cell::new(&result.domain).fg(Color::Red),
                        Cell::new("N/A"),
                        Cell::new("扫描失败"),
                        Cell::new("N/A"),
                        Cell::new("N/A"),
                        Cell::new("N/A"),
                        Cell::new(error_msg).fg(Color::Red),
                    ]);
                }
            }
        }

        table.to_string()
    }

    fn format_cert_row(cert: &CertificateInfo) -> Vec<Cell> {
        let days = cert.days_remaining();
        let status_cell = Self::format_days_cell(days);
        let chain_cell = if cert.chain_complete {
            Cell::new("完整").fg(Color::Green)
        } else {
            Cell::new("不完整⚠️").fg(Color::Yellow)
        };

        let issuer = if cert.issuer.len() > 40 {
            format!("{}...", &cert.issuer.chars().take(37).collect::<String>())
        } else {
            cert.issuer.clone()
        };

        let fingerprint = if cert.fingerprint_sha256.len() > 20 {
            cert.fingerprint_sha256
                .chars()
                .take(17)
                .collect::<String>()
                + "..."
        } else {
            cert.fingerprint_sha256.clone()
        };

        vec![
            Cell::new(&cert.domain),
            status_cell,
            Cell::new(Self::format_status_text(days, &cert.ocsp_status)),
            Cell::new(issuer),
            Cell::new(
                cert.not_after
                    .format("%Y-%m-%d")
                    .to_string(),
            ),
            chain_cell,
            Cell::new(fingerprint),
        ]
    }

    fn format_days_cell(days: i64) -> Cell {
        if days < 0 {
            Cell::new(format!("已过期 {} 天", days.abs()))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
        } else if days <= 7 {
            Cell::new(format!("{} 天", days))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
        } else if days <= 30 {
            Cell::new(format!("{} 天", days))
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold)
        } else if days <= 60 {
            Cell::new(format!("{} 天", days)).fg(Color::Yellow)
        } else {
            Cell::new(format!("{} 天", days)).fg(Color::Green)
        }
    }

    fn format_status_text(
        days: i64,
        ocsp: &crate::types::OcspStatus,
    ) -> String {
        let level = AlertLevel::from_days(days);
        let status = match level {
            Some(AlertLevel::Emergency) => "紧急",
            Some(AlertLevel::Critical) => "严重",
            Some(AlertLevel::Warning) => "警告",
            Some(AlertLevel::Info) => "注意",
            None => "正常",
        };
        let ocsp_text = match ocsp {
            crate::types::OcspStatus::Good => "",
            crate::types::OcspStatus::Revoked => " (已吊销)",
            crate::types::OcspStatus::Unknown => "",
        };
        format!("{}{}", status, ocsp_text)
    }

    pub fn format_summary(results: &[ScanResult]) -> String {
        let total = results.len();
        let success = results.iter().filter(|r| r.cert.is_some()).count();
        let failed = total - success;

        let emergency = results
            .iter()
            .filter(|r| {
                r.cert
                    .as_ref()
                    .map(|c| c.days_remaining() < 0)
                    .unwrap_or(false)
            })
            .count();
        let critical = results
            .iter()
            .filter(|r| {
                r.cert
                    .as_ref()
                    .map(|c| c.days_remaining() >= 0 && c.days_remaining() <= 7)
                    .unwrap_or(false)
            })
            .count();
        let warning = results
            .iter()
            .filter(|r| {
                r.cert
                    .as_ref()
                    .map(|c| c.days_remaining() > 7 && c.days_remaining() <= 30)
                    .unwrap_or(false)
            })
            .count();
        let info = results
            .iter()
            .filter(|r| {
                r.cert
                    .as_ref()
                    .map(|c| c.days_remaining() > 30 && c.days_remaining() <= 60)
                    .unwrap_or(false)
            })
            .count();
        let ok = results
            .iter()
            .filter(|r| {
                r.cert
                    .as_ref()
                    .map(|c| c.days_remaining() > 60)
                    .unwrap_or(false)
            })
            .count();

        format!(
            "\n扫描完成: 总计 {} 个域名, 成功 {} 个, 失败 {} 个\n\
            状态分布: 紧急(已过期) {} | 严重(≤7天) {} | 警告(≤30天) {} | 注意(≤60天) {} | 正常 {} \n",
            total.to_string().bold(),
            success.to_string().green().bold(),
            failed.to_string().red().bold(),
            emergency.to_string().red().bold(),
            critical.to_string().red().bold(),
            warning.to_string().yellow().bold(),
            info.to_string().yellow(),
            ok.to_string().green()
        )
    }

    pub fn to_json(results: &[ScanResult]) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(results)
    }
}
