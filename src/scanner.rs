use crate::config::{Config, IpRangeConfig};
use crate::types::{CertificateInfo, OcspStatus, ScanResult};
use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnet::IpNet;
use reqwest::Client;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use bcder::{decode::{Constructed, IntoSource, Source}, encode::{self, PrimitiveContent}, Integer, Mode, Oid, OctetString, Tag};
use x509_certificate::{
    certificate::X509Certificate,
    rfc3280::{GeneralName, GeneralNames},
};

#[derive(Clone)]
pub struct Scanner {
    config: Arc<Config>,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

impl Scanner {
    pub fn new(config: Arc<Config>) -> Self {
        let concurrency = config.concurrency() as usize;
        let timeout = Duration::from_secs(config.connect_timeout_secs());
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(concurrency)),
            timeout,
        }
    }

    pub async fn scan_all(&self) -> Vec<ScanResult> {
        let domains = self.collect_all_domains();
        tracing::info!("开始扫描 {} 个域名", domains.len());

        let mut futures = FuturesUnordered::new();
        for domain in domains {
            let scanner = self.clone();
            futures.push(async move {
                let _permit = scanner
                    .semaphore
                    .acquire()
                    .await
                    .expect("Semaphore acquire failed");
                scanner.scan_domain(&domain).await
            });
        }

        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            results.push(result);
        }

        results
    }

    fn collect_all_domains(&self) -> Vec<String> {
        let mut domains = HashSet::new();

        for domain_config in &self.config.domains {
            domains.insert(domain_config.name.clone());
        }

        if let Some(sources) = &self.config.sources {
            if let Some(domain_list) = &sources.domain_list {
                for d in domain_list {
                    domains.insert(d.clone());
                }
            }

            if let Some(ip_ranges) = &sources.ip_ranges {
                for ip_range in ip_ranges {
                    match self.scan_ip_range(ip_range) {
                        Ok(ips) => {
                            for ip in ips {
                                domains.insert(ip.to_string());
                            }
                        }
                        Err(e) => {
                            tracing::warn!("IP段扫描失败 {}: {}", ip_range.cidr, e);
                        }
                    }
                }
            }

            if let Some(pem_dirs) = &sources.pem_directories {
                for dir in pem_dirs {
                    match self.scan_pem_directory(dir) {
                        Ok(pem_domains) => {
                            for d in pem_domains {
                                domains.insert(d);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("PEM目录扫描失败 {}: {}", dir, e);
                        }
                    }
                }
            }
        }

        domains.into_iter().collect()
    }

    fn scan_ip_range(&self, ip_config: &IpRangeConfig) -> Result<Vec<IpAddr>> {
        let net: IpNet = ip_config
            .cidr
            .parse()
            .with_context(|| format!("Invalid CIDR format: {}", ip_config.cidr))?;

        let mut ips = Vec::new();
        let limit = match net {
            IpNet::V4(_) => 256,
            IpNet::V6(_) => 1024,
        };

        for (i, addr) in net.hosts().enumerate() {
            if i >= limit {
                break;
            }
            ips.push(addr);
        }
        Ok(ips)
    }

    fn scan_pem_directory(&self, dir: &str) -> Result<Vec<String>> {
        let path = Path::new(dir);
        if !path.exists() {
            return Err(anyhow!("Directory does not exist: {}", dir));
        }

        let mut domains = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                let ext = file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                if ext == "pem" || ext == "crt" || ext == "cer" {
                    match Self::extract_domain_from_pem(&file_path) {
                        Ok(domain) => domains.push(domain),
                        Err(e) => {
                            tracing::warn!("解析PEM文件失败 {:?}: {}", file_path, e);
                        }
                    }
                }
            }
        }
        Ok(domains)
    }

    fn extract_domain_from_pem(path: &Path) -> Result<String> {
        let content = std::fs::read(path)?;
        let cert = X509Certificate::from_pem(&content)
            .map_err(|e| anyhow!("Failed to parse PEM: {:?}", e))?;
        let subject = cert
            .subject_name()
            .user_friendly_str()
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(subject)
    }

    pub async fn scan_domain(&self, domain: &str) -> ScanResult {
        tracing::debug!("扫描域名: {}", domain);
        let scanned_at = Utc::now();

        let ports = self.get_ports_for_domain(domain);
        let mut last_error = None;

        for port in ports {
            match self.scan_domain_with_port(domain, port).await {
                Ok(info) => {
                    return ScanResult {
                        domain: domain.to_string(),
                        cert: Some(info),
                        error: None,
                        scanned_at,
                    };
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        ScanResult {
            domain: domain.to_string(),
            cert: None,
            error: last_error,
            scanned_at,
        }
    }

    fn get_ports_for_domain(&self, domain: &str) -> Vec<u16> {
        for dc in &self.config.domains {
            if dc.name == domain {
                if let Some(ports) = &dc.ports {
                    return ports.clone();
                }
                break;
            }
        }

        if let Some(sources) = &self.config.sources {
            if let Some(ip_ranges) = &sources.ip_ranges {
                for ip_range in ip_ranges {
                    if let Ok(ip) = domain.parse::<IpAddr>() {
                        if self.is_ip_in_range(ip, ip_range) {
                            if let Some(port) = ip_range.port {
                                return vec![port];
                            }
                        }
                    }
                }
            }
        }

        vec![443]
    }

    fn is_ip_in_range(&self, ip: IpAddr, ip_range: &IpRangeConfig) -> bool {
        let net: IpNet = match ip_range.cidr.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        net.contains(&ip)
    }

    async fn scan_domain_with_port(&self, domain: &str, port: u16) -> Result<CertificateInfo> {
        let addr = format!("{}:{}", domain, port);

        let certs = tokio::time::timeout(self.timeout, async {
            let stream = TcpStream::connect(&addr)
                .await
                .with_context(|| format!("Failed to connect to {}", addr))?;

            let mut root_certs = rustls::RootCertStore::empty();
            let cert_result = rustls_native_certs::load_native_certs();
            if !cert_result.errors.is_empty() {
                tracing::warn!("Errors loading native certs: {:?}", cert_result.errors);
            }
            for cert in cert_result.certs {
                root_certs
                    .add(cert)
                    .map_err(|e| anyhow!("Failed to add root cert: {:?}", e))?;
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_certs)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let server_name = rustls::pki_types::ServerName::try_from(domain)
                .map_err(|e| anyhow!("Invalid domain: {}", e))?
                .to_owned();

            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .context("TLS handshake failed")?;

            let (_, conn) = tls_stream.get_ref();
            let certs = conn
                .peer_certificates()
                .map(|certs| certs.to_vec())
                .unwrap_or_default();

            Ok::<_, anyhow::Error>(certs)
        })
        .await
        .with_context(|| format!("Connection timeout for {}", addr))??;

        if certs.is_empty() {
            return Err(anyhow!("No certificates received from server"));
        }

        let leaf_cert_der = &certs[0];
        let leaf_cert = X509Certificate::from_der(leaf_cert_der.as_ref())
            .map_err(|e| anyhow!("Failed to parse certificate: {:?}", e))?;

        let fingerprint = Self::compute_sha256_fingerprint(leaf_cert_der.as_ref());
        let subject = leaf_cert
            .subject_name()
            .user_friendly_str()
            .map_err(|e| anyhow!("{:?}", e))?;
        let issuer = leaf_cert
            .issuer_name()
            .user_friendly_str()
            .map_err(|e| anyhow!("{:?}", e))?;
        let san_list = Self::extract_san(&leaf_cert);
        let not_before = Utc
            .timestamp_opt(leaf_cert.validity_not_before().timestamp(), 0)
            .single()
            .ok_or_else(|| anyhow!("Invalid not_before timestamp"))?;
        let not_after = Utc
            .timestamp_opt(leaf_cert.validity_not_after().timestamp(), 0)
            .single()
            .ok_or_else(|| anyhow!("Invalid not_after timestamp"))?;

        let chain_complete = Scanner::verify_chain_complete(&certs);
        let ocsp_status = self
            .check_ocsp_status(&leaf_cert, &certs)
            .await
            .unwrap_or(OcspStatus::Unknown);

        Ok(CertificateInfo {
            domain: domain.to_string(),
            subject,
            san_list,
            issuer,
            not_before,
            not_after,
            fingerprint_sha256: fingerprint,
            chain_complete,
            ocsp_status,
            source: format!("{}:{}", domain, port),
        })
    }

    fn compute_sha256_fingerprint(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn extract_san(cert: &X509Certificate) -> Vec<String> {
        let mut sans = Vec::new();
        let oid_san = Oid(&[85, 29, 17]);
        for ext in cert.iter_extensions() {
            if ext.id == oid_san {
                let source = ext.value.clone().into_source();
                if let Ok(general_names) = Constructed::decode(
                    source,
                    Mode::Der,
                    |cons| -> Result<GeneralNames, bcder::decode::DecodeError<<bcder::decode::BytesSource as Source>::Error>> {
                        cons.take_sequence(|cons| {
                            let mut names = Vec::new();
                            while let Some(name) = GeneralName::take_from(cons).ok() {
                                names.push(name);
                            }
                            Ok(names)
                        })
                    }
                ) {
                    for name in general_names {
                        match name {
                            GeneralName::DnsName(dns) => {
                                sans.push(dns.to_string());
                            }
                            GeneralName::IpAddress(ip) => {
                                if let Ok(ip_str) = std::str::from_utf8(ip.to_bytes().as_ref()) {
                                    sans.push(ip_str.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        sans
    }

    fn verify_chain_complete(certs: &[rustls::pki_types::CertificateDer]) -> bool {
        if certs.is_empty() {
            return false;
        }
        if certs.len() == 1 {
            return false;
        }

        let mut parsed_certs = Vec::new();
        for cert_der in certs {
            match X509Certificate::from_der(cert_der.as_ref()) {
                Ok(cert) => parsed_certs.push(cert),
                Err(_) => return false,
            }
        }

        for i in 0..parsed_certs.len() - 1 {
            let subject = &parsed_certs[i];
            let issuer = &parsed_certs[i + 1];

            if subject.tbs_certificate().issuer != issuer.tbs_certificate().subject {
                return false;
            }

            if Self::verify_certificate_signature(subject, issuer).is_err() {
                return false;
            }
        }

        true
    }

    fn verify_certificate_signature(
        subject: &X509Certificate,
        issuer: &X509Certificate,
    ) -> Result<()> {
        use ring::signature::{self, VerificationAlgorithm};

        let tbs_data = subject
            .tbs_certificate()
            .raw_data
            .as_ref()
            .ok_or_else(|| anyhow!("No raw TBS data available"))?;

        let cert_der = subject.encode_der()?;
        let tbs_len = tbs_data.len();
        
        let sig_alg_len = subject.signature_signature_algorithm_oid().as_ref().as_ref().len() + 4;
        let sig_start = tbs_len + sig_alg_len + 2;
        let actual_signature = if sig_start < cert_der.len() {
            &cert_der[sig_start + 2..]
        } else {
            return Err(anyhow!("Invalid certificate structure"));
        };

        let subject_sig_alg = subject.signature_signature_algorithm_oid();
        let oid_bytes: &[u8] = subject_sig_alg.as_ref().as_ref();

        let alg: &dyn VerificationAlgorithm = if oid_bytes == [42, 134, 72, 134, 247, 13, 1, 1, 11] {
            &signature::RSA_PKCS1_2048_8192_SHA256
        } else if oid_bytes == [42, 134, 72, 134, 247, 13, 1, 1, 12] {
            &signature::RSA_PKCS1_2048_8192_SHA384
        } else if oid_bytes == [42, 134, 72, 134, 247, 13, 1, 1, 13] {
            &signature::RSA_PKCS1_2048_8192_SHA512
        } else if oid_bytes == [42, 134, 72, 206, 61, 4, 3, 2] {
            &signature::ECDSA_P256_SHA256_ASN1
        } else if oid_bytes == [42, 134, 72, 206, 61, 4, 3, 3] {
            &signature::ECDSA_P384_SHA384_ASN1
        } else {
            return Err(anyhow!("Unsupported signature algorithm"));
        };

        let public_key = issuer
            .tbs_certificate()
            .subject_public_key_info
            .subject_public_key
            .octet_bytes();

        let peer_public_key = signature::UnparsedPublicKey::new(alg, public_key);
        peer_public_key.verify(tbs_data, actual_signature)
            .map_err(|_| anyhow!("Signature verification failed"))?;

        Ok(())
    }

    fn extract_ocsp_url(cert: &X509Certificate) -> Option<String> {
        let oid_aia = Oid(&[43, 6, 1, 5, 5, 7, 1, 1]);
        for ext in cert.iter_extensions() {
            if ext.id == oid_aia {
                let source = ext.value.clone().into_source();
                if let Ok(url) = Constructed::decode(
                    source,
                    Mode::Der,
                    |cons| -> Result<String, bcder::decode::DecodeError<<bcder::decode::BytesSource as Source>::Error>> {
                        cons.take_sequence(|cons| {
                            while let Ok(Some(access_desc)) = cons.take_opt_sequence(|cons| {
                                let oid = Oid::take_from(cons)?;
                                let oid_bytes: &[u8] = oid.as_ref().as_ref();
                                if oid_bytes == [43, 6, 1, 5, 5, 7, 48, 1] {
                                    let tag = Tag::ctx(6);
                                    let ia5 = cons.take_constructed_if(tag, |cons| {
                                        bcder::string::Ia5String::take_from(cons)
                                    })?;
                                    return Ok(Some(ia5.to_string()));
                                }
                                Ok(None)
                            }) {
                                if let Some(url) = access_desc {
                                    return Ok(url);
                                }
                            }
                            Err(cons.content_err("No OCSP URL found"))
                        })
                    }
                ) {
                    return Some(url);
                }
            }
        }
        None
    }

    async fn check_ocsp_status(
        &self,
        leaf: &X509Certificate,
        certs: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Result<OcspStatus> {
        let ocsp_url = match Self::extract_ocsp_url(leaf) {
            Some(url) => url,
            None => return Ok(OcspStatus::Unknown),
        };

        let issuer_cert = if certs.len() >= 2 {
            match X509Certificate::from_der(certs[1].as_ref()) {
                Ok(cert) => cert,
                Err(_) => return Ok(OcspStatus::Unknown),
            }
        } else {
            return Ok(OcspStatus::Unknown);
        };

        let ocsp_request = match Self::build_ocsp_request(leaf, &issuer_cert) {
            Some(req) => req,
            None => return Ok(OcspStatus::Unknown),
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?;

        let response = client
            .post(&ocsp_url)
            .header("Content-Type", "application/ocsp-request")
            .body(ocsp_request)
            .send()
            .await;

        let response = match response {
            Ok(r) => r,
            Err(_) => return Ok(OcspStatus::Unknown),
        };

        let status = response.status();
        if !status.is_success() {
            return Ok(OcspStatus::Unknown);
        }

        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(_) => return Ok(OcspStatus::Unknown),
        };

        Ok(Self::parse_ocsp_response(&bytes))
    }

    fn build_ocsp_request(leaf: &X509Certificate, issuer: &X509Certificate) -> Option<Vec<u8>> {
        use bcder::encode::Values;
        use sha1::Digest;

        let issuer_name_der = match issuer.tbs_certificate().subject.encode_ref().to_captured(Mode::Der).into_bytes() {
            bytes if !bytes.is_empty() => bytes,
            _ => return None,
        };

        let mut hasher = Sha1::new();
        hasher.update(&issuer_name_der);
        let issuer_name_hash = hasher.finalize();

        let spki_der = issuer.tbs_certificate().subject_public_key_info.subject_public_key.octet_bytes();
        let mut hasher = Sha1::new();
        hasher.update(spki_der);
        let issuer_key_hash = hasher.finalize();

        let serial_number = &leaf.tbs_certificate().serial_number;
        let serial_bytes = serial_number.encode_ref().to_captured(Mode::Der).into_bytes();
        let serial_int = bcder::decode::Constructed::decode(
            serial_bytes,
            Mode::Der,
            |cons| Integer::take_from(cons)
        ).ok()?;

        let request = encode::sequence((
            encode::sequence((
                Oid(&[43, 6, 1, 5, 5, 7, 48, 1, 1]).encode(),
                ().encode(),
            )),
            encode::sequence((
                encode::sequence((
                    OctetString::new(bytes::Bytes::copy_from_slice(issuer_name_hash.as_slice())).encode(),
                    OctetString::new(bytes::Bytes::copy_from_slice(issuer_key_hash.as_slice())).encode(),
                    serial_int.encode(),
                )),
            )),
        ));

        Some(request.to_captured(Mode::Der).into_bytes().to_vec())
    }

    fn parse_ocsp_response(bytes: &[u8]) -> OcspStatus {
        use bcder::decode::Source;

        fn read_all_bytes<S: Source>(prim: &mut bcder::decode::Primitive<S>) -> Result<Vec<u8>, bcder::decode::DecodeError<S::Error>> {
            let mut buf = Vec::new();
            loop {
                match prim.take_u8() {
                    Ok(byte) => buf.push(byte),
                    Err(_) => break,
                }
            }
            Ok(buf)
        }

        let source = bcder::decode::BytesSource::new(bytes::Bytes::copy_from_slice(bytes));
        let result: Result<Option<Option<OcspStatus>>, bcder::decode::DecodeError<<bcder::decode::BytesSource as Source>::Error>> = Constructed::decode(
            source,
            Mode::Der,
            |cons| {
                cons.take_sequence(|cons| {
                    let _response_status = cons.take_primitive_if(Tag::ENUMERATED, |p| p.to_u8())?;
                    let inner = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                        cons.take_sequence(|cons| {
                            let _version = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                                cons.take_u8()
                            })?;
                            let _responder_id = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                                cons.take_primitive_if(Tag::OCTET_STRING, |p| read_all_bytes(p))
                            }).or_else(|_| {
                                cons.take_opt_constructed_if(Tag::CTX_2, |cons| {
                                    cons.take_sequence(|_| Ok(Vec::new()))
                                })
                            })?;
                            let _produced_at = cons.take_primitive_if(Tag::GENERALIZED_TIME, |p| read_all_bytes(p))?;

                            cons.take_sequence(|cons| {
                                loop {
                                    let resp_opt = cons.take_opt_sequence(|cons| {
                                        let _cert_id = cons.take_sequence(|cons| {
                                            let _hash_alg = cons.take_sequence(|_cons| Ok(()))?;
                                            let _name_hash = cons.take_primitive_if(Tag::OCTET_STRING, |p| read_all_bytes(p))?;
                                            let _key_hash = cons.take_primitive_if(Tag::OCTET_STRING, |p| read_all_bytes(p))?;
                                            let _serial = Integer::take_from(cons)?;
                                            Ok(())
                                        })?;

                                        let status_opt = cons.take_opt_constructed_if(Tag::CTX_0, |_cons| {
                                            Ok(())
                                        })?;
                                        if status_opt.is_some() {
                                            return Ok(Some(OcspStatus::Good));
                                        }

                                        let status_opt = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                                            let _revoked_time = cons.take_primitive_if(Tag::GENERALIZED_TIME, |p| read_all_bytes(p))?;
                                            let _reason = cons.take_opt_primitive_if(Tag::ENUMERATED, |p| p.to_u8())?;
                                            Ok(())
                                        })?;
                                        if status_opt.is_some() {
                                            return Ok(Some(OcspStatus::Revoked));
                                        }

                                        let _this_update = cons.take_primitive_if(Tag::GENERALIZED_TIME, |p| read_all_bytes(p))?;
                                        let _next_update = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                                            cons.take_primitive_if(Tag::GENERALIZED_TIME, |p| read_all_bytes(p))
                                        })?;

                                        Ok(Some(OcspStatus::Unknown))
                                    })?;

                                    if let Some(status) = resp_opt {
                                        return Ok(status);
                                    }
                                }
                            })
                        })
                    })?;
                    Ok(inner)
                })
            }
        );

        result.unwrap_or(None).flatten().unwrap_or(OcspStatus::Unknown)
    }

    pub async fn scan_pem_file(&self, domain: &str, pem_path: &Path) -> Result<ScanResult> {
        let scanned_at = Utc::now();
        match Self::load_cert_from_pem(pem_path) {
            Ok(cert) => {
                let info = CertificateInfo {
                    domain: domain.to_string(),
                    subject: cert.subject.clone(),
                    san_list: cert.san_list,
                    issuer: cert.issuer,
                    not_before: cert.not_before,
                    not_after: cert.not_after,
                    fingerprint_sha256: cert.fingerprint_sha256,
                    chain_complete: cert.chain_complete,
                    ocsp_status: OcspStatus::Unknown,
                    source: pem_path.display().to_string(),
                };
                Ok(ScanResult {
                    domain: domain.to_string(),
                    cert: Some(info),
                    error: None,
                    scanned_at,
                })
            }
            Err(e) => Ok(ScanResult {
                domain: domain.to_string(),
                cert: None,
                error: Some(e.to_string()),
                scanned_at,
            }),
        }
    }

    fn load_cert_from_pem(path: &Path) -> Result<CertificateInfo> {
        let content = std::fs::read(path)?;
        let cert = X509Certificate::from_pem(&content)
            .map_err(|e| anyhow!("Failed to parse PEM: {:?}", e))?;
        let der_bytes = cert.encode_der()
            .map_err(|e| anyhow!("Failed to encode DER: {}", e))?;
        let fingerprint =
            Self::compute_sha256_fingerprint(&der_bytes);
        let subject = cert
            .subject_name()
            .user_friendly_str()
            .map_err(|e| anyhow!("{:?}", e))?;
        let issuer = cert
            .issuer_name()
            .user_friendly_str()
            .map_err(|e| anyhow!("{:?}", e))?;
        let san_list = Self::extract_san(&cert);
        let not_before = Utc
            .timestamp_opt(cert.validity_not_before().timestamp(), 0)
            .single()
            .ok_or_else(|| anyhow!("Invalid not_before timestamp"))?;
        let not_after = Utc
            .timestamp_opt(cert.validity_not_after().timestamp(), 0)
            .single()
            .ok_or_else(|| anyhow!("Invalid not_after timestamp"))?;

        Ok(CertificateInfo {
            domain: subject.clone(),
            subject,
            san_list,
            issuer,
            not_before,
            not_after,
            fingerprint_sha256: fingerprint,
            chain_complete: true,
            ocsp_status: OcspStatus::Unknown,
            source: path.display().to_string(),
        })
    }
}
