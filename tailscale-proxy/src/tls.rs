use std::{collections::HashSet, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use tracing::{error, info};

pub async fn create_config(
    localapi: &tailscale_localapi::UnixClient,
    domains: &[String],
) -> eyre::Result<Arc<ServerConfig>> {
    let cert_resolver = Arc::new(TailscaleCertificateResolver {
        client: localapi.clone(),
        domains: domains.iter().cloned().collect(),
    });

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    config.ignore_client_order = true;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

struct TailscaleCertificateResolver {
    client: tailscale_localapi::UnixClient,
    domains: HashSet<String>,
}

impl ResolvesServerCert for TailscaleCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let domain = match client_hello.server_name() {
            Some(sni) if self.domains.contains(sni) => sni.to_string(),
            Some(_) => return None,
            None => self.domains.iter().next().unwrap().clone(),
        };

        let fut = self.client.certificate_pair(&domain);
        match futures::executor::block_on(fut) {
            Ok((tailscale_localapi::PrivateKey(key_data), certs)) => {
                let key = rustls::PrivateKey(key_data);
                let certs = certs
                    .into_iter()
                    .map(|tailscale_localapi::Certificate(data)| rustls::Certificate(data))
                    .collect();

                let signing_key = match rustls::sign::any_supported_type(&key) {
                    Ok(k) => k,
                    Err(e) => {
                        error!("error resolving certificate for {domain}: {e}");
                        return None;
                    }
                };

                info!("got TLS certificate for {domain}");

                Some(Arc::new(CertifiedKey::new(certs, signing_key)))
            }
            Err(e) => {
                error!("error resolving certificate for {domain}: {e}");
                None
            }
        }
    }
}
