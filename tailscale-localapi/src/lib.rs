use std::{io, net::SocketAddr, path::PathBuf};

use http::{Request, Response, Uri};
use hyper::{body::Buf, Body};
use tokio::net::UnixStream;
use tracing::error;
pub use types::*;

mod types;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("connection failed")]
    IoError(#[from] io::Error),
    #[error("request failed")]
    HyperError(#[from] hyper::Error),
    #[error("http error")]
    HttpError(#[from] hyper::http::Error),
    #[error("unprocessible entity")]
    UnprocessableEntity,
    #[error("unable to parse json")]
    ParsingError(#[from] serde_json::Error),
    #[error("unable to parse certificate or key")]
    UnknownCertificateOrKey,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct UnixClient {
    socket_path: PathBuf,
}

impl Default for UnixClient {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/tailscale/tailscaled.sock".into(),
        }
    }
}

impl UnixClient {
    async fn get_request<U: AsRef<str>>(&self, uri: U) -> Result<Response<Body>>
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<http::Error>,
    {
        let request = Request::builder()
            .method("GET")
            .header("Host", "local-tailscaled.sock")
            .uri(uri)
            .body(Body::empty())?;

        let response = self.request(request).await?;
        Ok(response)
    }

    async fn request(&self, request: Request<Body>) -> Result<Response<Body>> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (mut request_sender, connection) = hyper::client::conn::handshake(stream).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("error in connection: {}", e);
            }
        });

        let response = request_sender.send_request(request).await?;
        if response.status() == 200 {
            Ok(response)
        } else {
            Err(Error::UnprocessableEntity)
        }
    }

    pub async fn certificate_pair(&self, domain: &str) -> Result<(PrivateKey, Vec<Certificate>)> {
        let response = self
            .get_request(format!("/localapi/v0/cert/{domain}?type=pair"))
            .await?;
        let body = hyper::body::aggregate(response.into_body()).await?;
        let items = rustls_pemfile::read_all(&mut body.reader())?;
        let (certificates, mut private_keys) = items
            .into_iter()
            .map(|item| match item {
                rustls_pemfile::Item::ECKey(data)
                | rustls_pemfile::Item::PKCS8Key(data)
                | rustls_pemfile::Item::RSAKey(data) => Ok((false, data)),
                rustls_pemfile::Item::X509Certificate(data) => Ok((true, data)),
                _ => Err(Error::UnknownCertificateOrKey),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .partition::<Vec<(bool, Vec<u8>)>, _>(|&(cert, _)| cert);

        let certificates = certificates
            .into_iter()
            .map(|(_, data)| Certificate(data))
            .collect();
        let (_, private_key_data) = private_keys.pop().ok_or(Error::UnknownCertificateOrKey)?;
        let private_key = PrivateKey(private_key_data);

        Ok((private_key, certificates))
    }

    pub async fn status(&self) -> Result<Status> {
        let response = self.get_request("/localapi/v0/status").await?;
        let body = hyper::body::aggregate(response.into_body()).await?;
        let status = serde_json::de::from_reader(body.reader())?;

        Ok(status)
    }

    pub async fn whois(&self, address: SocketAddr) -> Result<Whois> {
        let response = self
            .get_request(format!("/localapi/v0/whois?addr={address}"))
            .await?;
        let body = hyper::body::aggregate(response.into_body()).await?;
        let whois = serde_json::de::from_reader(body.reader())?;

        Ok(whois)
    }
}
