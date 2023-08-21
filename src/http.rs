use std::{net::IpAddr, sync::Arc, time::Duration};

use eyre::ContextCompat;
use hyper::{
    header::HeaderName, header::HeaderValue, Body, HeaderMap, Request, Response, StatusCode,
};
use lazy_static::lazy_static;
use tailscale_localapi::Whois;
use tokio::{net::TcpStream, time::error::Elapsed};
use tracing::{error, warn};

use crate::Args;

const TIMEOUT: Duration = Duration::from_secs(60);

lazy_static! {
    static ref HOP_HEADERS: [HeaderName; 8] = [
        HeaderName::from_static("connection"),
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailers"),
        HeaderName::from_static("transfer-encoding"),
        HeaderName::from_static("upgrade"),
    ];
    static ref X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
    static ref X_WEBAUTH_USER: HeaderName = HeaderName::from_static("x-webauth-user");
}

pub fn is_hop_header(name: &str) -> bool {
    HOP_HEADERS.iter().any(|h| h == name)
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
pub fn remove_hop_headers(headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    let mut result = HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k.as_str()) {
            result.insert(k.clone(), v.clone());
        }
    }

    result
}

pub(crate) fn create_proxied_request<B>(mut request: Request<B>) -> eyre::Result<Request<B>> {
    let remote_ip = *request
        .extensions()
        .get::<IpAddr>()
        .context("missing remote IP")?;
    let whois = request
        .extensions()
        .get::<Arc<Whois>>()
        .context("missing whois")?
        .clone();
    *request.headers_mut() = remove_hop_headers(request.headers());

    match request.headers_mut().entry(&*X_FORWARDED_FOR) {
        hyper::header::Entry::Vacant(entry) => {
            entry.insert(remote_ip.to_string().parse()?);
        }
        hyper::header::Entry::Occupied(mut entry) => {
            let addr = format!("{}, {}", entry.get().to_str()?, remote_ip);
            entry.insert(addr.parse()?);
        }
    }

    request
        .headers_mut()
        .entry(&*X_WEBAUTH_USER)
        .or_insert(whois.user_profile.login_name.parse()?);

    Ok(request)
}

pub async fn proxy_request(request: Request<Body>) -> eyre::Result<Response<Body>> {
    let config = request
        .extensions()
        .get::<Arc<Args>>()
        .context("missing config")?
        .clone();
    let request = create_proxied_request(request)?;
    let stream = TcpStream::connect(&config.upstream).await?;

    let (mut request_sender, connection) = hyper::client::conn::Builder::new()
        .handshake::<TcpStream, Body>(stream)
        .await?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            warn!("error in connection: {e}");
        }
    });

    let request_future = request_sender.send_request(request);
    let response = tokio::time::timeout(TIMEOUT, request_future).await??;

    Ok(response)
}

#[tracing::instrument(skip(req))]
pub async fn handle_request(req: Request<Body>) -> eyre::Result<Response<Body>> {
    match proxy_request(req).await {
        Ok(resp) => Ok(resp),
        Err(e) if e.is::<Elapsed>() => {
            error!("error handling connection: {e}");
            let mut resp = Response::new(Body::from("Gateway Timeout"));
            *resp.status_mut() = StatusCode::GATEWAY_TIMEOUT;
            Ok(resp)
        }
        Err(e) => {
            error!("error handling connection: {e}");
            let mut resp = Response::new(Body::from("Bad Gateway"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}
