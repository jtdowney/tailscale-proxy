mod http;
mod observability;
mod tls;

use std::{net::SocketAddr, sync::Arc};

use argh::FromArgs;
use futures::{future, stream, StreamExt};
use hyper::{server::conn::Http, service::service_fn};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{debug, info, warn};

#[derive(FromArgs)]
/// Proxy requests from Tailscale clients to an upstream with a TLS certificate provided by the Tailscale daemon.
pub struct Args {
    /// port to listen on for connections (defaults to 443)
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// upstream to proxy connections to
    #[argh(option, short = 'u')]
    upstream: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    observability::start();

    let config: Arc<Args> = Arc::new(argh::from_env());

    let localapi = tailscale_localapi::UnixClient::default();
    let status = localapi.status().await?;

    let tls_config = tls::create_config(&localapi, &status.cert_domains).await?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let listen_addresses = status
        .tailscale_ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::from((ip, config.port)))
        .collect::<Vec<SocketAddr>>();

    info!("listening on {listen_addresses:?}");
    serve(&localapi, tls_acceptor, config, &listen_addresses).await?;

    Ok(())
}

async fn serve(
    localapi: &tailscale_localapi::UnixClient,
    tls_acceptor: TlsAcceptor,
    config: Arc<Args>,
    listen_addresses: &[SocketAddr],
) -> eyre::Result<()> {
    let listeners = listen_addresses.iter().map(TcpListener::bind);
    let streams = future::join_all(listeners)
        .await
        .into_iter()
        .map(|listener| listener.map(TcpListenerStream::new))
        .collect::<Result<Vec<_>, _>>()?;

    stream::select_all(streams)
        .filter_map(|stream| async {
            match stream {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!("error accepting connection: {e}");
                    None
                }
            }
        })
        .filter_map(|stream| async {
            let remote_addr = match stream.peer_addr() {
                Ok(v) => v,
                Err(e) => {
                    warn!("unable to retreive peer address: {e}");
                    return None;
                }
            };

            let whois = match localapi.whois(remote_addr).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(%remote_addr, "unable to retreive whois information: {e}");
                    return None;
                }
            };

            let remote_ip = remote_addr.ip();
            debug!(%remote_ip, "accepted connection");

            match tls_acceptor.accept(stream).await {
                Ok(s) => Some((remote_ip, whois, s)),
                Err(e) => {
                    warn!(%remote_ip, "error during TLS handshake: {e}");
                    None
                }
            }
        })
        .for_each(|(remote_ip, whois, stream)| {
            let (_, tls_conn) = stream.get_ref();
            debug!(%remote_ip, "negotiated TLS with {:?}", tls_conn.negotiated_cipher_suite().unwrap());

            let config = config.clone();
            let whois = Arc::new(whois);
            async move {
                let serve_connection = Http::new().serve_connection(
                    stream,
                    service_fn(move |mut request| {
                        request.extensions_mut().insert(config.clone());
                        request.extensions_mut().insert(whois.clone());
                        request.extensions_mut().insert(remote_ip);

                        http::handle_request(request)
                    }),
                );

                tokio::spawn(async move {
                    if let Err(e) = serve_connection.await {
                        warn!(%remote_ip, "error serving HTTP connection: {e}");
                    }
                });
            }
        })
        .await;

    Ok(())
}
