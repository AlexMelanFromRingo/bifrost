// Minimal HTTP/1.1 Prometheus endpoint for bifrost-socks5d.
//
// Modelled on norn-rs's metrics.rs: one connection at a time,
// hand-rolled response. We don't parse the request beyond draining
// a typical GET header; any GET path returns the same exposition
// body. POST / other methods get 405.
//
// Bound to a configurable addr; default empty = disabled (consistent
// with norn-rs's metrics_addr convention). Loopback strongly
// recommended — pub_keys leak in label values.

use anyhow::{Context, Result};
use bifrost_core::{metrics::render_pool, scoring::ScoredExitPool};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn listen(addr: &str, pool: Arc<ScoredExitPool>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics HTTP on {addr}"))?;
    info!("bifrost metrics endpoint on http://{}/metrics", addr);

    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                warn!("metrics accept: {e}");
                continue;
            }
        };
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match sock.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let method_ok = n >= 3 && &buf[..3] == b"GET";
            let response = if method_ok {
                let body = render_pool(&pool);
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {len}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    len = body.len(),
                )
            } else {
                let body = "method not allowed\n";
                format!(
                    "HTTP/1.1 405 Method Not Allowed\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {len}\r\n\
                     Allow: GET\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    len = body.len(),
                )
            };
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
