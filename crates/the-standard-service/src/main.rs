use std::net::SocketAddr;

use the_standard_service::{CoreServiceConfig, build_app};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("the_standard_service=info,tower_http=info")),
        )
        .init();

    let config = CoreServiceConfig::load()?;
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--check-config")
    {
        println!(
            "the-standard-service configuration valid: require_auth={} allow_private_targets={} target_dns_timeout_seconds={} max_response_bytes={} allowed_origins={} per_ip_detect_requests_per_minute={} rate_limit_max_entries={}",
            config.require_auth,
            config.allow_private_targets,
            config.target_dns_timeout.as_secs(),
            config.transport_config.max_response_bytes,
            config.allowed_origins.len(),
            config.per_ip_detect_requests_per_minute,
            config.rate_limit_max_entries,
        );
        return Ok(());
    }
    let address = config.address();
    let shutdown_grace_period = config.shutdown_grace_period;
    let listener = TcpListener::bind(address).await?;
    info!(%address, "TheStandard service listening");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // The per-IP detection limit is keyed on this peer address, so the serve
    // path must supply it; forwarded headers are never trusted for that key.
    let server = axum::serve(
        listener,
        build_app(config).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    let mut server = Box::pin(server.into_future());
    tokio::select! {
        result = &mut server => {
            result?;
        }
        _ = shutdown_signal() => {
            tracing::info!(grace_seconds = shutdown_grace_period.as_secs(), "shutdown signal received");
            let _ = shutdown_tx.send(());
            match timeout(shutdown_grace_period, &mut server).await {
                Ok(result) => result?,
                Err(_) => {
                    tracing::warn!(grace_seconds = shutdown_grace_period.as_secs(), "shutdown grace period elapsed");
                }
            }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Option<()>>();

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "failed to install Ctrl-C handler");
            }
        }
        _ = terminate => {}
    }
}
