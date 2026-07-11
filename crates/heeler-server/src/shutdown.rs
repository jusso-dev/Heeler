//! Graceful shutdown signalling.
//!
//! A `watch` channel broadcasts the shutdown flag to every loop; SIGINT and
//! SIGTERM both trigger it on Unix (Ctrl-C elsewhere).

use tokio::sync::watch;

/// Creates the shutdown flag channel (initially `false`).
#[must_use]
pub fn channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// Waits for SIGINT or SIGTERM and returns the signal name. Never returns
/// early; if signal registration fails the error is reported and the future
/// waits on the remaining signal(s).
#[cfg(unix)]
pub async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(stream) => Some(stream),
        Err(error) => {
            tracing::error!(%error, "cannot listen for SIGTERM");
            None
        }
    };
    let sigterm_recv = async {
        match sigterm.as_mut() {
            Some(stream) => {
                stream.recv().await;
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = sigterm_recv => "SIGTERM",
    }
}

/// Waits for Ctrl-C on non-Unix platforms.
#[cfg(not(unix))]
pub async fn wait_for_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}
