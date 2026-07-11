//! The `heeler` binary: command-line interface and process orchestration.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, unused_qualifications)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use heeler_core::clock::{ClockSource, SystemClockSource};
use heeler_core::timestamp::NtpInstant;
use heeler_server::config::{Config, ValidatedConfig, DEFAULT_CONFIG_TOML};
use heeler_server::server::{bind_sockets, run_server, ServerState};
use heeler_server::{bench, client, inspect, metrics, shutdown};

/// Default configuration path consulted when `--config` is not given.
const SYSTEM_CONFIG_PATH: &str = "/etc/heeler/heeler.toml";

#[derive(Parser)]
#[command(
    name = "heeler",
    version,
    about = "A lightweight, secure NTP server",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the NTP server.
    Serve(ServeArgs),
    /// Parse and validate configuration, then exit.
    CheckConfig {
        /// Configuration file to check.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print the documented default configuration.
    PrintDefaultConfig,
    /// Decode a hex-encoded NTP packet ("-" reads stdin).
    InspectPacket {
        /// Hex bytes, e.g. "230006ec00..." (whitespace tolerated).
        hex: String,
    },
    /// Send one diagnostic NTP query and report delay and offset.
    Query(QueryArgs),
    /// Print version information.
    Version,
    /// Run software micro-benchmarks (CPU cost, not time accuracy).
    Bench,
}

#[derive(Args)]
struct ServeArgs {
    /// Configuration file (default: /etc/heeler/heeler.toml when present).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override bind addresses (repeatable).
    #[arg(long)]
    bind: Vec<SocketAddr>,
    /// Override log level (error|warn|info|debug|trace).
    #[arg(long)]
    log_level: Option<String>,
    /// Override log format (pretty|compact|json).
    #[arg(long)]
    log_format: Option<String>,
    /// Override advertised stratum (1-15).
    #[arg(long)]
    stratum: Option<u8>,
    /// Enable the Prometheus metrics endpoint.
    #[arg(long)]
    metrics: bool,
    /// Override the metrics bind address (implies --metrics).
    #[arg(long)]
    metrics_bind: Option<SocketAddr>,
    /// Acknowledge binding to a public address under strict_public_bind.
    #[arg(long)]
    public_bind_acknowledged: bool,
}

#[derive(Args)]
struct QueryArgs {
    /// Server to query: host, host:port, IP, or [v6]:port (port 123 default).
    server: String,
    /// NTP version to send.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(3..=4))]
    ntp_version: u8,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 5.0)]
    timeout: f64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve(args) => serve(args),
        Command::CheckConfig { config } => check_config(config.as_deref()),
        Command::PrintDefaultConfig => {
            print!("{DEFAULT_CONFIG_TOML}");
            Ok(())
        }
        Command::InspectPacket { hex } => inspect_packet(&hex),
        Command::Query(args) => query(&args),
        Command::Version => {
            println!("heeler {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Bench => {
            println!("{}", bench::run());
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Logging may not be initialised yet; stderr is always right.
            eprintln!("heeler: error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Loads configuration with full precedence: defaults < file < env < CLI.
fn load_config(path: Option<&Path>, args: Option<&ServeArgs>) -> anyhow::Result<Config> {
    let mut config = match path {
        Some(path) => Config::from_file(path)?,
        None => {
            let system_path = Path::new(SYSTEM_CONFIG_PATH);
            if system_path.exists() {
                Config::from_file(system_path)?
            } else {
                Config::default()
            }
        }
    };
    config.apply_env_overrides()?;
    if let Some(args) = args {
        if !args.bind.is_empty() {
            config.server.bind = args.bind.clone();
        }
        if let Some(level) = &args.log_level {
            config.logging.level = level.clone();
        }
        if let Some(format) = &args.log_format {
            config.logging.format = format.clone();
        }
        if let Some(stratum) = args.stratum {
            config.protocol.stratum = stratum;
        }
        if args.metrics || args.metrics_bind.is_some() {
            config.metrics.enabled = true;
        }
        if let Some(bind) = args.metrics_bind {
            config.metrics.bind = bind;
        }
        if args.public_bind_acknowledged {
            config.server.public_bind_acknowledged = true;
        }
    }
    Ok(config)
}

fn check_config(path: Option<&Path>) -> anyhow::Result<()> {
    let config = load_config(path, None)?;
    let validated = config.validate()?;
    println!("configuration OK");
    println!(
        "  bind: {}",
        validated
            .config
            .server
            .bind
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  stratum {} refid {} versions {:?}",
        validated.identity.stratum,
        validated.identity.reference_id,
        validated.config.protocol.versions
    );
    let public = validated.config.public_bind_addresses();
    if !public.is_empty() {
        println!(
            "  warning: public bind addresses configured: {}",
            public
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn inspect_packet(hex: &str) -> anyhow::Result<()> {
    let input = if hex == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading stdin")?
    } else {
        hex.to_owned()
    };
    let pivot = NtpInstant::from_system_time(SystemTime::now());
    let report = inspect::inspect(&input, pivot)?;
    println!("{report}");
    Ok(())
}

fn query(args: &QueryArgs) -> anyhow::Result<()> {
    let options = client::QueryOptions {
        server: args.server.clone(),
        version: args.ntp_version,
        timeout: Duration::from_secs_f64(args.timeout.clamp(0.05, 300.0)),
    };
    let report = client::query(&options)?;
    println!("{}", client::format_report(&report));
    Ok(())
}

fn init_logging(config: &Config) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(&config.logging.level)
        .with_context(|| format!("invalid logging.level {:?}", config.logging.level))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match config.logging.format.as_str() {
        "json" => builder.json().init(),
        "compact" => builder.compact().init(),
        _ => builder.init(),
    }
    Ok(())
}

fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let config = load_config(args.config.as_deref(), Some(&args))?;
    let validated = config.validate()?;
    init_logging(&validated.config)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        stratum = %validated.identity.stratum,
        reference_id = %validated.identity.reference_id,
        versions = ?validated.config.protocol.versions,
        rate_limit = validated.config.rate_limit.enabled,
        metrics = validated.config.metrics.enabled,
        "starting heeler"
    );

    // Public-bind policy: loud warning, and under strict mode an explicit
    // acknowledgement is required to start at all.
    let public = validated.config.public_bind_addresses();
    if !public.is_empty() {
        let addresses = public
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if validated.config.server.strict_public_bind
            && !validated.config.server.public_bind_acknowledged
        {
            anyhow::bail!(
                "refusing to bind public address(es) {addresses}: set \
                 server.public_bind_acknowledged = true (or pass \
                 --public-bind-acknowledged) after restricting [access], or \
                 disable server.strict_public_bind"
            );
        }
        tracing::warn!(
            %addresses,
            "binding PUBLIC addresses; ensure the [access] allow list and \
             your firewall restrict clients to intended networks"
        );
    }

    // Bind sockets while still privileged, then drop privileges while the
    // process is single-threaded, then start the runtime.
    let sockets = bind_sockets(&validated.config.server).context(
        "binding UDP sockets (port 123 needs \
             CAP_NET_BIND_SERVICE, root, or a high port)",
    )?;

    #[cfg(unix)]
    if validated.config.security.drop_privileges {
        use heeler_server::privilege::{drop_privileges, DropOutcome};
        let chroot = if validated.config.security.chroot_dir.is_empty() {
            None
        } else {
            Some(Path::new(&validated.config.security.chroot_dir))
        };
        match drop_privileges(
            &validated.config.security.user,
            &validated.config.security.group,
            chroot,
        )? {
            DropOutcome::NotRoot => {
                tracing::debug!("not running as root; no privileges to drop");
            }
            DropOutcome::Dropped { uid, gid } => {
                tracing::info!(uid, gid, "dropped root privileges");
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building async runtime")?;
    runtime.block_on(run(validated, sockets))
}

async fn run(validated: ValidatedConfig, sockets: Vec<std::net::UdpSocket>) -> anyhow::Result<()> {
    let system_clock = Arc::new(
        SystemClockSource::new(
            validated.jump_policy,
            Duration::from_millis(
                u64::try_from(validated.config.protocol.root_dispersion_ms).unwrap_or(0),
            ),
        )
        .map_err(|e| anyhow::anyhow!("cannot read the system clock: {e}"))?,
    );
    tracing::info!(
        precision = system_clock.estimated_precision().exponent(),
        "system clock accepted as time source"
    );
    let state = Arc::new(ServerState::new(
        &validated,
        system_clock.clone(),
        Some(system_clock),
    ));

    let (shutdown_tx, shutdown_rx) = shutdown::channel();

    // Optional metrics endpoint.
    if validated.config.metrics.enabled {
        let listener = tokio::net::TcpListener::bind(validated.config.metrics.bind)
            .await
            .with_context(|| {
                format!("binding metrics listener {}", validated.config.metrics.bind)
            })?;
        tracing::info!(bind = %validated.config.metrics.bind, "metrics endpoint enabled");
        tokio::spawn(metrics::serve_metrics(
            listener,
            state.metrics.clone(),
            shutdown_rx.clone(),
        ));
    }

    // Signal handler flips the shutdown flag.
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let signal = shutdown::wait_for_signal().await;
        tracing::info!(signal, "shutting down");
        let _ = signal_tx.send(true);
    });

    let metrics = state.metrics.clone();
    run_server(state, sockets, shutdown_rx).await?;

    use std::sync::atomic::Ordering;
    tracing::info!(
        requests = metrics.requests_total.load(Ordering::Relaxed),
        responses = metrics.responses_total.load(Ordering::Relaxed),
        dropped = metrics.packets_dropped_total.load(Ordering::Relaxed),
        rate_limited = metrics.rate_limited_total.load(Ordering::Relaxed),
        "stopped"
    );
    Ok(())
}
