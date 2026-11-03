use eyre::eyre;
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::prelude::*;

/// Initializes logging.
pub(crate) fn init(verbose: u8) -> eyre::Result<()> {
    let level = match verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        3 => Level::TRACE,
        _ => return Err(eyre!("Unsupported logging level")),
    };

    let fmt = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .without_time()
        .with_filter(LevelFilter::from_level(level));

    tracing_subscriber::registry().with(fmt).try_init()?;

    Ok(())
}
