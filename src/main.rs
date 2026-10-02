use std::{
    fs,
    io::{self, Read as _, Write as _},
    time::Duration,
};

use clap::{CommandFactory as _, Parser};
use der::{Decode as _, Encode as _};
use eyre::{WrapErr as _, eyre};
use pem_rfc7468::{LineEnding, PemLabel as _};
use x509_cert::Certificate;

mod ext;
mod fetch;
mod info;
mod logging;
mod tui;
mod util;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        const LINE_ENDING: LineEnding = LineEnding::CRLF;
    } else {
        const LINE_ENDING: LineEnding = LineEnding::LF;
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Download certificate chain from a server that starts TLS on connection.
    #[clap(long, conflicts_with = "file")]
    host: Option<String>,

    /// Port to use with --host.
    #[clap(long, conflicts_with = "file", default_value_t = 443)]
    port: u16,

    /// Overall time limit for remote fetching (for example, 500ms or 2m).
    #[arg(long, value_name = "DURATION", default_value = "10s", value_parser = parse_timeout)]
    timeout: Duration,

    /// When provided, writes downloaded chain to file in PEM format.
    #[clap(long, conflicts_with = "file")]
    dump: Option<camino::Utf8PathBuf>,

    /// Inspect a local certificate chain in PEM format.
    #[clap(long, conflicts_with = "host")]
    file: Option<camino::Utf8PathBuf>,

    /// View certificate chain using interactive (TUI) mode.
    #[arg(short, long)]
    interactive: bool,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn parse_timeout(value: &str) -> Result<Duration, String> {
    let timeout = humantime::parse_duration(value).map_err(|err| err.to_string())?;

    if timeout.is_zero() {
        return Err("Timeout must be greater than zero".to_owned());
    }

    Ok(timeout)
}

// let anchor = &TLS_SERVER_ROOTS.0[3]; // seems to have wrong modulus ?!?

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    logging::init(args.verbose)?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let certs = if let Some(host) = &args.host {
        tracing::info!(%host, "fetching certificate chain from remote host");
        fetch::cert_chain(host, args.port, args.timeout)?
    } else if let Some(path) = &args.file {
        let mut input = if path == "-" {
            if args.interactive {
                let mut err = clap::Error::new(clap::error::ErrorKind::ArgumentConflict)
                    .with_cmd(&Args::command());

                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String("--interactive".to_owned()),
                );
                err.insert(
                    clap::error::ContextKind::PriorArg,
                    clap::error::ContextValue::String("--file -".to_owned()),
                );

                err.exit();
            }

            tracing::info!("reading certificate chain from stdin");

            let mut buf = String::new();
            let n_bytes = io::stdin().read_to_string(&mut buf).unwrap();
            tracing::trace!("read {n_bytes} from stdin");
            Box::new(io::Cursor::new(buf)) as Box<dyn io::BufRead>
        } else {
            tracing::info!(%path, "reading certificate chain from file");

            let file =
                fs::File::open(path).wrap_err_with(|| format!("Could not open file: {path}"))?;
            Box::new(io::BufReader::new(file)) as Box<dyn io::BufRead>
        };

        tracing::debug!("reading certificate chain PEM files");
        let certs = rustls_pemfile::certs(&mut input).collect::<Result<Vec<_>, _>>()?;

        tracing::debug!("parsing certificate chain");
        certs
            .into_iter()
            .map(|der| x509_cert::Certificate::from_der(&der))
            .collect::<Result<_, _>>()?
    } else {
        return Err(eyre!("Use --host or --file"));
    };

    let n_certs = certs.len();
    tracing::info!("chain contains {n_certs} certificates");

    if n_certs == 0 {
        return Err(eyre!("Chain contained 0 certificates"));
    }

    if args.interactive {
        let mut tui = tui::init()?;
        let mut app = tui::App::new(&certs);
        app.run(&mut tui)?;
        tui::restore()?;
    } else {
        let mut stdout = io::stdout();

        for cert in &certs {
            writeln!(&mut stdout, "Certificate")?;
            writeln!(&mut stdout, "===========")?;

            info::write_cert_info(cert, &mut stdout, false)?;

            writeln!(&mut stdout)?;
            writeln!(&mut stdout)?;
        }
    }

    if let Some(dump_path) = args.dump {
        tracing::info!(%dump_path, "writing chain");

        let mut der_buf = Vec::with_capacity(1_024);

        let pem_cap = certs.len() * 2_048; // ~2Kb per cert

        let pem_chain = certs.into_iter().try_fold(
            String::with_capacity(pem_cap),
            |buf, cert| -> eyre::Result<_> {
                der_buf.clear();

                cert.encode_to_vec(&mut der_buf)
                    .wrap_err("Failed to convert certificate back to DER encoding")?;

                let pem = pem_rfc7468::encode_string(Certificate::PEM_LABEL, LINE_ENDING, &der_buf)
                    .wrap_err("Failed to encode DER certificate to PEM format")?;

                Ok(buf + &pem)
            },
        )?;

        fs::write(&dump_path, pem_chain)
            .wrap_err_with(|| format!("Failed to dump downloaded cert chain to {dump_path}"))?;
    }

    Ok(())
}
