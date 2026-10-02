use std::{
    fs,
    io::{self, Read as _, Write as _},
    process::ExitCode,
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
mod report;
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
#[command(group(clap::ArgGroup::new("input").required(true).args(["host", "file"])))]
struct Args {
    /// Download certificate chain from remote host.
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
    #[arg(short, long, conflicts_with_all = ["check"])]
    interactive: bool,

    /// Check all certificate validity dates. Exit 0=OK, 1=warning, 2=critical, 3=unknown.
    #[arg(long)]
    check: bool,

    /// Warn if a certificate expires within this duration (for example, 30d).
    #[arg(long, requires = "check", value_name = "DURATION", value_parser = humantime::parse_duration)]
    warn_within: Option<Duration>,

    /// Report critical if a certificate expires within this duration (for example, 7d).
    #[arg(long, requires = "check", value_name = "DURATION", value_parser = humantime::parse_duration)]
    critical_within: Option<Duration>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Args {
    fn validate(&self) -> Result<(), clap::Error> {
        if self.interactive && self.file.as_deref() == Some(camino::Utf8Path::new("-")) {
            return Err(Args::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--interactive cannot be used with --file -",
            ));
        }

        if let (Some(warning), Some(critical)) = (self.warn_within, self.critical_within)
            && critical > warning
        {
            return Err(Args::command().error(
                clap::error::ErrorKind::ValueValidation,
                "--critical-within must not exceed --warn-within",
            ));
        }

        Ok(())
    }
}

fn parse_timeout(value: &str) -> Result<Duration, String> {
    let timeout = humantime::parse_duration(value).map_err(|err| err.to_string())?;

    if timeout.is_zero() {
        return Err("Timeout must be greater than zero".to_owned());
    }

    Ok(timeout)
}

fn main() -> ExitCode {
    if let Err(err) = color_eyre::install() {
        eprintln!("{err:?}");
        return ExitCode::from(3);
    }

    let args = match Args::try_parse().and_then(|args| {
        args.validate()?;
        Ok(args)
    }) {
        Ok(args) => args,
        Err(err) => {
            let code = if err.use_stderr() { 3 } else { 0 };
            let _ = err.print();
            return ExitCode::from(code);
        }
    };

    match run(&args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:?}");

            ExitCode::from(if args.check { 3 } else { 1 })
        }
    }
}

fn run(args: &Args) -> eyre::Result<ExitCode> {
    logging::init(args.verbose)?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Failed to install TLS crypto provider"))?;

    let certs = if let Some(host) = &args.host {
        tracing::info!(%host, "fetching certificate chain from remote host");
        fetch::cert_chain(host, args.port, args.timeout)?
    } else if let Some(path) = &args.file {
        let mut input = if path == "-" {
            tracing::info!("reading certificate chain from stdin");

            let mut buf = String::new();
            let n_bytes = io::stdin()
                .read_to_string(&mut buf)
                .wrap_err("Failed to read certificate chain from stdin")?;
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

    let report = report::Report::new(&certs, args.warn_within, args.critical_within);

    if args.interactive {
        let mut tui = tui::init()?;
        let mut app = tui::App::new(&certs);
        app.run(&mut tui)?;
        tui::restore()?;
    } else {
        let mut stdout = io::stdout().lock();

        if !args.check {
            for cert in &certs {
                writeln!(&mut stdout, "Certificate")?;
                writeln!(&mut stdout, "===========")?;

                info::write_cert_info(cert, &mut stdout, false)?;

                writeln!(&mut stdout)?;
                writeln!(&mut stdout)?;
            }
        }

        if args.check {
            report.write_check(&mut stdout)?;
        }
    }

    if let Some(dump_path) = &args.dump {
        tracing::info!(%dump_path, "writing chain");

        let mut der_buf = Vec::with_capacity(1_024);

        let pem_cap = certs.len() * 2_048; // ~2Kb per cert

        let pem_chain = certs.iter().try_fold(
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

        fs::write(dump_path, pem_chain)
            .wrap_err_with(|| format!("Failed to dump downloaded cert chain to {dump_path}"))?;
    }

    Ok(if args.check {
        ExitCode::from(report.status() as u8)
    } else {
        ExitCode::SUCCESS
    })
}
