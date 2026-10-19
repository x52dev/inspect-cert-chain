use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const HARNESS_TIMEOUT: Duration = Duration::from_secs(13);
const CERTIFICATE: &[u8] = include_bytes!("fixtures/server.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/server-key.pem");

fn tls_stream(
    sock: TcpStream,
    version: &'static rustls::SupportedProtocolVersion,
) -> rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    let mut cert_pem = CERTIFICATE;
    let certs = rustls_pemfile::certs(&mut cert_pem)
        .collect::<Result<_, _>>()
        .unwrap();
    let mut key_pem = PRIVATE_KEY;
    let key = rustls_pemfile::private_key(&mut key_pem).unwrap().unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();

    // Do not send session tickets after the inspector closes the connection.
    config.send_tls13_tickets = 0;

    rustls::StreamOwned::new(
        rustls::ServerConnection::new(Arc::new(config)).unwrap(),
        sock,
    )
}

struct Server<T> {
    addr: SocketAddr,
    stop: Sender<()>,
    worker: Option<JoinHandle<T>>,
}

impl<T: Send + 'static> Server<T> {
    fn start(handler: impl FnOnce(TcpStream, Receiver<()>) -> T + Send + 'static) -> Self {
        Self::start_on("127.0.0.1", handler)
    }

    fn start_on(
        host: &str,
        handler: impl FnOnce(TcpStream, Receiver<()>) -> T + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind((host, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + HARNESS_TIMEOUT;

            let sock = loop {
                match listener.accept() {
                    Ok((sock, _)) => break sock,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "Server did not receive a connection"
                        );
                        assert!(
                            stopped.try_recv().is_err(),
                            "Server stopped before accepting"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("Failed to accept connection: {err}"),
                }
            };

            sock.set_nonblocking(false).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();

            handler(sock, stopped)
        });

        Self {
            addr,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> T {
        let _ = self.stop.send(());
        self.worker.take().unwrap().join().unwrap()
    }
}

impl<T> Drop for Server<T> {
    fn drop(&mut self) {
        let _ = self.stop.send(());

        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Cli(Option<Child>);

impl Drop for Cli {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(args: &[&str], limit: Duration) -> (Output, Duration) {
    let started = Instant::now();
    let mut cli = Cli(Some(
        Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));

    let mut killed = false;

    while cli.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        if started.elapsed() >= limit {
            cli.0.as_mut().unwrap().kill().unwrap();
            killed = true;
            break;
        }

        thread::sleep(Duration::from_millis(10));
    }

    let output = cli.0.take().unwrap().wait_with_output().unwrap();
    let elapsed = started.elapsed();

    assert!(
        !killed,
        "CLI exceeded the {limit:?} harness limit: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    (output, elapsed)
}

fn assert_timeout(output: &Output, elapsed: Duration, timeout: Duration) {
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "CLI succeeded after the deadline");
    assert!(
        stderr.contains("timed out"),
        "Missing timeout error: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "CLI printed a certificate after timing out"
    );
    assert!(elapsed >= timeout, "Timeout was too early: {elapsed:?}");
    assert!(
        elapsed < timeout + Duration::from_secs(2),
        "Timeout was too late: {elapsed:?}"
    );
}

#[test]
fn stalled_tls_handshake_uses_the_default_ten_second_timeout() {
    let server = Server::start(|mut sock, stopped| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");
        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, elapsed) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
        ],
        HARNESS_TIMEOUT,
    );

    server.finish();
    assert_timeout(&output, elapsed, Duration::from_secs(10));
}

#[test]
fn stalled_tls_handshake_uses_a_subsecond_timeout() {
    let server = Server::start(|mut sock, stopped| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");
        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, elapsed) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--server-name",
            "staging.example.invalid",
            "--timeout",
            "500ms",
        ],
        Duration::from_secs(3),
    );

    assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
        "Remote certificate fetch from {} timed out",
        server.addr,
    )));

    server.finish();
    assert_timeout(&output, elapsed, Duration::from_millis(500));
    assert!(String::from_utf8_lossy(&output.stderr).contains("after 500ms"));
}

#[test]
fn server_first_application_data_does_not_delay_inspection() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS12);

        // Queue the banner so it is sent with the final handshake messages.
        tls.conn
            .writer()
            .write_all(b"* OK TLS mail server ready\r\n")
            .unwrap();
        tls.conn.complete_io(&mut tls.sock).unwrap();

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "1s",
        ],
        Duration::from_secs(3),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    server.finish();
    assert!(String::from_utf8_lossy(&output.stdout).contains("CN=localhost"));
}

#[test]
fn repeated_handshake_data_does_not_extend_the_deadline() {
    let server = Server::start(|mut sock, stopped| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");

        // Start a 16 KiB handshake record, then keep its body incomplete.
        sock.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).unwrap();

        let deadline = Instant::now() + HARNESS_TIMEOUT;
        let mut writes = 0;

        while Instant::now() < deadline {
            if sock.write_all(b".").is_err() {
                break;
            }

            writes += 1;

            if stopped.recv_timeout(Duration::from_millis(100)).is_ok() {
                break;
            }
        }

        writes
    });

    let (output, elapsed) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "1s",
        ],
        Duration::from_secs(3),
    );

    assert!(server.finish() >= 3, "Server did not send repeated data");
    assert_timeout(&output, elapsed, Duration::from_secs(1));
}

fn inspect_with_tls(version: &'static rustls::SupportedProtocolVersion) {
    let server = Server::start(move |sock, stopped| {
        let mut tls = tls_stream(sock, version);
        tls.conn.complete_io(&mut tls.sock).unwrap();
        assert_eq!(tls.conn.protocol_version(), Some(version.version));
        assert_eq!(tls.conn.server_name(), None);

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);

        let mut byte = [0];

        match tls.read(&mut byte) {
            Ok(0) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            result => panic!("Client sent application data or did not close: {result:?}"),
        }
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    server.finish();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("Certificate\n===========\n"),
        "Missing certificate output: {stdout}"
    );
    assert!(
        stdout.contains("CN=localhost"),
        "Missing certificate subject: {stdout}"
    );
}

#[test]
fn tls12_inspection_finishes_without_application_data_or_server_close() {
    inspect_with_tls(&rustls::version::TLS12);
}

#[test]
fn tls13_inspection_finishes_without_application_data_or_server_close() {
    inspect_with_tls(&rustls::version::TLS13);
}

#[test]
fn inspection_sends_the_hostname_as_sni() {
    // Use the same address family that the client resolves for localhost.
    let server = Server::start_on("localhost", |sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();
        assert_eq!(tls.conn.server_name(), Some("localhost"));

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "localhost",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    server.finish();
    assert!(String::from_utf8_lossy(&output.stdout).contains("CN=localhost"));
}

#[test]
fn inspection_dumps_the_server_certificate_chain() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS12);
        tls.conn.complete_io(&mut tls.sock).unwrap();

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let dump_path = std::env::temp_dir().join(format!(
        "inspect-cert-chain-{}-chain.pem",
        std::process::id(),
    ));

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
            "--dump",
            dump_path.to_str().unwrap(),
        ],
        Duration::from_secs(4),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    server.finish();

    let dumped_pem = std::fs::read(&dump_path).unwrap();
    std::fs::remove_file(dump_path).unwrap();

    let dumped_chain = rustls_pemfile::certs(&mut dumped_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut server_pem = CERTIFICATE;
    let server_chain = rustls_pemfile::certs(&mut server_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(dumped_chain, server_chain);
}

#[test]
fn closed_tls_handshake_returns_an_error_without_certificates() {
    let server = Server::start(|mut sock, _| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    server.finish();

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Inspection unexpectedly succeeded"
    );
    assert!(
        stderr.contains("Failed to complete TLS handshake"),
        "Missing handshake error: {stderr}",
    );
    assert!(output.stdout.is_empty(), "CLI printed a certificate");
}

#[test]
fn invalid_tls_handshake_returns_an_error_without_certificates() {
    let server = Server::start(|mut sock, _| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");
        sock.write_all(b"This is not a TLS server\r\n").unwrap();
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    server.finish();

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Inspection unexpectedly succeeded"
    );
    assert!(
        stderr.contains("Failed to complete TLS handshake"),
        "Missing handshake error: {stderr}",
    );
    assert!(output.stdout.is_empty(), "CLI printed a certificate");
}

#[test]
fn ip_connection_uses_the_chosen_server_name() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();
        assert_eq!(tls.conn.server_name(), Some("staging.example.invalid"));

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--server-name",
            "staging.example.invalid",
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    server.finish();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("CN=localhost"));
    assert!(
        stdout.contains("Hostname (staging.example.invalid): INVALID"),
        "{stdout}"
    );
}

#[test]
fn ipv6_connection_uses_the_chosen_server_name() {
    let server = Server::start_on("::1", |sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS12);
        tls.conn.complete_io(&mut tls.sock).unwrap();
        assert_eq!(tls.conn.server_name(), Some("staging.example.invalid"));

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "::1",
            "--port",
            &server.addr.port().to_string(),
            "--server-name",
            "staging.example.invalid",
            "--timeout",
            "2s",
        ],
        Duration::from_secs(4),
    );

    assert!(
        output.status.success(),
        "Inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    server.finish();
    assert!(String::from_utf8_lossy(&output.stdout).contains("CN=localhost"));
}

#[test]
fn server_name_requires_a_connection_host() {
    let (output, _) = run(
        &["--server-name", "staging.example.invalid"],
        Duration::from_secs(3),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "Missing host was accepted");
    assert!(stderr.contains("--host <HOST>"), "Wrong error: {stderr}");
}

#[test]
fn server_name_conflicts_with_local_file_inspection() {
    let (output, _) = run(
        &[
            "--file",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/server.pem"),
            "--server-name",
            "staging.example.invalid",
        ],
        Duration::from_secs(3),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Server name with file was accepted"
    );
    assert!(
        stderr.contains("cannot be used with"),
        "Wrong error: {stderr}"
    );
    assert!(stderr.contains("--server-name"), "Wrong error: {stderr}");
    assert!(stderr.contains("--file"), "Wrong error: {stderr}");
}

#[test]
fn invalid_server_names_are_rejected() {
    for server_name in ["", "bad/name", "localhost\r\nInjected: header"] {
        let (output, _) = run(
            &[
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--server-name",
                server_name,
            ],
            Duration::from_secs(3),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(!output.status.success(), "Invalid server name was accepted");
        assert!(
            stderr.contains("Invalid TLS server name"),
            "Wrong validation error: {stderr}"
        );
    }
}

#[test]
fn remote_json_output_remains_valid_with_verbose_logs() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
            "--json",
            "--fields",
            "subject",
            "-vv",
        ],
        Duration::from_secs(4),
    );

    server.finish();

    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(
        value["certificates"],
        serde_json::json!([{ "subject": "CN=localhost" }])
    );
    assert_eq!(value["validation"]["status"], "invalid");
    assert_eq!(value["validation"]["path"]["status"], "invalid");
    assert_eq!(value["validation"]["hostname"]["name"], "127.0.0.1");
    assert_eq!(
        value["validation"]["handshake_signature"]["status"],
        "valid"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Certificate chain:"));
}

#[test]
fn dump_errors_produce_one_json_error_document() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });
    let directory = std::env::temp_dir();

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "2s",
            "--check",
            "--json",
            "--dump",
            directory.to_str().unwrap(),
        ],
        Duration::from_secs(4),
    );

    server.finish();

    assert_eq!(output.status.code(), Some(3), "{output:?}");

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["check"]["status"], "unknown");
    assert!(
        value["error"]
            .as_str()
            .unwrap()
            .contains("Failed to dump downloaded cert chain")
    );
    assert!(value.get("certificates").is_none());
}

#[test]
fn remote_timeout_in_check_mode_has_unknown_status() {
    let server = Server::start(|mut sock, stopped| {
        let mut buf = [0; 1024];
        assert!(sock.read(&mut buf).unwrap() > 0, "Client did not start TLS");
        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--timeout",
            "500ms",
            "--check",
            "--json",
        ],
        Duration::from_secs(3),
    );

    server.finish();

    assert_eq!(output.status.code(), Some(3), "{output:?}");

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["check"]["status"], "unknown");
    assert!(value["error"].as_str().unwrap().contains("timed out"));
}

#[test]
fn remote_inspection_reports_an_untrusted_chain_without_rejecting_it() {
    let server = Server::start(|sock, _| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
        ],
        Duration::from_secs(4),
    );

    server.finish();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("CN=localhost"));
    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Hostname (127.0.0.1):"), "{stdout}");
}

#[test]
fn remote_check_keeps_date_exit_codes_for_an_untrusted_chain() {
    let server = Server::start(|sock, _| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        tls.conn.complete_io(&mut tls.sock).unwrap();
    });

    let (output, _) = run(
        &[
            "--host",
            "127.0.0.1",
            "--port",
            &server.addr.port().to_string(),
            "--check",
            "--fields",
            "subject",
        ],
        Duration::from_secs(4),
    );

    server.finish();

    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("subject: CN=localhost"), "{stdout}");
    assert!(!stdout.contains("Public Key Algorithm:"), "{stdout}");
    assert!(stdout.contains("OK: 1 certificates"), "{stdout}");
    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Path validation: INVALID"), "{stdout}");
}

#[test]
fn zero_timeout_is_rejected() {
    for timeout in ["0", "0s", "0ms"] {
        let (output, _) = run(
            &["--host", "localhost", "--timeout", timeout],
            Duration::from_secs(3),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "Zero timeout was accepted: {timeout}"
        );
        assert!(
            stderr.contains("Timeout must be greater than zero"),
            "Wrong validation error: {stderr}"
        );
        assert!(
            stderr.contains("--timeout <DURATION>"),
            "Missing option name: {stderr}"
        );
    }
}

#[test]
fn local_file_inspection_still_works_with_the_timeout_option() {
    for timeout in ["1s", "2m", "1m 500ms"] {
        let (output, _) = run(
            &[
                "--file",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/server.pem"),
                "--timeout",
                timeout,
            ],
            Duration::from_secs(3),
        );

        assert!(
            output.status.success(),
            "Local inspection with {timeout} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("CN=localhost"));
    }
}

#[test]
fn local_chain_checks_report_validity_without_rejecting_the_chain() {
    let (output, _) = run(
        &[
            "--file",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/server.pem"),
            "--check",
            "--hostname",
            "localhost",
        ],
        Duration::from_secs(3),
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
    assert!(!stdout.contains("TLS handshake signature:"), "{stdout}");
}
