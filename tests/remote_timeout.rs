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
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();

    rustls::StreamOwned::new(
        rustls::ServerConnection::new(Arc::new(config)).unwrap(),
        sock,
    )
}

fn read_request(tls: &mut impl std::io::Read, host: &str) {
    let mut request = Vec::new();
    let mut byte = [0];

    while !request.ends_with(b"\r\n\r\n") {
        assert!(request.len() < 4096, "HTTP request was too long");
        tls.read_exact(&mut byte).unwrap();
        request.extend_from_slice(&byte);
    }

    assert_eq!(
        String::from_utf8(request).unwrap(),
        format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: inspect-cert-chain/{}\r\nAccept-Encoding: identity\r\n\r\n",
            env!("CARGO_PKG_VERSION"),
        ),
    );
}

fn finish_response(tls: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>) {
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        .unwrap();
    tls.conn.send_close_notify();
    tls.flush().unwrap();
}

struct Server<T> {
    addr: SocketAddr,
    stop: Sender<()>,
    worker: Option<JoinHandle<T>>,
}

impl<T: Send + 'static> Server<T> {
    fn start(handler: impl FnOnce(TcpStream, Receiver<()>) -> T + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            "--timeout",
            "500ms",
        ],
        Duration::from_secs(3),
    );

    server.finish();
    assert_timeout(&output, elapsed, Duration::from_millis(500));
    assert!(String::from_utf8_lossy(&output.stderr).contains("after 500ms"));
}

#[test]
fn unfinished_response_times_out_after_tls_completes() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS12);
        read_request(&mut tls, "127.0.0.1");
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npartial")
            .unwrap();
        tls.flush().unwrap();

        let _ = stopped.recv_timeout(HARNESS_TIMEOUT);
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

    server.finish();
    assert_timeout(&output, elapsed, Duration::from_secs(1));
}

#[test]
fn repeated_response_data_does_not_extend_the_deadline() {
    let server = Server::start(|sock, stopped| {
        let mut tls = tls_stream(sock, &rustls::version::TLS13);
        read_request(&mut tls, "127.0.0.1");
        tls.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
        tls.flush().unwrap();

        let deadline = Instant::now() + HARNESS_TIMEOUT;
        let mut writes = 0;

        while Instant::now() < deadline {
            if tls.write_all(b".").and_then(|_| tls.flush()).is_err() {
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

#[test]
fn tls_and_response_share_one_deadline() {
    let server = Server::start(|sock, stopped| {
        thread::sleep(Duration::from_millis(1200));

        let mut tls = tls_stream(sock, &rustls::version::TLS12);
        read_request(&mut tls, "127.0.0.1");

        if stopped.recv_timeout(Duration::from_millis(1200)).is_err() {
            // Each delay fits in two seconds, but their sum exceeds the deadline.
            let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });

    let (output, elapsed) = run(
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
    assert_timeout(&output, elapsed, Duration::from_secs(2));
}

fn inspect_with_tls(version: &'static rustls::SupportedProtocolVersion) {
    let server = Server::start(move |sock, _| {
        let mut tls = tls_stream(sock, version);
        read_request(&mut tls, "127.0.0.1");
        assert_eq!(tls.conn.protocol_version(), Some(version.version));
        finish_response(&mut tls);
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
fn successful_inspection_supports_tls12() {
    inspect_with_tls(&rustls::version::TLS12);
}

#[test]
fn successful_inspection_supports_tls13() {
    inspect_with_tls(&rustls::version::TLS13);
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
