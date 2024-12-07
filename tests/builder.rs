use std::sync::Arc;

use pki_types::CertificateDer;
use pki_types::PrivatePkcs8KeyDer;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::ClientConfig;
use quinn::Endpoint;
use quinn::EndpointConfig;
use quinn::ServerConfig;
use quinn::TokioRuntime;
use rand::RngCore;
use rustls::quic::Suite;
use rustls::ClientConfig as RusTlsClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig as RusTlsServerConfig;
use rustls_rustcrypto::quic::chacha20::QuicChacha20;
use rustls_rustcrypto::TLS13_AES_128_GCM_SHA256;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use std::net::SocketAddr;

use rustls_rustcrypto::provider as rustcrypto_provider;

mod fake_time;
use fake_time::FakeTime;

mod fake_cert_server_verifier;
use fake_cert_server_verifier::FakeServerCertVerifier;

mod fake_cert_client_verifier;
use fake_cert_client_verifier::FakeClientCertVerifier;

mod fake_cert_server_resolver;
use fake_cert_server_resolver::FakeServerCertResolver;

// Test integration between rustls and rustls in Client builder context
#[test]
fn integrate_client_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let fake_server_cert_verifier = FakeServerCertVerifier {};

    let builder_init =
        RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    let dangerous_verifier = builder_default_versions
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(fake_server_cert_verifier));

    // Out of scope
    let rustls_client_config = dangerous_verifier.with_no_client_auth();

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

use rustls::DistinguishedName;

// Test integration between rustls and rustls in Server builder context
#[test]
fn integrate_server_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let builder_init =
        RusTlsServerConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    // A DistinguishedName is a Vec<u8> wrapped in internal types.
    // DER or BER encoded Subject field from RFC 5280 for a single certificate.
    // The Subject field is encoded as an RFC 5280 Name
    //let b_wrap_in: &[u8] = b""; // TODO: should have constant somewhere

    let dummy_entry: &[u8] = b"";

    let client_dn = [DistinguishedName::in_sequence(dummy_entry)];

    let client_cert_verifier = FakeClientCertVerifier { dn: client_dn };

    let dangerous_verifier =
        builder_default_versions.with_client_cert_verifier(Arc::new(client_cert_verifier));

    let server_cert_resolver = FakeServerCertResolver {};

    // Out of scope
    let rustls_client_config =
        dangerous_verifier.with_cert_resolver(Arc::new(server_cert_resolver));

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

#[tokio::test]
async fn test_quic() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let server = tokio::spawn({
        let cert_der = cert_der.clone();
        async move {
            // let provider = rustcrypto_provider();
            let crypto = RusTlsServerConfig::builder()
                // .with_protocol_versions(&[&rustls::version::TLS13])
                // .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], priv_key.into())
                .unwrap();
            let quic_server_config = QuicServerConfig::with_initial(
                Arc::new(crypto),
                Suite {
                    suite: TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
                    quic: &QuicChacha20,
                },
            )
            .unwrap();

            let mut server_config = ServerConfig::new(Arc::new(quic_server_config), {
                let rng = &mut rand::thread_rng();
                let mut master_key = [0u8; 64];
                rng.fill_bytes(&mut master_key);
                let master_key =
                    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&master_key);
                Arc::new(master_key)
            });
            let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
            transport_config.max_concurrent_uni_streams(0_u8.into());
            let runtime = Arc::new(TokioRuntime);
            let server_endpoint = Endpoint::new(
                EndpointConfig::default(),
                Some(server_config),
                std::net::UdpSocket::bind("127.0.0.1:5000").unwrap(),
                runtime,
            )
            .unwrap();
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            println!(
                "[server] incoming connection: addr={}",
                connection.remote_address()
            );
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 1024];
                        loop {
                            match recv.read(&mut buf).await.expect("read chunks") {
                                Some(n) => {
                                    println!("{:?}", std::str::from_utf8(&buf[..n]));
                                    send.write_all(&mut buf[..n]).await.expect("write chunks");
                                }
                                None => break,
                            }
                        }
                        let _ = send.finish();
                    });
                }
            });

            server_endpoint.wait_idle().await;
        }
    });

    let client = tokio::spawn({
        let cert_der = cert_der.clone();
        async move {
            let mut certs = rustls::RootCertStore::empty();
            certs.add(CertificateDer::from(cert_der)).unwrap();

            let client_cfg = ClientConfig::with_root_certificates(Arc::new(certs)).unwrap();
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let mut client_endpoint = Endpoint::new(
                EndpointConfig::default(),
                None,
                {
                    let socket =
                        Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
                            .unwrap();
                    socket.bind(&addr.into()).unwrap();
                    socket.into()
                },
                Arc::new(TokioRuntime),
            )
            .unwrap();
            client_endpoint.set_default_client_config(client_cfg);
            let connect = client_endpoint
                .connect("127.0.0.1:5000".parse().unwrap(), "localhost")
                .unwrap();
            let connection = connect.await.unwrap();
            println!("[client] connected: addr={}", connection.remote_address());
            let (mut send, mut recv) = connection.open_bi().await.expect("stream open");
            send.write_all(b"Hello World").await.unwrap();
            let mut buf = [0; 1024];
            match recv.read(&mut buf).await.expect("read chunks") {
                Some(n) => {
                    println!("{:?}", std::str::from_utf8(&buf[..n]));
                    send.write_all(&mut buf[..n]).await.expect("write chunks");
                }
                None => {}
            }
            send.finish().unwrap();
            connection.close(0u32.into(), b"done");
            client_endpoint.wait_idle().await;
        }
    });

    let _ = tokio::join!(client, server);
}
