use std::{ops::Deref, path::Path, str::FromStr, sync::Arc};

use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rcgen::{CertifiedIssuer, CustomExtension};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use tonic::Request;
use tonic::body::Body;
use tonic::service::Routes;
use tower::ServiceExt;
use tower_http::ServiceBuilderExt;
use tracing_subscriber::EnvFilter;
use x509_parser::{
    asn1_rs::Oid,
    prelude::{FromDer, X509Certificate},
};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct Rbac {
    allow_ping: bool,
}

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

mod proto {
    tonic::include_proto!("echo");
}

struct EchoServer;

#[tonic::async_trait]
impl proto::public_echo_services_server::PublicEchoServices for EchoServer {
    async fn ping(
        &self,
        request: tonic::Request<proto::EchoRequest>,
    ) -> Result<tonic::Response<proto::EchoResponse>, tonic::Status> {
        let reply = proto::EchoResponse {
            message: request.into_inner().message,
        };
        tracing::info!("Received public ping: `{}`", reply.message,);
        Ok(tonic::Response::new(reply))
    }
}

#[tonic::async_trait]
impl proto::echo_services_server::EchoServices for EchoServer {
    async fn ping(
        &self,
        request: tonic::Request<proto::EchoRequest>,
    ) -> Result<tonic::Response<proto::EchoResponse>, tonic::Status> {
        let reply = proto::EchoResponse {
            message: request.into_inner().message,
        };
        tracing::info!("Received privileged ping: `{}`", reply.message);
        Ok(tonic::Response::new(reply))
    }
}

fn ensure_key_exists<T: AsRef<Path>>(target_dir: T) {
    if target_dir.as_ref().join("priv.key").exists() {
        return;
    }

    let signing_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];

    let ca_issuer = CertifiedIssuer::self_signed(ca_params, signing_key).unwrap();

    let mut server_cert = rcgen::CertificateParams::new(vec!["server.local".to_string()]).unwrap();
    server_cert.is_ca = rcgen::IsCa::NoCa;
    server_cert.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    server_cert.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_cert
        .signed_by(ca_issuer.key(), ca_issuer.deref())
        .unwrap();

    let mut client_cert = rcgen::CertificateParams::new(vec!["lambino".to_string()]).unwrap();
    client_cert.is_ca = rcgen::IsCa::NoCa;
    client_cert.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    let rbac = Rbac { allow_ping: false };
    let rbac_json = serde_json::to_vec(&rbac).unwrap();

    let rbac_ext = CustomExtension::from_oid_content(&[2, 25, 1789463, 1, 5], rbac_json);
    client_cert.custom_extensions = vec![rbac_ext];
    client_cert.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_cert
        .signed_by(ca_issuer.key(), ca_issuer.deref())
        .unwrap();

    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.as_ref().join("ca.pem"), ca_issuer.pem()).unwrap();
    std::fs::write(target_dir.as_ref().join("server.pem"), server_cert.pem()).unwrap();
    std::fs::write(target_dir.as_ref().join("client.pem"), client_cert.pem()).unwrap();
    std::fs::write(
        target_dir.as_ref().join("priv.key"),
        ca_issuer.key().serialize_pem(),
    )
    .unwrap();
}

#[derive(Debug)]
struct CertVerifier {
    verifier: Arc<dyn ClientCertVerifier>,
}

impl ClientCertVerifier for CertVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.verifier.client_auth_mandatory()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        let result = self
            .verifier
            .verify_client_cert(end_entity, intermediates, now);
        match &result {
            Ok(_) => tracing::info!("Client certificate verified successfully"),
            Err(e) => tracing::warn!("Client certificate verification failed: {:?}", e),
        }
        result
    }

    fn offer_client_auth(&self) -> bool {
        self.verifier.offer_client_auth()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.verifier.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.verifier.root_hint_subjects()
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }
}

#[derive(Debug)]
#[allow(unused)]
struct ConnInfo {
    addr: std::net::SocketAddr,
    certificates: Option<Vec<CertificateDer<'static>>>,
}

fn rbac_allow_ping(req: Request<()>) -> Result<Request<()>, tonic::Status> {
    if let Some(conn_info) = req.extensions().get::<Arc<ConnInfo>>() {
        let rbac_oid = Oid::from_str("2.25.1789463.1.5").unwrap();

        for cert in conn_info.certificates.iter().flatten() {
            let (_, cert) = X509Certificate::from_der(cert.as_ref()).unwrap();
            for ext in cert.extensions() {
                if ext.oid == rbac_oid {
                    let rbac: Rbac = serde_json::from_slice(ext.value).unwrap();
                    if rbac.allow_ping {
                        tracing::info!("RBAC check passed: {:?}", rbac);
                        return Ok(req);
                    } else {
                        tracing::warn!("RBAC check failed: {:?}", rbac);
                    }
                }
            }
        }
    }

    Err(tonic::Status::permission_denied("RBAC check failed"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .with_file(true)
        .with_line_number(true)
        .init();

    let data_dir = std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);
    ensure_key_exists(data_dir.join("tls"));

    let root_ca = std::fs::read_to_string(data_dir.join("tls/ca.pem"))?;
    let cert = std::fs::read_to_string(data_dir.join("tls/server.pem"))?;
    let key = std::fs::read_to_string(data_dir.join("tls/priv.key"))?;

    let root_ca = CertificateDer::from_pem_slice(root_ca.as_bytes()).unwrap();
    let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();

    let mut root_certs = RootCertStore::empty();
    root_certs.add(root_ca).unwrap();

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_certs)).build()?;
    let client_verifier: Arc<dyn ClientCertVerifier> = Arc::new(CertVerifier {
        verifier: client_verifier,
    });

    let mut tls_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let http = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let service = proto::echo_services_server::EchoServicesServer::with_interceptor(
        EchoServer,
        rbac_allow_ping,
    );
    let public_service =
        proto::public_echo_services_server::PublicEchoServicesServer::new(EchoServer);

    let mut routes = Routes::builder();
    routes.add_service(service);
    routes.add_service(public_service);

    let service = routes.routes();
    let listener = tokio::net::TcpListener::bind("[::1]:50051").await?;
    tracing::info!("Server listening on [::1]:50051");
    loop {
        let (tcp_stream, socket_addr) = match listener.accept().await {
            Ok(incoming) => incoming,
            Err(e) => {
                tracing::error!("Failed to accept connection: {:?}", e);
                continue;
            }
        };

        tracing::info!("Accepted connection from {:?}", socket_addr);

        let service = service.clone();
        let http = http.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let conn = tls_acceptor.accept(tcp_stream).await.unwrap();
            let certificates: Option<Vec<CertificateDer<'static>>> =
                conn.get_ref().1.peer_certificates().map(Vec::from);

            let svc = tower::ServiceBuilder::new()
                .add_extension(Arc::new(ConnInfo {
                    addr: socket_addr,
                    certificates,
                }))
                .service(service.clone());

            http.serve_connection(
                TokioIo::new(conn),
                TowerToHyperService::new(
                    svc.map_request(|req: hyper::Request<_>| req.map(Body::new)),
                ),
            )
            .await
            .unwrap();
        });
    }
}
