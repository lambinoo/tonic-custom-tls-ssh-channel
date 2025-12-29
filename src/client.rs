use std::time::Duration;

use rustls::{RootCertStore, pki_types::pem::PemObject};
use tonic::transport::Endpoint;

use crate::{
    client_builder::{Certs, ClientBuilder},
    proto::{
        EchoRequest, echo_services_client::EchoServicesClient,
        public_echo_services_client::PublicEchoServicesClient,
    },
    ssh_channel::SSHChannel,
};

mod proto {
    tonic::include_proto!("echo");
}

mod client_builder;
mod insecure_cert_verifier;
mod ssh_channel;

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let data_dir = std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);
    let cert = std::fs::read_to_string(data_dir.join("tls/client.pem"))?;
    let key = std::fs::read_to_string(data_dir.join("tls/priv.key"))?;

    let cert = rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes())?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes())?;

    let endpoint = Endpoint::from_static("https://server.local")
        .http2_keep_alive_interval(Duration::from_secs(1))
        .keep_alive_timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(5));

    let ssh_channel = SSHChannel::new("localhost")
        .with_user(std::env::var("USER").unwrap_or_else(|_| "root".into()))
        .with_jumps(vec!["lamb@127.0.0.1"])
        .with_connect_timeout(Duration::from_secs(5));

    let certs = if matches!(std::env::var("RUSTLS_INSECURE"), Ok(v) if v == "1") {
        tracing::warn!("Insecure certificate verification enabled!");
        Certs::DoNotVerify
    } else {
        tracing::info!("Using root certificates from data/tls/ca.pem");
        let root_ca = std::fs::read_to_string(data_dir.join("tls/ca.pem"))?;
        let root_ca = rustls::pki_types::CertificateDer::from_pem_slice(root_ca.as_bytes())?;
        let mut root_store = RootCertStore::empty();
        root_store.add(root_ca).unwrap();
        Certs::RootCerts(root_store)
    };

    let channel = ClientBuilder::new(endpoint)
        .with_certs(certs)
        .with_client_auth(vec![cert], key)
        .with_ssh_channel(ssh_channel)
        .with_connect_uri(Some("[::1]:50051".parse().expect("invalid url")))
        .build()
        .expect("failed to setup channel");

    let mut privileged_client = EchoServicesClient::new(channel.clone());
    let mut public_client = PublicEchoServicesClient::new(channel);
    let mut i = 0;
    loop {
        let response = if i % 2 == 0 {
            privileged_client
                .ping(EchoRequest {
                    message: format!("ping {i}"),
                })
                .await
        } else {
            public_client
                .ping(EchoRequest {
                    message: format!("ping {i}"),
                })
                .await
        };

        match response {
            Ok(resp) => {
                tracing::info!("RESPONSE={:?}", resp.into_inner().message);
            }
            Err(e) => tracing::warn!("ERROR={:?}", e),
        }
        i += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
