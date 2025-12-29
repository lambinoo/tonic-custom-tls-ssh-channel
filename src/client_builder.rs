use std::sync::Arc;

use hyper_util::client::legacy::connect::HttpConnector;
use rustls::{ClientConfig, RootCertStore};
use tonic::transport::{Channel, Endpoint};

use crate::{insecure_cert_verifier::InsecureCertificateVerifier, ssh_channel::SSHChannel};

pub enum Certs {
    RootCerts(RootCertStore),
    DoNotVerify,
}

impl From<RootCertStore> for Certs {
    fn from(store: RootCertStore) -> Self {
        Certs::RootCerts(store)
    }
}

pub struct ClientBuilder {
    endpoint: Endpoint,
    root_certs: Certs,
    client_auth: Option<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    ssh_channel: Option<SSHChannel>,
    connect_uri: Option<hyper::Uri>,
}

impl ClientBuilder {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            root_certs: Certs::RootCerts(RootCertStore::empty()),
            client_auth: None,
            ssh_channel: None,
            connect_uri: None,
        }
    }

    pub fn with_ssh_channel(mut self, channel: SSHChannel) -> Self {
        self.ssh_channel = Some(channel);
        self
    }

    /// Specifies how the server shall be verified. By default, an empty root certificate store is used.
    /// You should pass a RootCertStore that is properly configured to get a working TLS client.
    /// If you want to disable verification, use `Certs::DoNotVerify`.
    pub fn with_certs<T: Into<Certs>>(mut self, certs: T) -> Self {
        self.root_certs = certs.into();
        self
    }

    /// Configures the client to use TLS client authentication
    pub fn with_client_auth(
        mut self,
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Self {
        self.client_auth = Some((certs, key));
        self
    }

    /// If this is specified, the client will connect to the given URI, and verify the server certificate against
    /// the hostname **in the endpoint**.
    pub fn with_connect_uri<T: Into<Option<hyper::Uri>>>(mut self, uri: T) -> Self {
        self.connect_uri = uri.into();
        self
    }

    pub fn build(self) -> Result<Channel, String> {
        let tls_config = ClientConfig::builder();
        let tls_config = match self.root_certs {
            Certs::RootCerts(root_store) => {
                if root_store.is_empty() {
                    tracing::warn!("No root certificates provided, TLS connections will fail");
                }

                tls_config.with_root_certificates(root_store)
            }
            Certs::DoNotVerify => tls_config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertificateVerifier)),
        };

        let tls_config = if let Some((certs, key)) = self.client_auth {
            tls_config
                .with_client_auth_cert(certs, key)
                .map_err(|e| e.to_string())?
        } else {
            tls_config.with_no_client_auth()
        };

        let uri = self
            .connect_uri
            .unwrap_or_else(|| self.endpoint.uri().clone());

        let channel = if let Some(ssh_channel) = self.ssh_channel {
            let connector = tower::ServiceBuilder::new()
                .layer_fn(move |s| {
                    hyper_rustls::HttpsConnectorBuilder::new()
                        .with_tls_config(tls_config.clone())
                        .https_or_http()
                        .enable_http2()
                        .wrap_connector(s)
                })
                .map_request(move |_| uri.clone())
                .service(ssh_channel);

            self.endpoint.connect_with_connector_lazy(connector)
        } else {
            let mut http = HttpConnector::new();
            http.enforce_http(false);

            let connector = tower::ServiceBuilder::new()
                .layer_fn(move |s| {
                    hyper_rustls::HttpsConnectorBuilder::new()
                        .with_tls_config(tls_config.clone())
                        .https_or_http()
                        .enable_http2()
                        .wrap_connector(s)
                })
                .map_request(move |_| uri.clone())
                .service(http);

            self.endpoint.connect_with_connector_lazy(connector)
        };

        Ok(channel)
    }
}
