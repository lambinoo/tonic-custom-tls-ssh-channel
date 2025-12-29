use std::time::Duration;

use hyper::Uri;
use hyper_util::rt::TokioIo;
use tokio::process::Command;
use tonic::ConnectError;

pub struct ChildIO {
    reader: tokio::process::ChildStdout,
    writer: tokio::process::ChildStdin,
    _child: tokio::process::Child,
}

impl hyper_util::client::legacy::connect::Connection for ChildIO {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl tokio::io::AsyncRead for ChildIO {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ChildIO {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.writer).poll_shutdown(cx)
    }
}

pub struct BoxedFuture<T> {
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>,
}

impl<T> Future for BoxedFuture<T> {
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

#[derive(Clone)]
pub struct SSHChannel {
    ssh_user: String,
    ssh_host: String,
    jumps: Vec<String>,
    timeout_connect: Option<Duration>,
}

impl SSHChannel {
    pub fn new<T: Into<String>>(host: T) -> Self {
        let default_user = std::env::var("USER").unwrap_or_else(|_| "root".into());
        Self {
            ssh_user: default_user,
            ssh_host: host.into(),
            jumps: Vec::new(),
            timeout_connect: None,
        }
    }

    pub fn with_user<T: Into<String>>(mut self, user: T) -> Self {
        self.ssh_user = user.into();
        self
    }

    pub fn with_jumps<T: Into<String>>(mut self, jumps: Vec<T>) -> Self {
        self.jumps = jumps.into_iter().map(|s| s.into()).collect();
        self
    }

    pub fn with_connect_timeout<T: Into<Option<Duration>>>(mut self, timeout: T) -> Self {
        self.timeout_connect = timeout.into();
        self
    }
}

impl tower::Service<Uri> for SSHChannel {
    type Response = TokioIo<ChildIO>;
    type Error = ConnectError;
    type Future = BoxedFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let self_ = self.clone();

        let fut = async move {
            let host = req
                .host()
                .ok_or_else(|| ConnectError("URI must have a host".into()))?;

            let port = req
                .port_u16()
                .or_else(|| match req.scheme_str() {
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                })
                .ok_or_else(|| ConnectError("URI must have a port".into()))?;

            tracing::info!("Connecting to {}:{}", host, port);
            let mut command = Command::new("ssh");
            if let Some(duration) = self_.timeout_connect {
                command.arg(format!("-oConnectTimeout={}", duration.as_secs()));
            }

            if !self_.jumps.is_empty() {
                let jumps = self_.jumps.join(",");
                command.arg("-J").arg(jumps);
            }

            let mut child = command
                .arg("-l")
                .arg(&self_.ssh_user)
                .arg(format!("-W{}:{}", host, port))
                .arg(&self_.ssh_host)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| ConnectError(Box::new(e)))?;

            let out_bytes = child
                .stdout
                .take()
                .ok_or_else(|| ConnectError("Failed to take stdout".into()))?;

            let in_bytes = child
                .stdin
                .take()
                .ok_or_else(|| ConnectError("Failed to take stdin".into()))?;

            let io = ChildIO {
                reader: out_bytes,
                writer: in_bytes,
                _child: child,
            };

            Ok::<_, Self::Error>(TokioIo::new(io))
        };

        BoxedFuture { fut: Box::pin(fut) }
    }
}
