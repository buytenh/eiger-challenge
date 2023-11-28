use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::ssl::Ssl;
use std::io::Error;
use std::io::ErrorKind;
use std::pin::Pin;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::net::TcpStream;

mod libp2p_tls_openssl;
mod multistream;

const TLS_PROTOCOL: &str = "/tls/1.0.0";
const YAMUX_PROTOCOL: &str = "/yamux/1.0.0";

async fn connect(server: &str) -> Result<tokio::net::TcpStream, Error> {
    println!("Connecting to {}", server);

    let stream = TcpStream::connect(&server).await?;

    println!("Connected to {}", server);

    Ok(stream)
}

async fn negotiate_multistream<T>(stream: &mut T, protocol: &str) -> Result<(), Error>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    println!("Negotiating multistream protocol {} with remote", protocol);

    let res = multistream::initiate(stream, &[protocol]).await?;
    if res.is_none() {
        return Err(Error::new(
            ErrorKind::AddrNotAvailable,
            format!("remote doesn't support {}", protocol),
        ));
    }

    println!("Negotiated multistream protocol {} with remote", protocol);

    Ok(())
}

async fn perform_tls_handshake<T>(
    stream: T,
    libp2p_host_key: &PKey<Private>,
) -> Result<tokio_openssl::SslStream<T>, Error>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    println!("Performing TLS handshake");

    let ssl_ctx = libp2p_tls_openssl::new_ssl_context(libp2p_host_key)?;
    let ssl = Ssl::new(&ssl_ctx)?;
    let mut ssl_stream = tokio_openssl::SslStream::new(ssl, stream)?;

    Pin::new(&mut ssl_stream).connect().await.map_err(|err| {
        Error::new(
            ErrorKind::Other,
            format!("error performing TLS handshake: {}", err),
        )
    })?;

    if ssl_stream.ssl().selected_alpn_protocol() != Some("libp2p".as_bytes()) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unexpected ALPN negotiated",
        ));
    }

    println!("Performed TLS handshake");

    Ok(ssl_stream)
}

async fn try_negotiate(server: &str, libp2p_host_key: &PKey<Private>) -> Result<(), Error> {
    let stream = connect(server).await?;

    let mut buf_reader = BufReader::new(stream);

    negotiate_multistream(&mut buf_reader, TLS_PROTOCOL).await?;

    let mut ssl_stream = perform_tls_handshake(buf_reader, libp2p_host_key).await?;

    negotiate_multistream(&mut ssl_stream, YAMUX_PROTOCOL).await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let libp2p_host_key = if true {
        PKey::<Private>::generate_ed25519()
    } else {
        PKey::<Private>::ec_gen("secp521r1")
    }
    .expect("generate libp2p host key");

    try_negotiate("127.0.0.1:4001", &libp2p_host_key)
        .await
        .expect("libp2p handshake");

    println!("Terminating successfully");
}
