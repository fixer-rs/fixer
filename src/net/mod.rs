use addr::parse_domain_name;
use fast_socks5::client::Socks5Stream;
use simple_error::{SimpleError, SimpleResult};
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_native_tls::TlsStream;

pub mod proxy;
pub mod tls;

pub(crate) fn host_and_port_to_addr(host: &str, port: u16) -> SimpleResult<String> {
    let host_ip = IpAddr::from_str(host);
    match host_ip {
        Ok(ip_addr) => {
            let socket = match ip_addr {
                IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            };
            Ok(format!("{}", socket))
        }
        Err(_) => match parse_domain_name(host) {
            Ok(name) => Ok(format!("{}:{}", name.as_str(), port)),
            Err(err) => Err(SimpleError::from(err)),
        },
    }
}
pub enum DialerStream<S: AsyncRead + AsyncWrite + Unpin> {
    Tcp(S),
    Tls(TlsStream<S>),
    Socks5(Socks5Stream<S>),
    Socks5Tls(TlsStream<Socks5Stream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for DialerStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for DialerStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

// use tokio::net::{TcpListener, TcpStream };
// use tokio_util::codec::{ Framed, LinesCodec };
// use tokio::stream::StreamExt;
// use std::error::Error;
// use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     let args: Vec<String> = std::env::args().collect();

//     if args[1] == "server"
//     {
//         let local_addr: String = format!("{}{}",":::",args[2]); // app <server | client> <port>

//         let listener = TcpListener::bind(&local_addr).await?;

//         while let Ok((socket, peer)) = listener.accept().await {

//             tokio::spawn(async move {
//                 println!("Client Connected from: {}",peer.to_string());
//                 let mut client = Framed::new(socket, LinesCodec::new_with_max_length(1024));

//                 while let Some(Ok(line)) = client.next().await {
//                     println!("{}", line);
//                 }
//             });
//         }
//     }
//     else if args[1] == "client"
//     {
//         let port = args[2].parse::<u16>().unwrap(); // app client <port>
//         let saddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
//         let conn = TcpStream::connect(saddr).await?;

//         let mut server = Framed::new(conn, LinesCodec::new_with_max_length(1024));

//         while let Some(Ok(line)) = server.next().await {
//             println!("{}", line);
//         }
//     }

//     Ok({})
// }
// https://github.com/JuxhinDB/async-smtp/blob/fba44515fb8001b46fb61510f264035151410e3d/src/smtp/client/net.rs#L6
// Represents the different types of underlying network streams
// #[pin_project(project = NetworkStreamProj)]
// #[allow(missing_debug_implementations)]
// pub enum NetworkStream {
//     /// Plain TCP stream
//     Tcp(#[pin] TcpStream),
//     /// Encrypted TCP stream
//     Tls(#[pin] TlsStream<TcpStream>),
//     /// Socks5 stream
//     #[cfg(feature = "socks5")]
//     Socks5Stream(#[pin] Socks5Stream<TcpStream>),
//     #[cfg(feature = "socks5")]
//     TlsSocks5Stream(#[pin] TlsStream<Socks5Stream<TcpStream>>),
//     /// Mock stream
//     Mock(#[pin] MockStream),
// }
