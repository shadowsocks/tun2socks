#![allow(unused_imports, unused_mut, unused_variables, unused_assignments, unused_must_use, dead_code)]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate mio;
extern crate tun;
extern crate smoltcp;

use mio::Poll;
use mio::Token;
use mio::Interest;
use mio::Registry;
use mio::event::Event;
use mio::event::Events;
use mio::net::{ UdpSocket, TcpListener, TcpStream, };

use smoltcp::wire::{ PrettyPrinter, };
use smoltcp::wire::{ IpVersion, IpProtocol, IpAddress, Ipv4Cidr, Ipv4Address, EthernetAddress, };
use smoltcp::wire::{ IpRepr, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr, TcpSeqNumber, TcpControl, UdpPacket, UdpRepr, };
use smoltcp::phy::{ ChecksumCapabilities, Checksum, };
use smoltcp::socket::{TcpState, TcpSocket, TcpSocketBuffer, SocketSet, SocketSetItem, SocketRef};

use std::process::Command;
use std::io::{self, Read, Write};
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, };
use std::time::{ Duration, Instant, };
use std::collections::HashMap;


// NOTE: Linux TUN 在创建的时候默认设置成了 IFF_NO_PI.
#[cfg(target_os = "linux")]
const IFF_PI_PREFIX_LEN: usize = 0;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const IFF_PI_PREFIX_LEN: usize = 4;
#[cfg(target_os = "macos")]
const IPV4_PACKET_SIGNATURE: [u8; 4]   = [000, 000, 000, 002];


const DEFAULT_TUN_MTU: usize      = 4096;
const MAX_TCP_CONNECTIONS: usize  = 1024;

const POLL_TIMEOUT: Duration = Duration::from_secs(1); // 2s
const TUN_TOKEN: mio::Token = mio::Token(5);
const UDP_TOKEN: mio::Token = mio::Token(6);

pub const SOCKS_ATYP_IPV4: u8        = 0x01;
pub const SOCKS_ATYP_DOMAIN_NAME: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8        = 0x04;

pub type TunDevice = tun::Device;
pub type Relays = HashMap<Token, TcpRelay>;
pub type UdpRelays = HashMap<Token, UdpRelay>;
pub type Tokens = HashMap<[SocketAddr; 2], Token>; // [src, dst]


fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "tun2socks=debug");
    env_logger::init();

    // Config
    let tun_ifname  = "utun9";
    let tun_cidr    = Ipv4Cidr::new(Ipv4Address([10, 192, 168, 10]), 24);
    let tun_addr    = tun_cidr.address();
    let tun_network = tun_cidr.network();
    let tun_netmask = tun_network.netmask();
    let tun_gateway_addr = Ipv4Address([10, 192, 168, 1]);

    let egress_iface_ip         = IpAddr::from([192, 168, 199, 200]);
    let egress_iface_gateway_ip = IpAddr::from([192, 168, 199, 1]);
    
    // shadowsocks ss-remote socket address.
    let ss_remote_ip       = IpAddr::from([45, 77, 180, 8]);
    let ss_remote_endpoint = SocketAddr::from((ss_remote_ip, 65534));
    
    let mut tun_device = tun::Device::new(&tun_ifname)?;
    tun_device.set_address(tun_addr)?;
    tun_device.set_netmask(tun_netmask)?;
    tun_device.set_destination(tun_gateway_addr)?;
    tun_device.set_mtu(DEFAULT_TUN_MTU as i32)?;
    tun_device.enabled(true)?;

    info!("tun device: name={} address={} gateway={} network={}", tun_ifname, tun_addr, tun_gateway_addr, tun_network);

    // GNU/Linux
    // $ sudo route add -net {tun_cidr} dev {tun_ifname}
    // macOS
    // $ sudo route add -net {tun_cidr} -interface {tun_ifname}
    Command::new("route")
            .arg("add")
            .arg("-net")
            .arg(format!("{}", tun_cidr))
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("180.101.49.12") // www.baidu.com
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("104.193.88.123") // www.baidu.com
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("172.217.25.78") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("1.1.1.1") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("1.0.0.1") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("8.8.8.8") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("66.254.114.41") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg("172.217.174.100") // google
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
            

        
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg(format!("{}", tun_addr))
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg(format!("{}", tun_gateway_addr))
            .arg("-interface")
            .arg(&tun_ifname)
            .output()?;
    
    Command::new("route")
            .arg("add")
            .arg("-host")
            .arg(format!("{}", ss_remote_ip))
            .arg("-interface")
            .arg("en0")
            // .arg("192.168.199.1")
            .output()?;

    // sudo route add -net 10.192.168.0/24 -gateway 192.168.199.1
    println!("
Try:
    $ curl 180.101.49.12
    $ curl 172.217.25.78
    $ curl \"{}:80\"
    $ curl \"{}:80\"

    # macOS
    $ sudo route delete default; sudo route add default -interface utun9
    $ sudo route delete default; sudo route add default 192.168.199.1
", tun_addr, tun_gateway_addr);

    let mut events  = Events::with_capacity(1024);

    let mut poll = Poll::new()?;
    let mut buffer = [0u8; DEFAULT_TUN_MTU + IFF_PI_PREFIX_LEN];
    let mut unique_token = Token(10);
    
    let mut relays: HashMap<Token, TcpRelay> = HashMap::with_capacity(1024);
    let mut tokens: HashMap<[SocketAddr; 2], Token> = HashMap::with_capacity(1024);

    let mut udp_relays: HashMap<Token, UdpRelay> = HashMap::with_capacity(1024);
    let mut udp_tokens: HashMap<[SocketAddr; 2], Token> = HashMap::with_capacity(1024);

    // let mut ss_remote_udp_socket = UdpSocket::bind(SocketAddr::from((egress_iface_ip, 0)))?;
    // ss_remote_udp_socket.connect(ss_remote_endpoint)?;

    poll.registry().register(&mut tun_device, TUN_TOKEN, Interest::READABLE)?;
    // poll.registry().register(&mut ss_remote_udp_socket, UDP_TOKEN, Interest::READABLE)?;

    info!("ready to go event loop...");
    loop {
        poll.poll(&mut events, Some(POLL_TIMEOUT))?;

        let registry = poll.registry();

        for event in events.iter() {
            let event_token = event.token();
            match event_token {
                TUN_TOKEN => {
                    let amt = tun_device.read(&mut buffer)?;
                    const IPV4_HDR_MIN: usize = 20 + IFF_PI_PREFIX_LEN;
                    if amt < IPV4_HDR_MIN {
                        trace!("Malformed");
                        continue;
                    }
                    let mut ip_packet = &mut buffer[IFF_PI_PREFIX_LEN..amt];

                    // Colord
                    // Red  : \x1b[31m  \x1b[0m
                    // Green: \x1b[32m  \x1b[0m
                    // Blue : \x1b[34m  \x1b[0m
                    match ingress_ip(&ip_packet, &registry, &mut tun_device, &mut tokens, &mut relays, &mut udp_tokens, &mut udp_relays, &mut unique_token, &ss_remote_endpoint, &egress_iface_ip) {
                        Ok(_) => { },
                        Err(e) => {
                            error!("{:?}", e);
                        }
                    }
                },
                token => {
                    let relay = match relays.get_mut(&token) {
                        Some(relay) => relay,
                        None => {
                            match udp_relays.get_mut(&token) {
                                Some(relay) => {
                                    if let Err(e) = handle_udp_relay(relay, &mut tun_device, &mut buffer) {
                                        error!("Handle UDP Relay Stream Event error: {:?}", e);
                                        poll.registry().deregister(&mut relay.relay_stream)?;

                                        let socket_id = [relay.local_endpoint, relay.remote_endpoint];
                                        udp_tokens.remove(&socket_id);
                                        udp_relays.remove(&token);
                                    }
                                },
                                None => { },
                            }

                            continue;
                        },
                    };

                    relay.relay_is_readable = event.is_readable();
                    relay.relay_is_writable = event.is_writable();
                    relay.relay_is_error = event.is_error();

                    // if event.is_error() {
                    //     error!("relay poll error: {:?}", event);
                    //     let socket_id = [relay.local_endpoint, relay.remote_endpoint];
                    //     tokens.remove(&socket_id);
                    //     relays.remove(&token);
                    //     continue;
                    // }
                    
                    if let Err(e) = handle_relay(relay, &mut tun_device, &mut buffer) {
                        error!("Handle Relay Stream Event error: {:?}", e);
                        poll.registry().deregister(&mut relay.relay_stream)?;
                        
                        let socket_id = [relay.local_endpoint, relay.remote_endpoint];
                        tokens.remove(&socket_id);
                        relays.remove(&token);
                    }
                },
            }
        }
    }
}

fn token_increase(unique_token: &mut Token) -> Token {
    unique_token.0 += 1;
    Token(unique_token.0)
}



fn ingress_ip(tun_packet: &[u8], registry: &Registry, tun_device: &mut TunDevice, tokens: &mut Tokens, relays: &mut Relays, udp_tokens: &mut Tokens, udp_relays: &mut UdpRelays, unique_token: &mut Token, relay_endpoint: &SocketAddr, egress_iface_ip: &IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    match IpVersion::of_packet(&tun_packet) {
        Ok(IpVersion::Ipv4) => {
            ingress_ipv4(tun_packet, registry, tun_device, tokens, relays, udp_tokens, udp_relays, unique_token, relay_endpoint, egress_iface_ip)
        },
        Ok(IpVersion::Ipv6) => {
            trace!("droped");
            Ok(())
        },
        _ => {
            trace!("droped");
            Ok(())
        },
    }
}

fn ingress_ipv4(tun_packet: &[u8], registry: &Registry, tun_device: &mut TunDevice, tokens: &mut Tokens, relays: &mut Relays, udp_tokens: &mut Tokens, udp_relays: &mut UdpRelays, unique_token: &mut Token, relay_endpoint: &SocketAddr, egress_iface_ip: &IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    let mut checksum_caps = ChecksumCapabilities::ignored();

    let ipv4_packet = Ipv4Packet::new_unchecked(&tun_packet);
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

    let src_addr = ipv4_repr.src_addr;
    let dst_addr = ipv4_repr.dst_addr;

    match ipv4_repr.protocol {
        IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
            let udp_repr = UdpRepr::parse(&udp_packet, &IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr), &checksum_caps)?;

            println!("\x1b[32m{}\x1b[0m", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &ipv4_packet));
            // println!("\x1b[32m     \\ {:?}\x1b[0m", &udp_repr.payload);

            ingress_udp(ipv4_repr, udp_repr, registry, tun_device, udp_tokens, udp_relays, unique_token, relay_endpoint, egress_iface_ip)
        },
        IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
            let tcp_repr = TcpRepr::parse(&tcp_packet, &IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr), &checksum_caps)?;

            println!("\x1b[32m{}\x1b[0m", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &ipv4_packet));
            // println!("\x1b[32m     \\ {:?}\x1b[0m", &tcp_repr.payload);

            ingress_tcp(ipv4_repr, tcp_repr, registry, tun_device, tokens, relays, unique_token, relay_endpoint, egress_iface_ip)
        },
        _ => {
            Ok(())
        },
    }
}


#[derive(Debug)]
pub struct TcpRelay {
    pub local_endpoint: SocketAddr,
    pub remote_endpoint: SocketAddr,
    pub relay_endpoint: SocketAddr,

    pub local_socket: TcpSocket<'static>,

    pub relay_token: Token,
    pub relay_stream: TcpStream,
    pub relay_hdr_is_send: bool,
    pub relay_is_readable: bool,
    pub relay_is_writable: bool,
    pub relay_is_error: bool,
}

fn ingress_tcp(ipv4_repr: Ipv4Repr, tcp_repr: TcpRepr, registry: &Registry, tun_device: &mut TunDevice, tokens: &mut Tokens, relays: &mut Relays, unique_token: &mut Token, relay_endpoint: &SocketAddr, egress_iface_ip: &IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    let src_port = tcp_repr.src_port;
    let dst_port = tcp_repr.dst_port;

    let src_ip: Ipv4Addr = ipv4_repr.src_addr.into();
    let dst_ip: Ipv4Addr = ipv4_repr.dst_addr.into();

    let local_endpoint = SocketAddr::new(src_ip.into(), src_port);
    let remote_endpoint = SocketAddr::new(dst_ip.into(), dst_port);

    let socket_id = [local_endpoint, remote_endpoint];
    
    let relay = tokens.get(&socket_id).map(|token| relays.get_mut(token).unwrap());

    let mut checksum_caps = ChecksumCapabilities::ignored();
    checksum_caps.ipv4 = Checksum::Tx;
    checksum_caps.tcp = Checksum::Tx;
    checksum_caps.udp = Checksum::Tx;

    match relay {
        Some(relay) => {
            let local_socket = &mut relay.local_socket;

            let accepts = local_socket.accepts(&ipv4_repr.into(), &tcp_repr);
            assert_eq!(accepts, true);

            handle_local_tcp_socket_ingress(local_socket, ipv4_repr, tcp_repr, tun_device)?;

            let mut buffer = [0u8; 4096 * 2];
            handle_relay(relay, tun_device, &mut buffer)?;
        },
        None => {
            match (tcp_repr.control, tcp_repr.ack_number) {
                (TcpControl::Syn, None) => {
                    // 建立新的 TcpStream
                    let mut local_socket = TcpSocket::new(TcpSocketBuffer::new(vec![0u8; 4096 * 2]), TcpSocketBuffer::new(vec![0u8; 4096 * 2]));
                    local_socket.listen(remote_endpoint)?;
                    local_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(15)));

                    let accepts = local_socket.accepts(&ipv4_repr.into(), &tcp_repr);
                    assert_eq!(accepts, true);

                    handle_local_tcp_socket_ingress(&mut local_socket, ipv4_repr, tcp_repr, tun_device)?;

                    let relay_endpoint = *relay_endpoint;

                    let relay_token = token_increase(unique_token);

                    // NOTE: 绑定到 egress iface addr 上面，这样子流量会从 egress iface 路由出去。
                    let egress_iface_addr = SocketAddr::from((*egress_iface_ip, 0));
                    let sock = if egress_iface_addr.is_ipv4() {
                        mio::net::TcpSocket::new_v4()?
                    } else if egress_iface_addr.is_ipv6() {
                        mio::net::TcpSocket::new_v6()?
                    } else {
                        unreachable!()
                    };
                    sock.bind(egress_iface_addr)?;
                    // info!("connect to ss-remote: {}", relay_endpoint);
                    let mut relay_stream = sock.connect(relay_endpoint)?;

                    let relay_is_readable = false;
                    let relay_is_writable = false;
                    let relay_is_error = false;

                    registry.register(&mut relay_stream, relay_token, Interest::READABLE | Interest::WRITABLE)?;

                    let relay = TcpRelay {
                        local_endpoint, remote_endpoint, relay_endpoint, 
                        local_socket, relay_token, relay_stream, 
                        relay_is_readable, relay_is_writable, relay_is_error,
                        relay_hdr_is_send: false,
                    };

                    tokens.insert(socket_id, relay_token);
                    relays.insert(relay_token, relay);
                },
                _ => {
                    // ignored

                },
            }
        },
    }

    Ok(())
}

fn handle_local_tcp_socket_ingress(local_socket: &mut TcpSocket, ipv4_repr: Ipv4Repr, tcp_repr: TcpRepr, tun_device: &mut TunDevice) -> Result<(), Box<dyn std::error::Error>> {
    let mut checksum_caps = ChecksumCapabilities::ignored();
    checksum_caps.ipv4 = Checksum::Tx;
    checksum_caps.tcp = Checksum::Tx;
    checksum_caps.udp = Checksum::Tx;

    let mut device_caps = smoltcp::phy::DeviceCapabilities::default();
    device_caps.max_transmission_unit = DEFAULT_TUN_MTU - IFF_PI_PREFIX_LEN;
    device_caps.checksum = checksum_caps;

    let mut buffer = [0u8; 4096 * 2]; // NOTE: 需要从上面把 buffer 传递下来

    let now = smoltcp::time::Instant::now();
    let ret = local_socket.process(now, &ipv4_repr.into(), &tcp_repr);
    match ret {
        Ok(Some((reply_ip_repr, reply_tcp_repr))) => {
            // 将答复报文写入 Tun Device 里面。
            if reply_ip_repr.version() == IpVersion::Unspecified {
                error!("TcpStack Illegal error.");
                return Err(Box::new(smoltcp::Error::Illegal));
            }

            match emit_ip_tcp(reply_ip_repr, reply_tcp_repr, tun_device, &mut buffer) {
                Ok(_) => { },
                Err(e) => {
                    error!("TUN Write Error: {:?}", e);
                    return Err(Box::new(smoltcp::Error::Exhausted));
                }
            }
        },
        Ok(None) => { },
        Err(e) => {
            error!("TcpStack incoming packet process error: {:?}", e);
            return Err(Box::new(e));
        },
    }

    let now = smoltcp::time::Instant::now();
    let ret = local_socket.dispatch(now,  &device_caps,
        |(reply_ip_repr, reply_tcp_repr)| -> Result<(), smoltcp::Error> {
            if reply_ip_repr.version() == IpVersion::Unspecified {
                error!("TcpStack Illegal error.");
                return Err(smoltcp::Error::Illegal);
            }

            match emit_ip_tcp(reply_ip_repr, reply_tcp_repr, tun_device, &mut buffer) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("TUN Write Error: {:?}", e);
                    Err(smoltcp::Error::Exhausted)
                }
            }
        }
    );
    match ret {
        Ok(_) => Ok(()),
        Err(smoltcp::Error::Exhausted) => Ok(()),
        Err(e) => {
            error!("TcpStack dispatch error: {:?}", e);
            Err(Box::new(e))
        }
    }
}


#[derive(Debug)]
pub struct UdpRelay {
    pub local_endpoint: SocketAddr,
    pub remote_endpoint: SocketAddr,
    pub relay_endpoint: SocketAddr,

    pub relay_token: Token,
    pub relay_stream: UdpSocket,

    pub last_update: Instant,
}

fn ingress_udp(ipv4_repr: Ipv4Repr, udp_repr: UdpRepr, registry: &Registry, tun_device: &mut TunDevice, tokens: &mut Tokens, relays: &mut UdpRelays, unique_token: &mut Token, relay_endpoint: &SocketAddr, egress_iface_ip: &IpAddr) -> Result<(), Box<dyn std::error::Error>> {
    if udp_repr.payload.len() == 0 {
        return Ok(())
    }

    let src_port = udp_repr.src_port;
    let dst_port = udp_repr.dst_port;

    let src_ip: Ipv4Addr = ipv4_repr.src_addr.into();
    let dst_ip: Ipv4Addr = ipv4_repr.dst_addr.into();

    let local_endpoint = SocketAddr::new(src_ip.into(), src_port);
    let remote_endpoint = SocketAddr::new(dst_ip.into(), dst_port);

    let socket_id = [local_endpoint, remote_endpoint];
    
    let relay = tokens.get(&socket_id).map(|token| relays.get_mut(token).unwrap());

    let mut ss_udp_packet = Vec::with_capacity(1024);
    match remote_endpoint {
        SocketAddr::V4(v4_addr) => {
            ss_udp_packet.push(SOCKS_ATYP_IPV4);
            ss_udp_packet.extend_from_slice(&v4_addr.ip().octets());
            ss_udp_packet.extend_from_slice(&v4_addr.port().to_be_bytes());
            ss_udp_packet.extend_from_slice(&udp_repr.payload);
        },
        SocketAddr::V6(v6_addr) => {
            ss_udp_packet.push(SOCKS_ATYP_IPV6);
            ss_udp_packet.extend_from_slice(&v6_addr.ip().octets());
            ss_udp_packet.extend_from_slice(&v6_addr.port().to_be_bytes());
            ss_udp_packet.extend_from_slice(&udp_repr.payload);
        },
    };

    match relay {
        Some(relay) => {
            let amt = relay.relay_stream.send(&ss_udp_packet)?;
            if amt != ss_udp_packet.len() {
                let e = io::Error::new(io::ErrorKind::Other, "udp socket write_all failed.");
                return Err(Box::new(e));
            }

            relay.last_update = Instant::now();
        },
        None => {
            let relay_endpoint = *relay_endpoint;
            let relay_token = token_increase(unique_token);

            let mut relay_stream = UdpSocket::bind(SocketAddr::from((*egress_iface_ip, 0)))?;
            relay_stream.connect(relay_endpoint)?;

            let mut relay = UdpRelay {
                local_endpoint, remote_endpoint, relay_endpoint,
                relay_token, relay_stream, 
                last_update: Instant::now(),
            };

            let amt = relay.relay_stream.send(&ss_udp_packet)?;
            if amt != ss_udp_packet.len() {
                let e = io::Error::new(io::ErrorKind::Other, "udp socket write_all failed.");
                return Err(Box::new(e));
            }

            registry.register(&mut relay.relay_stream, relay_token, Interest::READABLE)?;

            tokens.insert(socket_id, relay_token);
            relays.insert(relay_token, relay);
        },
    }

    Ok(())
}

fn handle_relay(relay: &mut TcpRelay, tun_device: &mut TunDevice, buffer: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let local_socket = &mut relay.local_socket;
    let stream = &mut relay.relay_stream;
    
    if relay.relay_is_readable {
        if local_socket.can_send() {
            let ret = local_socket.send(|buf| -> (usize, Option<io::Error>) {
                match stream.read(buf) {
                    Ok(amt) => {
                        info!("read {:?} bytes from ss-remote ...", amt);
                        (amt, None)
                    },
                    Err(e) => {
                        info!("read bytes from ss-remote error: {:?}", e);
                        (0, Some(e))
                    },
                }
            });

            match ret {
                Ok(Some(io_error)) => {
                    if io_error.kind() == io::ErrorKind::WouldBlock {
                        // info!("WouldBlock");
                        // return Ok(());
                    }
                    error!("Relay Stream read error: {:?}", io_error);
                    return Err(Box::new(io_error));
                },
                Ok(None) => { },
                Err(e) => {
                    error!("TcpStack send error: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        }
    }

    let mut relay_hdr_is_send = relay.relay_hdr_is_send;
    let remote_endpoint = relay.remote_endpoint;

    if local_socket.can_recv() {
        if relay.relay_is_writable {
            let ret = local_socket.recv(|buf| -> (usize, Option<io::Error>) {
                // NOTE: 先发送 SS-SOCKS HEADER.
                // https://shadowsocks.org/en/wiki/Protocol.html
                if !relay_hdr_is_send {
                    info!("try write ss-socks protocol header ...");
                    let mut small_buffer = [0u8; 20];
                    
                    let len = match remote_endpoint {
                        SocketAddr::V4(v4_addr) => {
                            small_buffer[0] = SOCKS_ATYP_IPV4;
                            small_buffer[1..5].copy_from_slice(&v4_addr.ip().octets());        // BND.ADDR
                            small_buffer[5..7].copy_from_slice(&v4_addr.port().to_be_bytes()); // BND.PORT
                            7
                        },
                        SocketAddr::V6(v6_addr) => {
                            small_buffer[0] = SOCKS_ATYP_IPV6;
                            small_buffer[ 1..17].copy_from_slice(&v6_addr.ip().octets());        // BND.ADDR
                            small_buffer[17..19].copy_from_slice(&v6_addr.port().to_be_bytes()); // BND.PORT
                            19
                        },
                    };
                    match stream.write_all(&small_buffer[..len]) {
                        Ok(_) => { },
                        Err(e) => return (0, Some(e)),
                    }

                    relay_hdr_is_send = true;
                }

                info!("try write {:?} bytes to ss-remote ...", buf.len());

                match stream.write(&buf) {
                    Ok(amt) => {
                        let _ = stream.flush();
                        (amt, None)
                    },
                    Err(e) => (0, Some(e)),
                }
            });

            relay.relay_hdr_is_send = relay_hdr_is_send;

            match ret {
                Ok(Some(io_error)) => {
                    if io_error.kind() == io::ErrorKind::WouldBlock {
                        // return Ok(());
                    }
                    error!("Relay Stream write error: {:?}", io_error);
                    return Err(Box::new(io_error));
                },
                Ok(None) => { },
                Err(e) => {
                    error!("TcpStack recv error: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        }
    }

    let mut checksum_caps = ChecksumCapabilities::ignored();
    checksum_caps.ipv4 = Checksum::Tx;
    checksum_caps.tcp = Checksum::Tx;
    checksum_caps.udp = Checksum::Tx;

    let mut device_caps = smoltcp::phy::DeviceCapabilities::default();
    device_caps.max_transmission_unit = DEFAULT_TUN_MTU - IFF_PI_PREFIX_LEN;
    // device_caps.max_burst_size = Some(DEFAULT_TUN_MTU - 500);
    device_caps.max_burst_size = None;
    device_caps.checksum = checksum_caps;

    let local_socket = &mut relay.local_socket;

    let now = smoltcp::time::Instant::now();
    let ret = local_socket.dispatch(now,  &device_caps,
        |(reply_ip_repr, reply_tcp_repr)| -> Result<(), smoltcp::Error> {
            if reply_ip_repr.version() == IpVersion::Unspecified {
                error!("TcpStack Illegal error.");
                return Err(smoltcp::Error::Illegal);
            }

            match emit_ip_tcp(reply_ip_repr, reply_tcp_repr, tun_device, buffer) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("TUN Write Error: {:?}", e);
                    Err(smoltcp::Error::Exhausted)
                }
            }
        }
    );

    match ret {
        Ok(_) => Ok(()),
        Err(smoltcp::Error::Exhausted) => Ok(()),
        Err(e) => {
            error!("TcpStack dispatch error: {:?}", e);
            Err(Box::new(e))
        }
    }
}

fn handle_udp_relay(relay: &mut UdpRelay, tun_device: &mut TunDevice, buffer: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    let amt = relay.relay_stream.recv(buffer)?;
    if amt == 0 {
        return Ok(());
    }

    let payload = &buffer[..amt].to_vec();

    let mut checksum_caps = ChecksumCapabilities::ignored();
    checksum_caps.ipv4 = Checksum::Tx;
    checksum_caps.tcp = Checksum::Tx;
    checksum_caps.udp = Checksum::Tx;

    match (relay.remote_endpoint.ip(), relay.local_endpoint.ip()) {
        (IpAddr::V4(src_v4_addr), IpAddr::V4(dst_v4_addr)) => {
            debug!("recied SS UDP packet header: {:?}", &payload[..7]);
            let udp_repr = UdpRepr {
                src_port: relay.remote_endpoint.port(),
                dst_port: relay.local_endpoint.port(),
                // NOTE:前面有 SS-SOCKS 协议的头部，这里不处理。
                payload: &payload[7..],
            };

            let src_addr = src_v4_addr.into();
            let dst_addr = dst_v4_addr.into();
            let protocol = IpProtocol::Udp;
            let payload_len = udp_repr.buffer_len();
            let hop_limit = 0;

            let ip_repr = Ipv4Repr {
                src_addr, dst_addr, 
                protocol, payload_len, hop_limit,
            };

            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[IFF_PI_PREFIX_LEN..]);
            ip_repr.emit(&mut ipv4_packet, &checksum_caps);

            let mut udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload_mut());
            udp_repr.emit(&mut udp_packet, &src_addr.into(), &dst_addr.into(), &checksum_caps);

            let total_len = ip_repr.buffer_len() + udp_repr.buffer_len();

            let pkt = &buffer[IFF_PI_PREFIX_LEN..IFF_PI_PREFIX_LEN + total_len];
            // DEBUG
            let ipv4_packet = Ipv4Packet::new_unchecked(&pkt);
            let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
            println!("\x1b[31mDispatch: {}\x1b[0m", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &ipv4_packet));
            // println!("\x1b[31m     \\ {:?}\x1b[0m", &udp_packet.payload());

            // Write to TUN.
            #[cfg(target_os = "macos")]
            buffer[..IFF_PI_PREFIX_LEN].copy_from_slice(&IPV4_PACKET_SIGNATURE);
            
            let tun_packet = &buffer[..IFF_PI_PREFIX_LEN + total_len];
            tun_device.write_all(tun_packet)?;

            relay.last_update = Instant::now();
        },
        _ => {
            let e = io::Error::new(io::ErrorKind::Other, "only supoort ipv4.");
            return Err(Box::new(e));
        },
    }

    Ok(())
}

fn emit_ip_tcp<'a>(reply_ip_repr: IpRepr, reply_tcp_repr: TcpRepr<'a>, tun_device: &mut TunDevice, buffer: &mut [u8]) -> Result<(), io::Error> {
    let mut checksum_caps = ChecksumCapabilities::ignored();
    checksum_caps.ipv4 = Checksum::Tx;
    checksum_caps.tcp = Checksum::Tx;
    checksum_caps.udp = Checksum::Tx;

    let ip_hdr_len = reply_ip_repr.buffer_len();
    let tcp_len = reply_tcp_repr.buffer_len();
    assert!(ip_hdr_len + tcp_len + IFF_PI_PREFIX_LEN <= DEFAULT_TUN_MTU);
    assert_eq!(reply_ip_repr.payload_len(), reply_tcp_repr.buffer_len());

    let total_len = reply_ip_repr.total_len();

    let src_addr = reply_ip_repr.src_addr();
    let dst_addr = reply_ip_repr.dst_addr();

    reply_ip_repr.emit(&mut buffer[IFF_PI_PREFIX_LEN..], &checksum_caps);

    let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[IFF_PI_PREFIX_LEN..]);
    let mut tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload_mut());
    reply_tcp_repr.emit(&mut tcp_packet, &src_addr, &dst_addr, &checksum_caps);

    let pkt = &buffer[IFF_PI_PREFIX_LEN..IFF_PI_PREFIX_LEN + total_len];

    // DEBUG
    let ipv4_packet = Ipv4Packet::new_unchecked(&pkt);
    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
    println!("\x1b[31mDispatch: {}\x1b[0m", PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &ipv4_packet));
    // println!("\x1b[31m     \\ {:?}\x1b[0m", &tcp_packet.payload());
    
    // Write to TUN.
    #[cfg(target_os = "macos")]
    buffer[..IFF_PI_PREFIX_LEN].copy_from_slice(&IPV4_PACKET_SIGNATURE);
    
    let tun_packet = &buffer[..IFF_PI_PREFIX_LEN + total_len];
    tun_device.write_all(tun_packet)?;

    Ok(())
}