// pub struct RouteV4Entry {
//     dst: Ipv4Cidr,
//     ifindex: u32, // out_ifindex
//     flags: RouteFlags,
//     gateway: Option<Ipv4Addr>,
//     prefsrc: Option<Ipv6Addr>,

//     metrics: RouteMetrics,

//     #[cfg(target_os = "linux")]
//     table: RouteTable,
//     #[cfg(target_os = "linux")]
//     scope: RouteScope,
//     #[cfg(target_os = "linux")]
//     protocol: RouteProtocol,
//     #[cfg(target_os = "linux")]
//     kind: RouteType,
// }


// pub enum RouteEntry {
//     V4(RouteV4Entry),
//     V6(RouteV6),
// }


// pub struct RouteTable {

// }

// pub struct RouteRecord {

// }