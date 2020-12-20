extern crate tun;


use std::io::{self, Read};

fn main() -> Result<(), io::Error> {
    let mut device = tun::Device::new("utun6")?;
    device.set_address([10, 0, 0, 1])?;
    device.set_netmask([255, 255, 255, 0])?;
    device.set_mtu(1500)?;
    device.enabled(true)?;

    let mut buf = [0; 4096];
    
    println!("
macOS:
    $ sudo route add -net 10.0.0.0/24 -interface utun6
    $ ping 10.0.0.1

GNU/Linux:
    $ sudo route add -net 10.0.0.0/24 dev utun6
    $ ping 10.0.0.1
");
    loop {
        let amount = device.read(&mut buf)?;
        println!("{:?}", &buf[0 .. amount]);
    }
}
