extern crate sysconfig;

use std::io;


#[cfg(target_os = "linux")]
fn main() -> Result<(), io::Error> {
    let config = sysconfig::dns::load_resolver_config()?;
    
    println!("{:?}", config);

    Ok(())
}


#[cfg(target_os = "macos")]
fn main() -> Result<(), io::Error> {
    for item in sysconfig::dns::list_network_services().iter() {
        println!("NetWorkService: {:?}  DNS: {:?}", item.name(), item.dns());
    }
    

    for item in sysconfig::dns::list_network_interfaces().iter() {
        println!("{:?}", item);
    }

    let network_global = sysconfig::dns::get_network_global();
    println!("{:?}", network_global);

    // let global_dns = "8.8.8.8".parse::<std::net::IpAddr>().unwrap();
    // network_global.set_global_dns(&[global_dns])?;
    
    
    Ok(())
}