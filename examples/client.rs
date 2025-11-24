mod utils;

use log::debug;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, Medium, wait as phy_wait, ChecksumCapabilities};
use smoltcp::socket::icmp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr};

fn main() {
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("CLIENT_ADDRESS");
    free.push("SERVER_ADDRESS");

    let mut matches = utils::parse_options(&opts, free);
    let device = utils::parse_tuntap_options(&mut matches);

    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);
    let client_address = IpAddress::from_str(&matches.free[0]).expect("invalid address format");
    let server_address = IpAddress::from_str(&matches.free[1]).expect("invalid address format");

    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        Medium::Ieee802154 => todo!(),
    };
    config.random_seed = rand::random();

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(client_address, 24))
            .unwrap();
    });

    // Create sockets
    let rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 2048]);
    let tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 2048]);
    let socket = icmp::Socket::new(rx_buffer, tx_buffer);
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);

    // Bind socket ID
    let socket = sockets.get_mut::<icmp::Socket>(handle);
    let ident = 0x1234;
    assert_eq!(socket.bind(icmp::Endpoint::Ident(ident)), Ok(()));

    // Send echo request
    let icmp_repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no: 1,
        data: &[0xde, 0xad, 0xbe, 0xef], // arbitrary data payload
    };
    let mut bytes = [0xff; 12];
    let mut packet = Icmpv4Packet::new_unchecked(&mut bytes);
    icmp_repr.emit(&mut packet, &ChecksumCapabilities::default());

    match socket.send_slice(packet.into_inner(), server_address) {
        Ok(()) => debug!("Queued slice."),
        Err(err) => debug!("Error queueing slice: {}", err),
    };

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<icmp::Socket>(handle);

        if socket.can_recv() {
            let (icmp_reply, dest_addr) = socket.recv().unwrap();
            debug!("Received to {:x?} ICMPv4 packet {:x?}", dest_addr, icmp_reply);
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}
