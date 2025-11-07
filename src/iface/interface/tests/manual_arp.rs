use super::*;

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_manual_arp_request(#[case] medium: Medium) {
    // Set up the interface and mock device
    let (mut iface, mut sockets, mut device) = setup(medium);

    // Configure IP address on the interface
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 24)).unwrap();
    });

    // The target IP address we want to resolve
    let target_ip = Ipv4Address::new(192, 168, 1, 2);

    // The current timestamp
    let timestamp = Instant::from_millis(0);

    // Send a manual ARP request
    let result = iface.send_arp_request(&mut device, target_ip, timestamp);

    // The request should have been sent successfully
    assert!(result.is_ok());

    // Check if the device has a frame queued
    assert!(!device.tx_queue.is_empty());

    // Get the frame from the device's queue
    let frame_data = device.tx_queue.pop_front().unwrap();

    // Parse the Ethernet frame
    let eth_frame = EthernetFrame::new_unchecked(&frame_data);
    assert_eq!(eth_frame.dst_addr(), EthernetAddress::BROADCAST);
    assert_eq!(eth_frame.ethertype(), EthernetProtocol::Arp);

    // Parse the ARP packet inside the Ethernet frame
    let arp_packet = ArpPacket::new_unchecked(eth_frame.payload());

    // Convert to a high-level representation
    let arp_repr = ArpRepr::parse(&arp_packet).unwrap();

    // Check that the ARP request was correctly formed
    match arp_repr {
        ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr,
            source_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        } => {
            assert_eq!(operation, ArpOperation::Request);
            assert_eq!(source_hardware_addr, iface.hardware_addr().ethernet_or_panic());
            assert_eq!(source_protocol_addr, Ipv4Address::new(192, 168, 1, 1));
            assert_eq!(target_hardware_addr, EthernetAddress::BROADCAST);
            assert_eq!(target_protocol_addr, target_ip);
        }
        _ => panic!("Expected EthernetIpv4 ARP request"),
    }
}