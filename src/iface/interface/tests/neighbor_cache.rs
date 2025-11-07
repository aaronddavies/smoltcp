use super::*;

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_neighbor_cache_access(#[case] medium: Medium) {
    let (mut iface, mut sockets, device) = setup(medium);

    // Initially the cache should be empty
    assert!(iface.neighbor_cache().is_empty());
    assert_eq!(iface.neighbor_cache().len(), 0);

    // Add an entry to the neighbor cache
    let ip_addr = Ipv4Address::from_bytes(&[192, 168, 1, 2]).into();
    let hw_addr = HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x03]));
    iface.inner.neighbor_cache.fill(ip_addr, hw_addr, iface.inner.now);

    // Check that the entry is accessible through the interface method
    assert!(!iface.neighbor_cache().is_empty());
    assert_eq!(iface.neighbor_cache().len(), 1);

    // Check the entry through the iterator
    let mut entries = iface.neighbor_cache().iter().collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);

    let (cached_ip, cached_neighbor) = entries[0];
    assert_eq!(*cached_ip, ip_addr);
    assert_eq!(cached_neighbor.hardware_addr(), hw_addr);

    // Verify the neighbor_cache() returns the same instance as the internal one
    // by adding another entry directly and checking it's visible
    let ip_addr2 = Ipv4Address::from_bytes(&[192, 168, 1, 3]).into();
    let hw_addr2 = HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x04]));
    iface.inner.neighbor_cache.fill(ip_addr2, hw_addr2, iface.inner.now);

    assert_eq!(iface.neighbor_cache().len(), 2);

    // Check both entries are accessible
    let mut found1 = false;
    let mut found2 = false;

    for (ip, neighbor) in iface.neighbor_cache().iter() {
        if *ip == ip_addr {
            found1 = true;
            assert_eq!(neighbor.hardware_addr(), hw_addr);
        } else if *ip == ip_addr2 {
            found2 = true;
            assert_eq!(neighbor.hardware_addr(), hw_addr2);
        }
    }

    assert!(found1, "First entry should be in the cache");
    assert!(found2, "Second entry should be in the cache");
}