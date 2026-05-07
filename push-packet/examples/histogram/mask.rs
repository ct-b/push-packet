use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub fn mask_ip(seed: u64, addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => {
            let mut hasher = DefaultHasher::new();
            (seed, addr).hash(&mut hasher);
            let bytes = hasher.finish().to_le_bytes();
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
        IpAddr::V6(_) => {
            let mut hi = DefaultHasher::new();
            (seed, addr, 0u8).hash(&mut hi);
            let mut lo = DefaultHasher::new();
            (seed, addr, 1u8).hash(&mut lo);
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&hi.finish().to_le_bytes());
            out[8..].copy_from_slice(&lo.finish().to_le_bytes());
            IpAddr::V6(Ipv6Addr::from(out))
        }
    }
}
