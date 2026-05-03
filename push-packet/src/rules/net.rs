use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::rules::error::RuleError;

pub trait IntoIpNet {
    fn into_ip_net(self) -> Result<IpNet, RuleError>;
}

impl IntoIpNet for &str {
    fn into_ip_net(self) -> Result<IpNet, RuleError> {
        if !self.contains('/') {
            return self
                .parse::<IpAddr>()
                .map(std::convert::Into::into)
                .map_err(|e| RuleError::invalid_address(self, e));
        }
        self.parse::<IpNet>()
            .map_err(|e| RuleError::invalid_cidr(self, e))
    }
}

macro_rules! impl_into_ip_net {
    ($type:ty) => {
        impl IntoIpNet for $type {
            fn into_ip_net(self) -> Result<IpNet, RuleError> {
                Ok(self.into())
            }
        }
    };
}

macro_rules! impl_into_ip_net_addr {
    ($type:ty, $proxy_type:ty) => {
        impl IntoIpNet for $type {
            fn into_ip_net(self) -> Result<IpNet, RuleError> {
                let net: $proxy_type = self.into();
                Ok(net.into())
            }
        }
    };
}

impl_into_ip_net!(IpNet);
impl_into_ip_net!(Ipv4Net);
impl_into_ip_net!(Ipv6Net);
impl_into_ip_net!(IpAddr);
impl_into_ip_net_addr!(Ipv4Addr, Ipv4Net);
impl_into_ip_net_addr!(Ipv6Addr, Ipv6Net);

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ipnet::IpNet;

    use crate::rules::{error::RuleError, net::IntoIpNet};

    #[test]
    fn parse_bare_ipv4() {
        let test = "127.0.0.1".into_ip_net().unwrap();
        let control = IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).unwrap();
        assert_eq!(test, control);
    }

    #[test]
    fn parse_ipv4_cidr() {
        let test = "127.0.0.1/16".into_ip_net().unwrap();
        let control = IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 16).unwrap();
        assert_eq!(test, control);
    }

    #[test]
    fn parse_bare_ipv6() {
        let test = "2001:DB8:5002:AB41::801".into_ip_net().unwrap();
        let control = IpNet::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0DB8, 0x5002, 0xAB41, 0x000, 0x0000, 0x0000, 0x0801,
            )),
            128,
        )
        .unwrap();
        assert_eq!(test, control);
    }

    #[test]
    fn parse_ipv6_cidr() {
        let test = "2001:DB8:5002:AB41::801/32".into_ip_net().unwrap();
        let control = IpNet::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0DB8, 0x5002, 0xAB41, 0x000, 0x0000, 0x0000, 0x0801,
            )),
            32,
        )
        .unwrap();
        assert_eq!(test, control);
    }

    #[test]
    fn parse_bad_ip() {
        assert!(
            "notanip"
                .into_ip_net()
                .is_err_and(|e| matches!(e, RuleError::InvalidAddress { .. }))
        );
    }

    #[test]
    fn parse_bad_cidr_ip() {
        assert!(
            "not/an/ip"
                .into_ip_net()
                .is_err_and(|e| matches!(e, RuleError::InvalidCidr { .. }))
        );
    }
}
