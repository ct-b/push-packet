//! Network interface primitives
use nix::net::if_::{if_indextoname, if_nametoindex};
use push_packet_common::FrameKind;

use crate::error::Error;

/// A network interface
#[derive(Debug)]
pub struct Interface {
    name: String,
    index: u32,
}

impl Interface {
    /// Creates an interface from the name
    ///
    /// # Errors
    /// Returns [`Error::InvalidInterfaceName`] if the name is invalid.
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let index =
            if_nametoindex(name).map_err(|_| Error::InvalidInterfaceName(name.to_string()))?;
        let name = name.to_string();
        Ok(Self { name, index })
    }

    /// Creates an interface from the index
    ///
    /// # Errors
    /// Returns [`Error::InvalidInterfaceIndex`] if the index is invalid.
    /// Returns [`Error::InvalidInterfaceName`] if the name is invalid.
    ///
    /// # Panics
    /// Panics if the interface name is not a valid string
    pub fn from_index(index: u32) -> Result<Self, Error> {
        let name = if_indextoname(index)
            .map_err(|_| Error::InvalidInterfaceIndex(index))?
            .into_string()
            .expect("Linux interface names are valid ASCII");
        if name.is_empty() {
            return Err(Error::InvalidInterfaceIndex(index));
        }
        Ok(Self { name, index })
    }

    /// Returns the interface name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the interface index
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Returns the interfaces [`FrameKind`]. This is needed because most interfaces receive
    /// ethernet frames, while wireguard interfaces receive IP frames.
    ///
    /// # Errors
    /// Returns [`Error::InvalidFrameKind`] if the [`FrameKind`] is not [`FrameKind::Eth`] or
    /// [`FrameKind::Ip`].
    pub fn frame_kind(&self) -> Result<FrameKind, Error> {
        let value: u32 = std::fs::read_to_string(format!("/sys/class/net/{}/type", self.name))
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(|_e| Error::InvalidFrameKind(0))?;
        match value {
            1 | 772 => Ok(FrameKind::Eth),
            65534 => Ok(FrameKind::Ip),
            other => Err(Error::InvalidFrameKind(other)),
        }
    }
}

impl TryFrom<&String> for Interface {
    type Error = Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Interface::from_name(value)
    }
}

impl TryFrom<&str> for Interface {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Interface::from_name(value)
    }
}

impl TryFrom<String> for Interface {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Interface::from_name(&value)
    }
}

impl TryFrom<u32> for Interface {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Interface::from_index(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::Error, interface::Interface};

    #[test]
    fn interface_loads_loopback() {
        assert!(Interface::from_name("lo").is_ok());
    }

    #[test]
    fn interface_name_index_roundtrip() {
        let interface = Interface::from_name("lo").unwrap();
        let index = interface.index();
        let interface = Interface::from_index(index).unwrap();
        assert_eq!(interface.name(), "lo");
    }

    #[test]
    fn interface_lo_is_eth() {
        let interface = Interface::from_name("lo").unwrap();
        assert!(matches!(
            interface.frame_kind(),
            Ok(push_packet_common::FrameKind::Eth)
        ));
    }

    #[test]
    fn try_interface_from_values() {
        let _interface: Interface = "lo".try_into().unwrap();
        let interface: Interface = "lo".to_string().try_into().unwrap();
        let index = interface.index();
        let interface: Interface = index.try_into().unwrap();
        assert_eq!(interface.index(), index);
    }

    #[test]
    fn invalid_interface_name_fails() {
        let interface = Interface::from_name("invalidinterfacethatdoesntexist");
        assert!(interface.is_err_and(|e| matches!(e, Error::InvalidInterfaceName(_))));
    }

    #[test]
    fn invalid_interface_index_fails() {
        let interface = Interface::from_index(u32::MAX);
        println!("Got interface: {interface:?}");
        assert!(matches!(interface, Err(Error::InvalidInterfaceIndex(_))));
    }
}
