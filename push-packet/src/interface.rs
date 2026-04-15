use nix::net::if_::{if_indextoname, if_nametoindex};
use push_packet_common::FrameKind;

use crate::error::Error;

pub struct Interface {
    name: String,
    index: u32,
}

impl Interface {
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let index =
            if_nametoindex(name).map_err(|_| Error::InvalidInterfaceName(name.to_string()))?;
        let name = name.to_string();
        Ok(Self { name, index })
    }

    pub fn from_index(index: u32) -> Result<Self, Error> {
        let name = if_indextoname(index)
            .map_err(|_| Error::InvalidInterfaceIndex(index))?
            .into_string()?
            .to_string();
        Ok(Self { name, index })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

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
