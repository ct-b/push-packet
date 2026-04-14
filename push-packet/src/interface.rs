use nix::net::if_::{if_indextoname, if_nametoindex};

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
