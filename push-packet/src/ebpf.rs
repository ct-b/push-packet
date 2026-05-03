use aya::{
    Ebpf, Pod,
    maps::{Array, Map, MapData},
    programs::Xdp,
};

use crate::{Loader, error::Error};

pub struct EbpfVar<T: Pod> {
    value: T,
    map: Array<MapData, T>,
    name: String,
}

impl<T: Pod> EbpfVar<T> {
    /// Set the `EbpfVar` value
    pub fn update(&mut self, value: T) -> Result<(), Error> {
        self.value = value;
        self.map
            .set(0, value, 0)
            .map_err(|e| Error::map(&self.name, e))
    }
    /// Get the `EbpfVar` value
    pub fn get(&self) -> &T {
        &self.value
    }
    /// Creates a new `EbpfVar` with a given name and value
    pub fn new(ebpf: &mut Ebpf, name: &str, value: T) -> Result<Self, Error> {
        let mut map = array_owned(ebpf, name)?;
        map.set(0, value, 0).map_err(|e| Error::map(name, e))?;
        Ok(Self {
            value,
            map,
            name: name.into(),
        })
    }
}

impl<T: Pod> Loader for (T, &str) {
    type Component = EbpfVar<T>;
    fn load(self, ebpf: &mut Ebpf) -> Result<Self::Component, Error> {
        EbpfVar::new(ebpf, self.1, self.0)
    }
}

pub(crate) fn map_owned<T>(ebpf: &mut Ebpf, name: &str) -> Result<T, Error>
where
    T: TryFrom<Map, Error = aya::maps::MapError>,
{
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| Error::MissingMap(name.into()))?;
    T::try_from(map).map_err(|e| Error::map(name, e))
}

pub(crate) fn array_owned<T: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<Array<MapData, T>, Error> {
    map_owned(ebpf, name)
}

/// Get an un-loaded xdp program
pub(crate) fn xdp_program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp, Error> {
    ebpf.program_mut(name)
        .ok_or_else(|| Error::MissingProgram(name.into()))?
        .try_into()
        .map_err(|e| Error::InvalidProgramType {
            program_name: name.into(),
            e,
        })
}

/// Get a loaded xdp program
pub(crate) fn load_xdp_program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp, Error> {
    let program = xdp_program(ebpf, name)?;
    program.load().map_err(|e| Error::load_program(name, e))?;
    Ok(program)
}
