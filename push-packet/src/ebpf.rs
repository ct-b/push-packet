use aya::{
    Ebpf, Pod,
    maps::{Array, Map, MapData},
    programs::Xdp,
};

use crate::{Loader, error::Error};

pub struct EbpfVar<T: Pod> {
    value: T,
    map: Array<MapData, T>,
}

impl<T: Pod> EbpfVar<T> {
    pub fn update(&mut self, value: T) -> Result<(), Error> {
        self.value = value;
        self.map.set(0, value, 0)?;
        Ok(())
    }
    pub fn get(&self) -> &T {
        &self.value
    }
    pub fn new(ebpf: &mut Ebpf, name: &str, value: T) -> Result<Self, Error> {
        let mut map = array_owned(ebpf, name)?;
        map.set(0, value, 0)?;
        Ok(Self { value, map })
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
    T: TryFrom<Map>,
    T::Error: Into<Error>,
{
    let map = ebpf.take_map(name).ok_or(Error::MissingEbpfMap)?;
    T::try_from(map).map_err(Into::into)
}

pub(crate) fn array_owned<T: Pod>(ebpf: &mut Ebpf, name: &str) -> Result<Array<MapData, T>, Error> {
    map_owned(ebpf, name)
}

pub(crate) fn xdp_program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp, Error> {
    let program: &mut Xdp = ebpf
        .program_mut(name)
        .ok_or(Error::MissingEbpfProgram)?
        .try_into()?;
    Ok(program)
}
