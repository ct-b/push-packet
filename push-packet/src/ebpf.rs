use aya::{
    Ebpf, Pod,
    maps::{Array, Map, MapData},
    programs::Xdp,
};

use crate::error::Error;

pub(crate) fn map_mut<'a, T>(ebpf: &'a mut Ebpf, name: &str) -> Result<T, Error>
where
    T: TryFrom<&'a mut Map>,
    T::Error: Into<Error>,
{
    let map = ebpf.map_mut(name).ok_or(Error::MissingEbpfMap)?;
    T::try_from(map).map_err(Into::into)
}

pub(crate) fn map_owned<T>(ebpf: &mut Ebpf, name: &str) -> Result<T, Error>
where
    T: TryFrom<Map>,
    T::Error: Into<Error>,
{
    let map = ebpf.take_map(name).ok_or(Error::MissingEbpfMap)?;
    T::try_from(map).map_err(Into::into)
}

pub(crate) fn array_mut<'a, T: Pod>(
    ebpf: &'a mut Ebpf,
    name: &str,
) -> Result<Array<&'a mut MapData, T>, Error> {
    map_mut(ebpf, name)
}

pub(crate) fn set_array<T: Pod>(
    ebpf: &mut Ebpf,
    name: &str,
    index: u32,
    value: T,
) -> Result<(), Error> {
    let mut map: Array<&mut MapData, T> = map_mut(ebpf, name)?;
    map.set(index, value, 0)?;
    Ok(())
}

pub(crate) fn clear_array<T: Pod + Default>(
    ebpf: &mut Ebpf,
    name: &str,
    index: u32,
) -> Result<(), Error> {
    let mut map = array_mut(ebpf, name)?;
    map.set(index, T::default(), 0).map_err(Into::into)
}

pub(crate) fn xdp_program<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp, Error> {
    let program: &mut Xdp = ebpf
        .program_mut(name)
        .ok_or(Error::MissingEbpfProgram)?
        .try_into()?;
    Ok(program)
}
