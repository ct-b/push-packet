use aya::{
    Pod,
    maps::{Array, MapData},
};

use crate::Error;

pub(crate) trait ArrayExt<V> {
    fn clear(&mut self, index: u32, name: &str) -> Result<(), Error>;
}

impl<V: Default + Pod> ArrayExt<V> for Array<MapData, V> {
    fn clear(&mut self, index: u32, name: &str) -> Result<(), Error> {
        self.set(index, V::default(), 0)
            .map_err(|e| Error::map(name, e))?;
        Ok(())
    }
}
