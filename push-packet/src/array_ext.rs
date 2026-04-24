use aya::{
    Pod,
    maps::{Array, MapData},
};

use crate::Error;

pub(crate) trait ArrayExt<V> {
    fn clear(&mut self, index: u32) -> Result<(), Error>;
}

impl<V: Default + Pod> ArrayExt<V> for Array<MapData, V> {
    fn clear(&mut self, index: u32) -> Result<(), Error> {
        self.set(index, V::default(), 0)?;
        Ok(())
    }
}
