use std::ops::Deref;

use aya::maps::ring_buf::RingBufItem;

use crate::rules::RuleId;

pub struct CopyEvent<'a>(RingBufItem<'a>);

impl<'a> From<RingBufItem<'a>> for CopyEvent<'a> {
    fn from(value: RingBufItem<'a>) -> Self {
        Self(value)
    }
}

impl<'a> CopyEvent<'a> {
    pub fn take(&self) -> u32 {
        u32::from_ne_bytes(self.0[0..4].try_into().unwrap())
    }

    pub fn rule_id(&self) -> RuleId {
        RuleId(u32::from_ne_bytes(self.0[4..8].try_into().unwrap()) as usize)
    }

    pub fn len(&self) -> u32 {
        u32::from_ne_bytes(self.0[8..12].try_into().unwrap())
    }

    pub fn data(&self) -> &[u8] {
        &self.0[12..(12 + self.len() as usize)]
    }
}
