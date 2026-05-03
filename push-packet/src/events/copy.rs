//! Defines events for [`crate::rules::Action::Copy`].
use std::mem::offset_of;

use aya::maps::ring_buf::RingBufItem;
use push_packet_common::CopyArgs;

use crate::{cast, rules::RuleId};

/// A packet event captured with [`crate::rules::Action::Copy`]. This will block the ring buffer
/// until it is [dropped](`Drop`), so it should be consumed quickly. Calling
/// [`CopyEvent::into_owned`] returns an [`OwnedCopyEvent`], dropping the underlying [`RingBufItem`]
/// at the cost of a copy.
#[derive(Debug)]
pub struct CopyEvent<'a>(RingBufItem<'a>);

impl AsRef<[u8]> for CopyEvent<'_> {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl<'a> From<RingBufItem<'a>> for CopyEvent<'a> {
    fn from(value: RingBufItem<'a>) -> Self {
        Self(value)
    }
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(data[offset..offset + 4].try_into().expect("4 bytes"))
}

fn parse_take(data: &[u8]) -> Option<u32> {
    match read_u32(data, offset_of!(CopyArgs, take)) {
        0 => None,
        n => Some(n),
    }
}

fn parse_rule_id(data: &[u8]) -> RuleId {
    let rule_id = read_u32(data, offset_of!(CopyArgs, rule_id));
    RuleId(rule_id)
}

fn parse_packet_len(data: &[u8]) -> u32 {
    read_u32(data, offset_of!(CopyArgs, packet_len))
}

fn parse_data_len(data: &[u8]) -> u32 {
    parse_take(data).unwrap_or(parse_packet_len(data))
}

fn parse_data(data: &[u8]) -> &[u8] {
    let header_len = core::mem::size_of::<CopyArgs>();
    &data[header_len..(header_len + cast::packet_len_to_usize(parse_data_len(data)))]
}

impl CopyEvent<'_> {
    /// If set, returns the number of bytes copied. This may be lower than the originally specified
    /// value, if the packet is less than the original take.
    #[must_use]
    pub fn take(&self) -> Option<u32> {
        parse_take(&self.0)
    }

    /// Returns the [`RuleId`] that the packet matched on
    #[must_use]
    pub fn rule_id(&self) -> RuleId {
        parse_rule_id(&self.0)
    }

    /// Returns the length of the packet data, before take is applied
    #[must_use]
    pub fn packet_len(&self) -> u32 {
        parse_packet_len(&self.0)
    }

    /// Returns the length of the data, after take has been applied
    #[must_use]
    pub fn data_len(&self) -> u32 {
        parse_data_len(&self.0)
    }

    /// Returns the raw data copied from the packet
    #[must_use]
    pub fn data(&self) -> &[u8] {
        parse_data(&self.0)
    }

    /// Converts to an [`OwnedCopyEvent`], dropping the underlying [`RingBufItem`] which frees
    /// capacity for successive writes.
    #[must_use]
    pub fn into_owned(self) -> OwnedCopyEvent {
        let take = self.take();
        let rule_id = self.rule_id();
        let packet_len = self.packet_len();
        let data = self.data().into();
        OwnedCopyEvent {
            take,
            rule_id,
            packet_len,
            data,
        }
    }
}

/// An owned copy event contains a Box containing copied data from the [`RingBufItem`]. This allows
/// working with the data why freeing up capacity for the [`aya::maps::RingBuf`].
#[derive(Debug, Clone)]
pub struct OwnedCopyEvent {
    take: Option<u32>,
    rule_id: RuleId,
    packet_len: u32,
    data: Box<[u8]>,
}

impl AsRef<[u8]> for OwnedCopyEvent {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl OwnedCopyEvent {
    /// If set, returns the number of bytes copied. This may be lower than the originally specified
    /// value, if the packet is less than the original take.
    #[must_use]
    pub fn take(&self) -> Option<u32> {
        self.take
    }

    /// Returns the [`RuleId`] that the packet matched on
    #[must_use]
    pub fn rule_id(&self) -> RuleId {
        self.rule_id
    }

    /// Returns the length of the packet data, before take is applied
    #[must_use]
    pub fn packet_len(&self) -> u32 {
        self.packet_len
    }

    /// Returns the length of the data, after take has been applied
    #[must_use]
    pub fn data_len(&self) -> u32 {
        self.take.unwrap_or(self.packet_len)
    }

    /// Returns the raw data copied from the packet
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        events::copy::{parse_packet_len, parse_rule_id, parse_take},
        rules::RuleId,
    };

    fn make_packet(take: u32, rule_id: u32, packet_len: u32, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![];
        packet.extend_from_slice(&take.to_ne_bytes());
        packet.extend_from_slice(&rule_id.to_ne_bytes());
        packet.extend_from_slice(&packet_len.to_ne_bytes());
        packet.extend_from_slice(data);
        packet
    }

    #[test]
    fn zero_take_is_none() {
        let packet = make_packet(0, 0, 100, &[0]);
        assert_eq!(parse_take(&packet), None);
    }

    #[test]
    fn nonzero_take_is_some() {
        let packet = make_packet(10, 0, 100, &[0]);
        assert_eq!(parse_take(&packet), Some(10));
    }

    #[test]
    fn rule_id_parses() {
        let packet = make_packet(0, 4, 100, &[0]);
        assert_eq!(parse_rule_id(&packet), RuleId(4));
    }

    #[test]
    fn packet_len_parses() {
        let packet = make_packet(0, 0, 100, &[0]);
        assert_eq!(parse_packet_len(&packet), 100);
    }
}
