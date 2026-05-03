// Documented safe casts

pub(crate) fn usize_to_rule_index(index: usize) -> u32 {
    index
        .try_into()
        .expect("engine capacity bounds rules to fit in u32")
}

pub(crate) fn rule_index_to_usize(index: u32) -> usize {
    index.try_into().expect("Linux requires usize >= u32")
}

pub(crate) fn packet_len_to_u32(len: usize) -> u32 {
    len.try_into().expect("packet length fits in u32")
}

pub(crate) fn packet_len_to_usize(len: u32) -> usize {
    len.try_into().expect("Linux requires usize >= u32")
}

pub(crate) fn umem_offset_to_usize(address: u64) -> usize {
    address
        .try_into()
        .expect("UMEM offset is <= usize on targets")
}

pub(crate) fn xsk_config_usize(count: u32) -> usize {
    count
        .try_into()
        .expect("all socket config values must fit in usize")
}
