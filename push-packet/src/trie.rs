use aya::maps::{LpmTrie, MapData};

pub struct Ipv4Trie(LpmTrie<MapData, u32, u32>);

pub struct Ipv6Trie(LpmTrie<MapData, [u8; 16], u32>);
