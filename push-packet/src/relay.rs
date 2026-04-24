use aya::{
    Ebpf, EbpfLoader,
    maps::{MapData, ProgramArray, RingBuf},
};
use push_packet_common::RING_BUF_NAME;

use crate::{
    Error,
    channels::copy,
    ebpf::{map_owned, xdp_program},
    filter::Filter,
    loader::Loader,
    rules::Action,
    tap::{CopyConfig, RouteConfig},
};

const COPY_PROGRAM_NAME: &str = "copy_packet";
const PROGRAM_ARRAY_NAME: &str = "PROGRAM_ARRAY";

#[derive(Default)]
pub(crate) struct RelayLoader {
    copy_enabled: bool,
    route_enabled: bool,
    ring_buf_size: Option<u32>,
}

impl RelayLoader {
    pub fn new(copy_config: &CopyConfig, route_config: &RouteConfig, filter: &Filter) -> Self {
        let mut copy_enabled = copy_config.force_enabled;
        let mut route_enabled = route_config.force_enabled;
        for (_, rule) in filter.iter_rules() {
            if route_enabled && copy_enabled {
                break;
            }
            match rule.action {
                Action::Route => route_enabled = true,
                Action::Copy { .. } => copy_enabled = true,
                _ => (),
            }
        }

        Self {
            copy_enabled,
            route_enabled,
            ring_buf_size: copy_config.ring_buf_size,
        }
    }
}

impl Loader for RelayLoader {
    type Component = Relay;

    fn configure(&self, ebpf_loader: &mut EbpfLoader) -> Result<(), Error> {
        if let Some(size) = self.ring_buf_size {
            ebpf_loader.map_max_entries(RING_BUF_NAME, size);
        }
        Ok(())
    }

    fn load(self, ebpf: &mut Ebpf) -> Result<Self::Component, Error> {
        if !self.copy_enabled && !self.route_enabled {
            return Ok(Relay {
                copy_receiver: None,
                program_array: None,
                copy_enabled: false,
                route_enabled: false,
            });
        }

        let mut program_array: ProgramArray<_> = map_owned(ebpf, PROGRAM_ARRAY_NAME)?;

        let copy_receiver = if self.copy_enabled {
            let program = xdp_program(ebpf, COPY_PROGRAM_NAME)?;
            program.load()?;
            program_array.set(0, program.fd()?, 0)?;

            let ring_buf: RingBuf<MapData> = map_owned(ebpf, RING_BUF_NAME)?;
            Some(ring_buf.into())
        } else {
            None
        };

        Ok(Relay {
            copy_enabled: self.copy_enabled,
            route_enabled: self.route_enabled,
            program_array: Some(program_array),
            copy_receiver,
        })
    }
}

pub(crate) struct Relay {
    pub copy_enabled: bool,
    pub route_enabled: bool,
    pub copy_receiver: Option<copy::Receiver>,
    #[allow(unused)]
    pub program_array: Option<ProgramArray<MapData>>,
}
