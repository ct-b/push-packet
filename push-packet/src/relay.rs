use aya::{
    Ebpf, EbpfLoader,
    maps::{MapData, ProgramArray, RingBuf},
};
use push_packet_common::{DEFAULT_RING_BUF_SIZE, RING_BUF_NAME};

use crate::{
    Error, Interface,
    af_xdp::{AfXdpSocket, AfXdpSocketLoader},
    channels::copy,
    ebpf::{load_xdp_program, map_owned},
    filter::Filter,
    loader::Loader,
    rules::Action,
    tap::{CopyConfig, RouteConfig},
};

const COPY_PROGRAM_NAME: &str = "copy_packet";
const ROUTE_PROGRAM_NAME: &str = "route_packet";
const PROGRAM_ARRAY_NAME: &str = "PROGRAM_ARRAY";

#[derive(Default)]
pub(crate) struct RelayLoader {
    copy_enabled: bool,
    route_enabled: bool,
    ring_buf_size: u32,
    af_xdp_loader: Option<AfXdpSocketLoader>,
}

impl RelayLoader {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        copy_config: CopyConfig,
        route_config: RouteConfig,
        filter: &Filter,
        interface: &Interface,
    ) -> Self {
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

        let RouteConfig {
            umem_config,
            socket_config,
            frame_count,
            queue_id,
            ..
        } = route_config;

        let af_xdp_loader = route_enabled.then(|| {
            AfXdpSocketLoader::new(
                umem_config,
                socket_config,
                frame_count,
                interface.index(),
                queue_id,
            )
        });
        Self {
            copy_enabled,
            route_enabled,
            ring_buf_size: copy_config.ring_buf_size,
            af_xdp_loader,
        }
    }
}

impl Loader for RelayLoader {
    type Component = Relay;

    fn configure(&self, ebpf_loader: &mut EbpfLoader) -> Result<(), Error> {
        if self.ring_buf_size != DEFAULT_RING_BUF_SIZE {
            ebpf_loader.set_max_entries(RING_BUF_NAME, self.ring_buf_size);
        }
        if let Some(af_xdp_loader) = &self.af_xdp_loader {
            af_xdp_loader.configure(ebpf_loader)?;
        }
        ebpf_loader.set_max_entries(PROGRAM_ARRAY_NAME, 2);
        Ok(())
    }

    fn load(self, ebpf: &mut Ebpf) -> Result<Self::Component, Error> {
        if !self.copy_enabled && !self.route_enabled {
            return Ok(Relay::default());
        }

        let mut program_array: ProgramArray<_> = map_owned(ebpf, PROGRAM_ARRAY_NAME)?;

        let copy_receiver = if self.copy_enabled {
            let program = load_xdp_program(ebpf, COPY_PROGRAM_NAME)?;
            let fd = program.fd().map_err(Error::FileDescriptor)?;
            program_array
                .set(0, fd, 0)
                .map_err(|e| Error::map(PROGRAM_ARRAY_NAME, e))?;

            let ring_buf: RingBuf<MapData> = map_owned(ebpf, RING_BUF_NAME)?;
            Some(ring_buf.into())
        } else {
            None
        };

        let af_xdp_socket = if self.route_enabled {
            let program = load_xdp_program(ebpf, ROUTE_PROGRAM_NAME)?;
            let fd = program.fd().map_err(Error::FileDescriptor)?;
            program_array
                .set(1, fd, 0)
                .map_err(|e| Error::map(PROGRAM_ARRAY_NAME, e))?;
            let loader = self
                .af_xdp_loader
                .expect("AfXdpSocketLoader must exist if route_enabled");
            Some(loader.load(ebpf)?)
        } else {
            None
        };

        Ok(Relay {
            copy_enabled: self.copy_enabled,
            route_enabled: self.route_enabled,
            program_array: Some(program_array),
            copy_receiver,
            af_xdp_socket,
        })
    }
}

#[derive(Default)]
pub(crate) struct Relay {
    pub copy_enabled: bool,
    pub route_enabled: bool,
    pub copy_receiver: Option<copy::Receiver>,
    pub af_xdp_socket: Option<AfXdpSocket>,
    #[allow(unused)]
    pub program_array: Option<ProgramArray<MapData>>,
}
