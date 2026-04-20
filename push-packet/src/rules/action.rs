/// An action to take on matching rules.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum Action {
    /// Instructs the kernel to do nothing, and should be used to override other rules.
    Pass,
    /// Drops the packet.
    Drop,
    /// Copies the packet to userspace, but it is processed as normal by the kernel. The `take`
    /// field optionally limits the copied data to a certain number of bytes.
    Copy {
        /// Maximum bytes to copy from each packet. `None` copies the entire packet.
        take: Option<u32>,
    },
    /// Routes the packet to userspace.
    Route,
}

impl Action {
    pub(crate) fn into_common_action(self) -> (push_packet_common::Action, Option<u32>) {
        match self {
            Self::Pass => (push_packet_common::Action::Pass, None),
            Self::Drop => (push_packet_common::Action::Drop, None),
            Self::Copy { take } => (push_packet_common::Action::Copy, take),
            Self::Route => (push_packet_common::Action::Route, None),
        }
    }
}
