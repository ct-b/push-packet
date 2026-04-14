/// An action to take on matching rules.
///
/// `Action::Pass` instructs the kernel to do nothing, and should be used to override other rules.
/// `Action::Drop` drops the packet.
/// `Action::Copy` copies the packet to userspace, but it is processed as normal by the kernel. The
/// `take` field optionally limits the copied data to a certain number of bytes.
/// `Action::Route` routes the packet to userspace.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum Action {
    Pass,
    Drop,
    Copy { take: Option<u16> },
    Route,
}

impl Action {
    pub fn into_common_action(self) -> (push_packet_common::Action, Option<u16>) {
        match self {
            Self::Pass => (push_packet_common::Action::Pass, None),
            Self::Drop => (push_packet_common::Action::Drop, None),
            Self::Copy { take } => (push_packet_common::Action::Copy, take),
            Self::Route => (push_packet_common::Action::Route, None),
        }
    }
}
