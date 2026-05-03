#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("the channel cannot be polled.")]
    Disconnected,
    #[error("there is no available item in the socket or buffer")]
    Empty,
    #[error("poll on channel fd failed")]
    Poll(#[source] nix::errno::Errno),
}
