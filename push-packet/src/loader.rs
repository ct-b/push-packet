use aya::{Ebpf, EbpfLoader};

use crate::Error;

/// This trait enforces organizational principles for configuring and loading Ebpf components. This
/// should be implemented on configuration structs, in a builder pattern, using `load(self, ebpf:
/// &mut Ebpf)` instead of the common `build(self)`.
pub trait Loader {
    /// The component that is loaded.
    type Component;

    /// Optionally set map max entries or otherwise interact with the [`EbpfLoader`].
    ///
    /// # Errors
    /// Returns an [`Error`] if the configuration fails.
    fn configure(&self, _ebpf_loader: &mut EbpfLoader) -> Result<(), Error> {
        Ok(())
    }
    /// Loads the [`Self::Component`]
    ///
    /// # Errors
    /// Returns as [`Error`] if the [`Self::Component`] can not be loaded.
    fn load(self, ebpf: &mut Ebpf) -> Result<Self::Component, Error>;
}
