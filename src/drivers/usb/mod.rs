//! USB drivers for CrabEFI
//!
//! This module provides USB host controller and device class drivers.

pub mod mass_storage;
pub mod xhci;

pub use mass_storage::UsbMassStorage;
pub use xhci::{get_controller, init, XhciController, XhciError};

/// Initialize all USB subsystems
pub fn init_all() {
    xhci::init();
}
