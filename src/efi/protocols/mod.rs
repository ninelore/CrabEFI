//! EFI Protocol implementations
//!
//! This module contains implementations of the EFI protocols needed for booting.

pub mod console;
pub mod loaded_image;
pub mod simple_file_system;
pub mod unicode_collation;

// TODO: Implement in Phase 3-4
// pub mod block_io;
// pub mod device_path;
// pub mod graphics_output;
