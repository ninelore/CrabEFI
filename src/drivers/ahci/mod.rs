//! AHCI (Advanced Host Controller Interface) driver for CrabEFI
//!
//! This module provides a minimal AHCI driver for reading from SATA devices.
//! It implements the basic AHCI command set needed for booting.

use crate::drivers::pci::{self, PciDevice};
use crate::efi;
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use spin::Mutex;

/// AHCI HBA (Host Bus Adapter) memory registers
mod regs {
    /// Host Capabilities
    pub const CAP: u32 = 0x00;
    /// Global Host Control
    pub const GHC: u32 = 0x04;
    /// Interrupt Status
    pub const IS: u32 = 0x08;
    /// Ports Implemented
    pub const PI: u32 = 0x0C;
    /// Version
    pub const VS: u32 = 0x10;
    /// Command Completion Coalescing Control
    pub const CCC_CTL: u32 = 0x14;
    /// Command Completion Coalescing Ports
    pub const CCC_PORTS: u32 = 0x18;
    /// Enclosure Management Location
    pub const EM_LOC: u32 = 0x1C;
    /// Enclosure Management Control
    pub const EM_CTL: u32 = 0x20;
    /// Host Capabilities Extended
    pub const CAP2: u32 = 0x24;
    /// BIOS/OS Handoff Control and Status
    pub const BOHC: u32 = 0x28;

    /// Port registers base offset
    pub const PORT_BASE: u32 = 0x100;
    /// Port register block size
    pub const PORT_SIZE: u32 = 0x80;
}

/// AHCI Port registers (relative to port base)
mod port_regs {
    /// Port Command List Base Address (low)
    pub const CLB: u32 = 0x00;
    /// Port Command List Base Address (high)
    pub const CLBU: u32 = 0x04;
    /// Port FIS Base Address (low)
    pub const FB: u32 = 0x08;
    /// Port FIS Base Address (high)
    pub const FBU: u32 = 0x0C;
    /// Port Interrupt Status
    pub const IS: u32 = 0x10;
    /// Port Interrupt Enable
    pub const IE: u32 = 0x14;
    /// Port Command and Status
    pub const CMD: u32 = 0x18;
    /// Port Task File Data
    pub const TFD: u32 = 0x20;
    /// Port Signature
    pub const SIG: u32 = 0x24;
    /// Port Serial ATA Status
    pub const SSTS: u32 = 0x28;
    /// Port Serial ATA Control
    pub const SCTL: u32 = 0x2C;
    /// Port Serial ATA Error
    pub const SERR: u32 = 0x30;
    /// Port Serial ATA Active
    pub const SACT: u32 = 0x34;
    /// Port Command Issue
    pub const CI: u32 = 0x38;
    /// Port Serial ATA Notification
    pub const SNTF: u32 = 0x3C;
    /// Port FIS-based Switching Control
    pub const FBS: u32 = 0x40;
}

/// GHC register bits
mod ghc {
    /// HBA Reset
    pub const HR: u32 = 1 << 0;
    /// Interrupt Enable
    pub const IE: u32 = 1 << 1;
    /// AHCI Enable
    pub const AE: u32 = 1 << 31;
}

/// Port CMD register bits
mod port_cmd {
    /// Start (command list processing)
    pub const ST: u32 = 1 << 0;
    /// Spin-Up Device
    pub const SUD: u32 = 1 << 1;
    /// Power On Device
    pub const POD: u32 = 1 << 2;
    /// Command List Override
    pub const CLO: u32 = 1 << 3;
    /// FIS Receive Enable
    pub const FRE: u32 = 1 << 4;
    /// Current Command Slot
    pub const CCS_SHIFT: u32 = 8;
    pub const CCS_MASK: u32 = 0x1F;
    /// Mechanical Presence Switch State
    pub const MPSS: u32 = 1 << 13;
    /// FIS Receive Running
    pub const FR: u32 = 1 << 14;
    /// Command List Running
    pub const CR: u32 = 1 << 15;
    /// Cold Presence State
    pub const CPS: u32 = 1 << 16;
    /// Port Multiplier Attached
    pub const PMA: u32 = 1 << 17;
    /// Hot Plug Capable Port
    pub const HPCP: u32 = 1 << 18;
    /// Mechanical Presence Switch Attached
    pub const MPSP: u32 = 1 << 19;
    /// Cold Presence Detection
    pub const CPD: u32 = 1 << 20;
    /// External SATA Port
    pub const ESP: u32 = 1 << 21;
    /// FIS-based Switching Capable Port
    pub const FBSCP: u32 = 1 << 22;
    /// Automatic Partial to Slumber Transitions Enabled
    pub const APSTE: u32 = 1 << 23;
    /// Aggressive Slumber/Partial
    pub const ASP: u32 = 1 << 27;
    /// Interface Communication Control
    pub const ICC_SHIFT: u32 = 28;
    pub const ICC_MASK: u32 = 0xF;
}

/// Port TFD (Task File Data) bits
mod port_tfd {
    /// Status: Error
    pub const STS_ERR: u32 = 1 << 0;
    /// Status: Data Request
    pub const STS_DRQ: u32 = 1 << 3;
    /// Status: Busy
    pub const STS_BSY: u32 = 1 << 7;
}

/// Port Signature values
mod signatures {
    /// ATA device (hard drive)
    pub const SATA_SIG_ATA: u32 = 0x00000101;
    /// ATAPI device (CD/DVD)
    pub const SATA_SIG_ATAPI: u32 = 0xEB140101;
    /// SEMB (Enclosure Management Bridge)
    pub const SATA_SIG_SEMB: u32 = 0xC33C0101;
    /// Port multiplier
    pub const SATA_SIG_PM: u32 = 0x96690101;
}

/// FIS Types
mod fis_type {
    /// Register FIS - Host to Device
    pub const REG_H2D: u8 = 0x27;
    /// Register FIS - Device to Host
    pub const REG_D2H: u8 = 0x34;
    /// DMA Activate FIS - Device to Host
    pub const DMA_ACT: u8 = 0x39;
    /// DMA Setup FIS - Bidirectional
    pub const DMA_SETUP: u8 = 0x41;
    /// Data FIS - Bidirectional
    pub const DATA: u8 = 0x46;
    /// BIST Activate FIS - Bidirectional
    pub const BIST: u8 = 0x58;
    /// PIO Setup FIS - Device to Host
    pub const PIO_SETUP: u8 = 0x5F;
    /// Set Device Bits FIS - Device to Host
    pub const DEV_BITS: u8 = 0xA1;
}

/// ATA Commands
mod ata_cmd {
    /// Read DMA Extended (48-bit LBA)
    pub const READ_DMA_EXT: u8 = 0x25;
    /// Write DMA Extended (48-bit LBA)
    pub const WRITE_DMA_EXT: u8 = 0x35;
    /// Identify Device
    pub const IDENTIFY: u8 = 0xEC;
    /// Set Features
    pub const SET_FEATURES: u8 = 0xEF;
}

/// Command Header (32 bytes)
/// Layout per AHCI spec 1.3.1:
/// - DW0: bits 0-4 = CFL, bit 5 = A, bit 6 = W, bit 7 = P, bit 8 = R,
///        bit 9 = B, bit 10 = C, bits 16-31 = PRDTL
/// - DW1: PRDBC (PRD Byte Count, updated by HBA)
/// - DW2: CTBA (Command Table Base Address, low 32 bits)
/// - DW3: CTBAU (Command Table Base Address, upper 32 bits)
/// - DW4-7: Reserved
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CommandHeader {
    /// DW0: Command FIS Length (0-4), flags (5-15), PRDTL (16-31)
    pub dw0: u32,
    /// DW1: Physical Region Descriptor Byte Count (updated by HBA)
    pub prdbc: u32,
    /// DW2: Command Table Base Address (low)
    pub ctba: u32,
    /// DW3: Command Table Base Address (high)
    pub ctbau: u32,
    /// DW4-7: Reserved
    pub reserved: [u32; 4],
}

impl CommandHeader {
    /// Set command FIS length (in DWORDs)
    fn set_cfl(&mut self, len: u8) {
        self.dw0 = (self.dw0 & !0x1F) | ((len as u32) & 0x1F);
    }

    /// Set write bit
    fn set_write(&mut self, write: bool) {
        if write {
            self.dw0 |= 1 << 6;
        } else {
            self.dw0 &= !(1 << 6);
        }
    }

    /// Set PRDT length (stored in upper 16 bits of DW0)
    fn set_prdtl(&mut self, len: u16) {
        self.dw0 = (self.dw0 & 0xFFFF) | ((len as u32) << 16);
    }

    /// Set command table address
    fn set_ctba(&mut self, addr: u64) {
        self.ctba = addr as u32;
        self.ctbau = (addr >> 32) as u32;
    }
}

/// FIS Register - Host to Device (20 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FisRegH2D {
    /// FIS Type (0x27)
    pub fis_type: u8,
    /// Port multiplier, Command bit
    pub pm_c: u8,
    /// Command register
    pub command: u8,
    /// Feature register (low)
    pub feature_l: u8,

    /// LBA low (bits 0-7)
    pub lba0: u8,
    /// LBA mid (bits 8-15)
    pub lba1: u8,
    /// LBA high (bits 16-23)
    pub lba2: u8,
    /// Device register
    pub device: u8,

    /// LBA (bits 24-31)
    pub lba3: u8,
    /// LBA (bits 32-39)
    pub lba4: u8,
    /// LBA (bits 40-47)
    pub lba5: u8,
    /// Feature register (high)
    pub feature_h: u8,

    /// Count (low)
    pub count_l: u8,
    /// Count (high)
    pub count_h: u8,
    /// Isochronous command completion
    pub icc: u8,
    /// Control register
    pub control: u8,

    /// Reserved
    pub reserved: [u8; 4],
}

impl FisRegH2D {
    fn new() -> Self {
        Self {
            fis_type: fis_type::REG_H2D,
            pm_c: 0x80, // Command bit set
            ..Default::default()
        }
    }

    fn set_command(&mut self, cmd: u8) {
        self.command = cmd;
    }

    fn set_lba(&mut self, lba: u64) {
        self.lba0 = (lba & 0xFF) as u8;
        self.lba1 = ((lba >> 8) & 0xFF) as u8;
        self.lba2 = ((lba >> 16) & 0xFF) as u8;
        self.lba3 = ((lba >> 24) & 0xFF) as u8;
        self.lba4 = ((lba >> 32) & 0xFF) as u8;
        self.lba5 = ((lba >> 40) & 0xFF) as u8;
        self.device = 0x40; // LBA mode
    }

    fn set_count(&mut self, count: u16) {
        self.count_l = (count & 0xFF) as u8;
        self.count_h = ((count >> 8) & 0xFF) as u8;
    }
}

/// Physical Region Descriptor Table Entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct PrdtEntry {
    /// Data Base Address (low)
    pub dba: u32,
    /// Data Base Address (high)
    pub dbau: u32,
    /// Reserved
    pub reserved: u32,
    /// Byte Count (bit 0 = interrupt on completion, bits 1-21 = byte count - 1)
    pub dbc: u32,
}

impl PrdtEntry {
    fn set_address(&mut self, addr: u64) {
        self.dba = addr as u32;
        self.dbau = (addr >> 32) as u32;
    }

    fn set_byte_count(&mut self, count: u32, interrupt: bool) {
        self.dbc = (count - 1) | if interrupt { 1u32 << 31 } else { 0 };
    }
}

/// Command Table (varies by PRDT length, minimum 128 bytes)
/// Layout: CFIS (64) + ACMD (16) + Reserved (48) + PRDT entries (16 each)
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (64 bytes)
    pub cfis: [u8; 64],
    /// ATAPI Command (16 bytes)
    pub acmd: [u8; 16],
    /// Reserved (48 bytes)
    pub reserved: [u8; 48],
    /// PRDT entries (up to 65535, but we only use a few)
    pub prdt: [PrdtEntry; 8],
}

impl Default for CommandTable {
    fn default() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            reserved: [0; 48],
            prdt: [PrdtEntry::default(); 8],
        }
    }
}

/// Received FIS structure (256 bytes)
#[repr(C, align(256))]
#[derive(Clone, Copy)]
pub struct ReceivedFis {
    /// DMA Setup FIS
    pub dsfis: [u8; 28],
    pub reserved0: [u8; 4],
    /// PIO Setup FIS
    pub psfis: [u8; 20],
    pub reserved1: [u8; 12],
    /// D2H Register FIS
    pub rfis: [u8; 20],
    pub reserved2: [u8; 4],
    /// Set Device Bits FIS
    pub sdbfis: [u8; 8],
    /// Unknown FIS
    pub ufis: [u8; 64],
    pub reserved3: [u8; 96],
}

impl Default for ReceivedFis {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// AHCI Port state
pub struct AhciPort {
    /// Port number
    pub port_num: u8,
    /// MMIO base for port registers
    port_base: u64,
    /// Command list (32 entries, 1KB)
    cmd_list: *mut CommandHeader,
    /// Received FIS (256 bytes)
    received_fis: *mut ReceivedFis,
    /// Command tables (one per command slot)
    cmd_tables: [*mut CommandTable; 32],
    /// Device type
    pub device_type: DeviceType,
    /// Sector count (for SATA drives)
    pub sector_count: u64,
    /// Sector size
    pub sector_size: u32,
}

/// Device type detected on port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    None,
    Sata,
    Satapi,
    Semb,
    PortMultiplier,
}

/// AHCI Controller
pub struct AhciController {
    /// MMIO base address
    mmio_base: u64,
    /// Number of command slots
    num_cmd_slots: u8,
    /// Number of ports
    num_ports: u8,
    /// Ports implemented bitmap
    ports_implemented: u32,
    /// Active ports
    ports: heapless::Vec<AhciPort, 32>,
}

/// AHCI error type
#[derive(Debug)]
pub enum AhciError {
    /// No device on port
    NoDevice,
    /// Port not ready
    PortNotReady,
    /// Command failed
    CommandFailed,
    /// Timeout
    Timeout,
    /// Allocation failed
    AllocationFailed,
    /// Invalid parameter
    InvalidParameter,
}

impl AhciController {
    /// Create a new AHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, AhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(AhciError::NoDevice)?;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capabilities
        let cap = Self::read_reg_static(mmio_base, regs::CAP);
        let num_cmd_slots = (((cap >> 8) & 0x1F) + 1) as u8;
        let num_ports = ((cap & 0x1F) + 1) as u8;
        let ports_implemented = Self::read_reg_static(mmio_base, regs::PI);

        // Read version
        let vs = Self::read_reg_static(mmio_base, regs::VS);
        let major = (vs >> 16) & 0xFFFF;
        let minor = vs & 0xFFFF;
        log::info!("AHCI version: {}.{}", major, minor);
        log::debug!(
            "AHCI CAP: {:#x}, ports={}, cmd_slots={}",
            cap,
            num_ports,
            num_cmd_slots
        );

        // Enable AHCI mode
        let ghc = Self::read_reg_static(mmio_base, regs::GHC);
        Self::write_reg_static(mmio_base, regs::GHC, ghc | ghc::AE);

        // Perform BIOS/OS handoff if needed
        let cap2 = Self::read_reg_static(mmio_base, regs::CAP2);
        if cap2 & 0x1 != 0 {
            // BOH supported
            let bohc = Self::read_reg_static(mmio_base, regs::BOHC);
            if bohc & 0x1 != 0 {
                // BIOS owns the HBA
                log::debug!("Performing BIOS/OS handoff...");
                Self::write_reg_static(mmio_base, regs::BOHC, bohc | 0x2); // Set OOS
                for _ in 0..100000 {
                    let bohc = Self::read_reg_static(mmio_base, regs::BOHC);
                    if bohc & 0x1 == 0 {
                        break;
                    }
                }
            }
        }

        let mut controller = Self {
            mmio_base,
            num_cmd_slots,
            num_ports,
            ports_implemented,
            ports: heapless::Vec::new(),
        };

        // Initialize ports
        controller.init_ports()?;

        Ok(controller)
    }

    fn read_reg_static(mmio_base: u64, offset: u32) -> u32 {
        unsafe { ptr::read_volatile((mmio_base + offset as u64) as *const u32) }
    }

    fn write_reg_static(mmio_base: u64, offset: u32, value: u32) {
        unsafe { ptr::write_volatile((mmio_base + offset as u64) as *mut u32, value) }
    }

    fn read_reg(&self, offset: u32) -> u32 {
        Self::read_reg_static(self.mmio_base, offset)
    }

    fn write_reg(&mut self, offset: u32, value: u32) {
        Self::write_reg_static(self.mmio_base, offset, value)
    }

    fn port_offset(port: u8) -> u32 {
        regs::PORT_BASE + (port as u32) * regs::PORT_SIZE
    }

    fn read_port_reg(&self, port: u8, offset: u32) -> u32 {
        let addr = self.mmio_base + Self::port_offset(port) as u64 + offset as u64;
        unsafe { ptr::read_volatile(addr as *const u32) }
    }

    fn write_port_reg(&mut self, port: u8, offset: u32, value: u32) {
        let addr = self.mmio_base + Self::port_offset(port) as u64 + offset as u64;
        unsafe { ptr::write_volatile(addr as *mut u32, value) }
    }

    /// Initialize all implemented ports
    fn init_ports(&mut self) -> Result<(), AhciError> {
        for port_num in 0..32u8 {
            if self.ports_implemented & (1 << port_num) == 0 {
                continue;
            }

            // Check if device is present
            let ssts = self.read_port_reg(port_num, port_regs::SSTS);
            let det = ssts & 0xF; // Device Detection
            let ipm = (ssts >> 8) & 0xF; // Interface Power Management

            if det != 3 || ipm != 1 {
                // No device or not active
                continue;
            }

            // Device is connected - initialize the port
            match self.init_port(port_num) {
                Ok(port) => {
                    if port.device_type == DeviceType::Sata {
                        log::info!(
                            "AHCI Port {}: SATA drive, {} sectors",
                            port_num,
                            port.sector_count
                        );
                        let _ = self.ports.push(port);
                    } else {
                        log::info!("AHCI Port {}: {:?} device", port_num, port.device_type);
                    }
                }
                Err(e) => {
                    log::error!("Failed to initialize port {}: {:?}", port_num, e);
                }
            }
        }

        log::info!("AHCI: {} SATA ports initialized", self.ports.len());
        Ok(())
    }

    /// Initialize a single port
    fn init_port(&mut self, port_num: u8) -> Result<AhciPort, AhciError> {
        let port_base = self.mmio_base + Self::port_offset(port_num) as u64;

        // Stop command processing
        self.stop_port(port_num)?;

        // Allocate command list (1KB, 1024-byte aligned)
        let cmd_list_addr = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(cmd_list_addr as *mut u8, 0, 4096) };

        // Allocate received FIS (256 bytes, 256-byte aligned)
        let received_fis_addr = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(received_fis_addr as *mut u8, 0, 4096) };

        // Allocate command tables (one per slot, 256-byte aligned each)
        let mut cmd_tables = [ptr::null_mut(); 32];
        let cmd_tables_page = efi::allocate_pages(4).ok_or(AhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(cmd_tables_page as *mut u8, 0, 4096 * 4) };

        for i in 0..self.num_cmd_slots as usize {
            let table_addr = cmd_tables_page + (i * 256) as u64;
            cmd_tables[i] = table_addr as *mut CommandTable;

            // Set command table address in command header
            let header = unsafe { &mut *(cmd_list_addr as *mut CommandHeader).add(i) };
            header.set_ctba(table_addr);
        }

        // Set command list and FIS addresses
        self.write_port_reg(port_num, port_regs::CLB, cmd_list_addr as u32);
        self.write_port_reg(port_num, port_regs::CLBU, (cmd_list_addr >> 32) as u32);
        self.write_port_reg(port_num, port_regs::FB, received_fis_addr as u32);
        self.write_port_reg(port_num, port_regs::FBU, (received_fis_addr >> 32) as u32);

        // Clear error register
        self.write_port_reg(port_num, port_regs::SERR, 0xFFFFFFFF);

        // Clear interrupt status
        self.write_port_reg(port_num, port_regs::IS, 0xFFFFFFFF);

        // Start command processing (this also enables FIS receive)
        self.start_port(port_num)?;

        // Wait for device to become ready (BSY=0, DRQ=0)
        let mut ready = false;
        for _ in 0..1000000u32 {
            let tfd = self.read_port_reg(port_num, port_regs::TFD);
            if tfd & (port_tfd::STS_BSY | port_tfd::STS_DRQ) == 0 {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }

        if !ready {
            let tfd = self.read_port_reg(port_num, port_regs::TFD);
            log::warn!(
                "AHCI Port {}: Device not ready (TFD={:#x}), trying anyway",
                port_num,
                tfd
            );
        }

        // Read the signature
        let sig = self.read_port_reg(port_num, port_regs::SIG);

        // Determine device type from signature
        let device_type = match sig {
            signatures::SATA_SIG_ATA => DeviceType::Sata,
            signatures::SATA_SIG_ATAPI => DeviceType::Satapi,
            signatures::SATA_SIG_SEMB => DeviceType::Semb,
            signatures::SATA_SIG_PM => DeviceType::PortMultiplier,
            0xFFFFFFFF | 0x00000000 => {
                // No valid signature - might still be a SATA device
                DeviceType::Sata
            }
            _ => DeviceType::None,
        };

        let mut port = AhciPort {
            port_num,
            port_base,
            cmd_list: cmd_list_addr as *mut CommandHeader,
            received_fis: received_fis_addr as *mut ReceivedFis,
            cmd_tables,
            device_type,
            sector_count: 0,
            sector_size: 512,
        };

        // Identify the device if it might be a SATA drive
        if device_type == DeviceType::Sata {
            if let Err(e) = self.identify_device(&mut port) {
                log::warn!("AHCI Port {}: IDENTIFY failed: {:?}", port_num, e);
            }
        }

        Ok(port)
    }

    /// Stop command processing on a port
    fn stop_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        let cmd = self.read_port_reg(port_num, port_regs::CMD);

        // Clear ST (Start) bit
        self.write_port_reg(port_num, port_regs::CMD, cmd & !port_cmd::ST);

        // Wait for CR (Command List Running) to clear
        for _ in 0..500000 {
            let cmd = self.read_port_reg(port_num, port_regs::CMD);
            if cmd & port_cmd::CR == 0 {
                break;
            }
        }

        // Clear FRE (FIS Receive Enable) bit
        let cmd = self.read_port_reg(port_num, port_regs::CMD);
        self.write_port_reg(port_num, port_regs::CMD, cmd & !port_cmd::FRE);

        // Wait for FR (FIS Receive Running) to clear
        for _ in 0..500000 {
            let cmd = self.read_port_reg(port_num, port_regs::CMD);
            if cmd & port_cmd::FR == 0 {
                return Ok(());
            }
        }

        Err(AhciError::Timeout)
    }

    /// Start command processing on a port
    fn start_port(&mut self, port_num: u8) -> Result<(), AhciError> {
        // Wait for CR to clear
        for _ in 0..500000 {
            let cmd = self.read_port_reg(port_num, port_regs::CMD);
            if cmd & port_cmd::CR == 0 {
                break;
            }
        }

        // Enable FIS receive
        let cmd = self.read_port_reg(port_num, port_regs::CMD);
        self.write_port_reg(port_num, port_regs::CMD, cmd | port_cmd::FRE);

        // Enable command processing
        let cmd = self.read_port_reg(port_num, port_regs::CMD);
        self.write_port_reg(port_num, port_regs::CMD, cmd | port_cmd::ST);

        Ok(())
    }

    /// Find a free command slot
    fn find_free_slot(&self, port_num: u8) -> Option<u8> {
        let sact = self.read_port_reg(port_num, port_regs::SACT);
        let ci = self.read_port_reg(port_num, port_regs::CI);
        let slots = sact | ci;

        for i in 0..self.num_cmd_slots {
            if slots & (1 << i) == 0 {
                return Some(i);
            }
        }
        None
    }

    /// Issue a command and wait for completion
    fn issue_command(&mut self, port: &AhciPort, slot: u8) -> Result<(), AhciError> {
        fence(Ordering::SeqCst);

        // Issue command
        self.write_port_reg(port.port_num, port_regs::CI, 1 << slot);

        // Wait for completion
        for _ in 0..10000000u32 {
            let ci = self.read_port_reg(port.port_num, port_regs::CI);
            if ci & (1 << slot) == 0 {
                // Check for errors
                let tfd = self.read_port_reg(port.port_num, port_regs::TFD);
                if tfd & (port_tfd::STS_ERR | port_tfd::STS_DRQ) != 0 {
                    log::error!("AHCI command error: TFD={:#x}", tfd);
                    return Err(AhciError::CommandFailed);
                }
                return Ok(());
            }

            // Check for fatal errors
            let is = self.read_port_reg(port.port_num, port_regs::IS);
            if is & (1 << 30) != 0 {
                // Task File Error
                let tfd = self.read_port_reg(port.port_num, port_regs::TFD);
                log::error!("AHCI task file error: TFD={:#x}, IS={:#x}", tfd, is);
                return Err(AhciError::CommandFailed);
            }
        }

        log::error!("AHCI: Command timeout");
        Err(AhciError::Timeout)
    }

    /// Identify a SATA device
    fn identify_device(&mut self, port: &mut AhciPort) -> Result<(), AhciError> {
        let slot = self
            .find_free_slot(port.port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Allocate buffer for identify data (512 bytes)
        let buffer = efi::allocate_pages(1).ok_or(AhciError::AllocationFailed)?;
        unsafe { ptr::write_bytes(buffer as *mut u8, 0, 4096) };

        // Setup command header
        let header = unsafe { &mut *port.cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5); // 5 DWORDs for H2D FIS
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *port.cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ata_cmd::IDENTIFY);

        // Setup PRDT
        table.prdt[0].set_address(buffer);
        table.prdt[0].set_byte_count(512, true);

        // Issue command
        self.issue_command(port, slot)?;

        // Parse identify data
        let identify = unsafe { core::slice::from_raw_parts(buffer as *const u16, 256) };

        // Word 60-61: Total number of user addressable sectors (28-bit LBA)
        let lba28_sectors = (identify[61] as u64) << 16 | identify[60] as u64;

        // Word 100-103: Total number of user addressable sectors (48-bit LBA)
        let lba48_sectors = (identify[103] as u64) << 48
            | (identify[102] as u64) << 32
            | (identify[101] as u64) << 16
            | identify[100] as u64;

        // Use 48-bit if available
        port.sector_count = if lba48_sectors > 0 {
            lba48_sectors
        } else {
            lba28_sectors
        };

        // Word 106: Physical/Logical sector size info
        let sector_info = identify[106];
        if sector_info & (1 << 12) != 0 {
            // Logical sector size is larger than 256 words
            port.sector_size = ((identify[118] as u32) << 16 | identify[117] as u32) * 2;
        } else {
            port.sector_size = 512;
        }

        // Get model number (words 27-46)
        let mut model = [0u8; 40];
        for i in 0..20 {
            let word = identify[27 + i];
            model[i * 2] = (word >> 8) as u8;
            model[i * 2 + 1] = (word & 0xFF) as u8;
        }
        let model_str = core::str::from_utf8(&model).unwrap_or("Unknown").trim();

        log::info!(
            "AHCI Port {}: {} - {} sectors x {} bytes = {} MB",
            port.port_num,
            model_str,
            port.sector_count,
            port.sector_size,
            (port.sector_count * port.sector_size as u64) / (1024 * 1024)
        );

        efi::free_pages(buffer, 1);
        Ok(())
    }

    /// Read sectors from a port
    pub fn read_sectors(
        &mut self,
        port_index: usize,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), AhciError> {
        if port_index >= self.ports.len() {
            return Err(AhciError::InvalidParameter);
        }

        // Extract needed values from port before mutable operations
        let port_num = self.ports[port_index].port_num;
        let cmd_list = self.ports[port_index].cmd_list;
        let cmd_tables = self.ports[port_index].cmd_tables;

        let slot = self
            .find_free_slot(port_num)
            .ok_or(AhciError::PortNotReady)?;

        // Setup command header
        let header = unsafe { &mut *cmd_list.add(slot as usize) };
        header.dw0 = 0;
        header.set_cfl(5); // 5 DWORDs for H2D FIS
        header.set_write(false);
        header.set_prdtl(1);
        header.prdbc = 0;

        // Setup command table
        let table = unsafe { &mut *cmd_tables[slot as usize] };
        *table = CommandTable::default();

        // Setup FIS for READ DMA EXT
        let fis = unsafe { &mut *(table.cfis.as_mut_ptr() as *mut FisRegH2D) };
        *fis = FisRegH2D::new();
        fis.set_command(ata_cmd::READ_DMA_EXT);
        fis.set_lba(start_lba);
        fis.set_count(num_sectors as u16);

        // Setup PRDT
        let byte_count = num_sectors * 512;
        table.prdt[0].set_address(buffer as u64);
        table.prdt[0].set_byte_count(byte_count, true);

        // Issue command - pass port_num instead of port reference
        self.issue_command_by_port(port_num, slot)?;

        Ok(())
    }

    /// Issue a command by port number and wait for completion
    fn issue_command_by_port(&mut self, port_num: u8, slot: u8) -> Result<(), AhciError> {
        fence(Ordering::SeqCst);

        // Issue command
        self.write_port_reg(port_num, port_regs::CI, 1 << slot);

        // Wait for completion
        for _ in 0..10000000 {
            let ci = self.read_port_reg(port_num, port_regs::CI);
            if ci & (1 << slot) == 0 {
                // Check for errors
                let tfd = self.read_port_reg(port_num, port_regs::TFD);
                if tfd & (port_tfd::STS_ERR | port_tfd::STS_DRQ) != 0 {
                    log::error!("AHCI command error: TFD={:#x}", tfd);
                    return Err(AhciError::CommandFailed);
                }
                return Ok(());
            }

            // Check for fatal errors
            let is = self.read_port_reg(port_num, port_regs::IS);
            if is & (1 << 30) != 0 {
                // Task File Error
                let tfd = self.read_port_reg(port_num, port_regs::TFD);
                log::error!("AHCI task file error: TFD={:#x}", tfd);
                return Err(AhciError::CommandFailed);
            }
        }

        Err(AhciError::Timeout)
    }

    /// Get the number of active ports
    pub fn num_active_ports(&self) -> usize {
        self.ports.len()
    }

    /// Get port info
    pub fn get_port(&self, index: usize) -> Option<&AhciPort> {
        self.ports.get(index)
    }
}

/// Wrapper for AHCI controller pointer to implement Send
struct AhciControllerPtr(*mut AhciController);

// SAFETY: We ensure single-threaded access via the Mutex
unsafe impl Send for AhciControllerPtr {}

/// Global list of AHCI controllers
static AHCI_CONTROLLERS: Mutex<heapless::Vec<AhciControllerPtr, 4>> =
    Mutex::new(heapless::Vec::new());

/// Initialize AHCI controllers
pub fn init() {
    log::info!("Initializing AHCI controllers...");

    let ahci_devices = pci::find_ahci_controllers();

    if ahci_devices.is_empty() {
        log::info!("No AHCI controllers found");
        return;
    }

    let mut controllers = AHCI_CONTROLLERS.lock();

    for dev in ahci_devices.iter() {
        match AhciController::new(dev) {
            Ok(controller) => {
                // Box the controller using EFI allocator
                // Calculate required pages: AhciController is large due to heapless::Vec<AhciPort, 32>
                let size = core::mem::size_of::<AhciController>();
                let pages = (size + 4095) / 4096;
                log::debug!(
                    "AHCI: Allocating {} pages ({} bytes) for AhciController",
                    pages,
                    size
                );
                let controller_ptr = efi::allocate_pages(pages as u64);
                if let Some(ptr) = controller_ptr {
                    let controller_box = ptr as *mut AhciController;
                    unsafe {
                        ptr::write(controller_box, controller);
                    }
                    let _ = controllers.push(AhciControllerPtr(controller_box));
                    log::info!("AHCI controller at {} initialized", dev.address);
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to initialize AHCI controller at {}: {:?}",
                    dev.address,
                    e
                );
            }
        }
    }

    log::info!(
        "AHCI initialization complete: {} controllers",
        controllers.len()
    );
}

/// Get an AHCI controller
pub fn get_controller(index: usize) -> Option<&'static mut AhciController> {
    let controllers = AHCI_CONTROLLERS.lock();
    controllers.get(index).map(|ptr| unsafe { &mut *ptr.0 })
}

// Ensure AhciController can be sent between threads
unsafe impl Send for AhciController {}
unsafe impl Send for AhciPort {}
