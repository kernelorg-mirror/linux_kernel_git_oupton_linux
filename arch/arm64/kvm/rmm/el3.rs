// SPDX-License-Identifier: GPL-2.0

//! RMM-EL3 Interface.
//!
//! Copyright (c) 2023 Google LLC
//!
//! Based on the TF-A RMM-EL3 Communication Interface Documentation:
//! https://trustedfirmware-a.readthedocs.io/en/latest/components/rmm-el3-comms-spec.html

use core::arch::asm;
use core::convert::TryFrom;

/// Represents the versioning scheme used for the RMM-EL3 interface and Boot
/// Manifest interface.
#[repr(transparent)]
pub struct InterfaceVersion(u32);

impl InterfaceVersion {
    /// Returns the major version
    pub fn major(&self) -> u16 {
        ((self.0 >> 16) & 0x7FFF) as u16
    }

    /// Returns the minor version
    pub fn minor(&self) -> u16 {
        self.0 as u16
    }
}

/// A bank of DRAM in the Non-Secure PAS.
#[repr(C)]
pub struct NsDramBank {
    base: u64,
    size: u64,
}

/// Describes the layout of DRAM in the Non-Secure PAS.
#[repr(C)]
pub struct NsDramInfo {
    num_banks: u64,
    banks: *const NsDramBank,
    checksum: u64,
}

/// Represents v0.2 of the RMM-EL3 Boot Manifest ABI.
#[repr(C)]
pub struct BootManifest {
    version: InterfaceVersion,
    padding: u32,
    plat_data: *const u8,
    ns_dram_info: NsDramInfo,
}

/// Status codes used with the `RMM_BOOT_COMPLETE` SMC call.
pub enum BootCompleteStatusCode {
    /// Successfully booted
    Success = 0,
    /// Unknown error
    ErrUnknown = -1,
    /// RMM does not support the specified boot protocol version
    VersonNotValid = -2,
    /// RMM does not support the specified number of CPUs
    CpusOutOfRange = -3,
    /// ID of the CPU is not supported by the RMM
    CpuIdOutOfRange = -4,
    /// Invalid pointer to shared memory buffer
    InvalidSharedBuffer = -5,
    /// Version reported in the Boot Manifest not supported by the RMM
    ManifestVersionNotSupported = -6,
    /// Error parsing data from the Boot Manifest
    ManifestDataError = -7,
}

/// Issues an `RMM_BOOT_COMPLETE` SMC call with the provided error.
pub fn rmm_boot_complete(rc: BootCompleteStatusCode) {
    const RMM_BOOT_COMPLETE: u32 = 0xC400_01CF;

    unsafe {
        asm!("smc #0",
             in("w0") RMM_BOOT_COMPLETE,
             in("x1") rc as u64,
        );
    }
}

/// Return codes from EL3
#[repr(i32)]
pub enum RuntimeReturnCode {
    /// No errors
    Success = 0,
    /// Unknown error
    Unknown = -1,
    /// Address argument invalid
    BadAddr = -2,
    /// PAS invalid
    BadPas = -3,
    /// Not enough memory to complete operation
    NoMem = -4,
    /// Invalid argument
    Inval = -5,
}

impl TryFrom<i32> for RuntimeReturnCode {
    type Error = ();

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        if v <= Self::Success as i32 && v >= Self::Inval as i32 {
            // SAFETY: the conversion is safe because the enum representation is
            // `i32` and the above bounds check guarantees the integer value has
            // a matching enumeration.
            unsafe { Ok(core::mem::transmute(v)) }
        } else {
            Err(())
        }
    }
}

/// Delegates a granule of memory from Non-Secure to Realm by changing its PAS
pub unsafe fn rmm_gtsi_delegate(pa: usize) -> RuntimeReturnCode {
    const RMM_GTSI_DELEGATE: u32 = 0xC400_01B0;
    let res: i32;

    unsafe {
        asm!("smc #0",
             in("w0") RMM_GTSI_DELEGATE,
             in("x1") pa,
             lateout("w0") res,
        );
    }

    res.try_into().unwrap()
}

/// Undelegates a granule of memory from Realm to Non-Secure by changing its PAS
pub unsafe fn rmm_gtsi_undelegate(pa: usize) -> RuntimeReturnCode {
    const RMM_GTSI_UNDELEGATE: u32 = 0xC400_01B1;
    let res: i32;

    unsafe {
        asm!("smc #0",
             in("w0") RMM_GTSI_UNDELEGATE,
             in("x1") pa,
             lateout("w0") res,
        );
    }

    res.try_into().unwrap()
}
