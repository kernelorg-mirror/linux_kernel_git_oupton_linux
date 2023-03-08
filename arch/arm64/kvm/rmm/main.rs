//! SPDX-License-Identifier: GPL-2.0
//!
//! Copyright (c) 2023 Google LLC
//! Author: Oliver Upton <oliver.upton@linux.dev>

use core::arch::asm;

/// Main loop for the RMM.
pub extern "C" fn rmm_main() -> ! {
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}
