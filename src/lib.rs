// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic for FFI users.

#![cfg_attr(not(feature = "std"), no_std)]
mod deps;

use core::mem::size_of;

use deps::{EalIdentity, SpdmEalDeps};
use spdm::{Spdm, SpdmDispatcher};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// FFI-safe type for holding the actual Spdm struct. The size of this struct
/// must be larger than `Spdm<SpdmEalDeps>`, such that its pointer is safe to be
/// casted as that of `Spdm<SpdmEalDeps>`.
#[repr(C)]
pub struct SpdmFFI {
    opaque: [u8; size_of::<Spdm<SpdmEalDeps>>()],
}

/// # Safety
/// - `spdm` must be valid pointer for `SpdmFFI`.
///
/// Initializes the data pointed by `spdm` to a valid, clean, `SpdmFFI` structure.
#[no_mangle]
pub unsafe extern "C" fn spdm_initialize(spdm: *mut SpdmFFI) {
    let spdm: &mut Spdm<SpdmEalDeps> = &mut *spdm.cast();
    *spdm = Spdm::<SpdmEalDeps>::new(EalIdentity);
}

/// # Safety
/// - `spdm` must be valid pointer for `SpdmFFI`, and the pointed data should have
/// been initialized by `spdm_initialize` first.
/// - `buf` must be valid pointer for `req_size` bytes, and writeable for `resp_size` bytes.
///
/// Dispatches the SPDM request to the global SPDM responder state machine.
///
/// - `is_secure` should be set to whether the request is secured (clear message if not).
/// - `buf` should contain the SPDM request and the SPDM response will be written back to `buf`.
/// - `req_size` should contain the size in bytes of the SPDM request.
/// - `resp_size` should contain the maximum size in bytes we can write to `buf`, and will be
/// set to the response size.
#[no_mangle]
pub unsafe extern "C" fn dispatch_spdm_request(
    spdm: *mut SpdmFFI,
    is_secure: bool,
    buf: *mut u8,
    req_size: usize,
    resp_size: *mut usize,
) {
    let spdm: &mut Spdm<SpdmEalDeps> = &mut *(spdm.cast());
    let buf = core::slice::from_raw_parts_mut(buf, *resp_size);
    *resp_size = spdm.dispatch_request(is_secure, buf, req_size);
}
