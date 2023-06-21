// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic for FFI users.

#![cfg_attr(not(feature = "std"), no_std)]
mod deps;

use deps::{EalIdentity, SpdmEalDeps};
use spdm::{Spdm, SpdmDispatcher, UNSPECIFIED_ERROR_RESPONSE};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Users of this library can't hold rust types, so the interface is designed
/// to be purely static. In exchange, SpdmState will be kept as a global variable.
/// Therefore, the user should only access this library in the same thread.
static mut SPDM: Option<Spdm<SpdmEalDeps>> = None;

fn get_or_create_spdm() -> Option<&'static mut Spdm<SpdmEalDeps>> {
    // SAFETY: SPDM will only be accessed in the same thread.
    unsafe {
        if SPDM.is_none() {
            SPDM = Some(Spdm::<SpdmEalDeps>::new(EalIdentity));
        }

        if SPDM.is_some() {
            SPDM.as_mut()
        } else {
            None
        }
    }
}

/// # Safety
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
    is_secure: bool,
    buf: *mut u8,
    req_size: usize,
    resp_size: *mut usize,
) {
    let buf = core::slice::from_raw_parts_mut(buf, *resp_size);

    let Some(spdm) = get_or_create_spdm() else {
      if *resp_size < UNSPECIFIED_ERROR_RESPONSE.len() {
        // We can't even write the error response. Leave the response empty.
        *resp_size = 0;
        return;
      }
      buf.copy_from_slice(&UNSPECIFIED_ERROR_RESPONSE);
      *resp_size = UNSPECIFIED_ERROR_RESPONSE.len();
      return;
    };
    *resp_size = spdm.dispatch_request(is_secure, buf, req_size);
}
