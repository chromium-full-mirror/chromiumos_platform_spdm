// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the state machine of the SPDM responder, the main logic of
//! this library.
use crate::context::SpdmContext;
use crate::error::write_error;
use crate::error::ErrorCode;

/// State machine of the SPDM responder. The user of this library should create
/// an SpdmState and call its `dispatch_request` whenever it receives an SPDM
/// request.
#[repr(C, packed)]
pub struct SpdmState;

impl SpdmState {
    /// Dispatches an SPDM request to the responder state machine. This is the main
    /// entry point of the library.
    ///
    /// `is_secure` should be set to whether the request is secured (clear message if not).
    /// - `buf` should contain the SPDM request and the SPDM response will be written back to `buf`.
    /// - `req_size` should contain the size in bytes of the SPDM request.
    /// - `resp_size` should contain the maximum size in bytes we can write to `buf`, and will be
    /// set to the response size.
    pub fn dispatch_request(
        &mut self,
        _ctx: &mut impl SpdmContext,
        _is_secure: bool,
        buf: &mut [u8],
        _req_size: usize,
    ) -> usize {
        // TODO(b/284404632): Implement the whole SPDM responder state machine.
        write_error(buf, ErrorCode::Unspecified)
    }
}
