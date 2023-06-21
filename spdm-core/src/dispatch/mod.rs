// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the dispatcher state machine of the SPDM responder.

use crate::deps::SpdmDeps;
use crate::types::error::ErrorCode;
use crate::Spdm;

/// Defines the methods related to dispatching a request.
///
/// This is the only trait exposed to the library users.
pub trait SpdmDispatcher {
    /// Dispatches an SPDM request to the state machine.
    ///
    /// - `is_secure` should be set to whether the request is secured (plaintext message if not).
    /// - `buf` should contain the SPDM request and the SPDM response will be written back to `buf`.
    /// - `req_size` should contain the size in bytes of the SPDM request.
    /// - `resp_size` should contain the maximum size in bytes we can write to `buf`, and will be
    /// set to the response size.
    fn dispatch_request(&mut self, is_secure: bool, buf: &mut [u8], req_size: usize) -> usize;
}

impl<D: SpdmDeps> SpdmDispatcher for Spdm<D> {
    fn dispatch_request(&mut self, _is_secure: bool, buf: &mut [u8], _req_size: usize) -> usize {
        // TODO(b/284404632): Implement the whole SPDM dispatcher state machine.
        ErrorCode::Unspecified.write_response(buf)
    }
}
