// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uninit::out_ref::Out;

/// Dispatch trait defines the interface to dispatch requests to and receive
/// responses from the SPDM responder.
pub trait Dispatch {
    /// Dispatches an SPDM request to the responder.
    ///
    /// - `is_secure` should be set to whether the request is secured (plaintext message if not).
    /// - `buf` should contain the SPDM request and the SPDM response will be written back to `buf`.
    /// - `req_size` should contain the size in bytes of the SPDM request.
    /// - the return value `resp` should be set to the response buffer, exactly equal to
    /// the response size.
    fn dispatch_request<'a>(
        &mut self,
        is_secure: bool,
        buf: Out<'a, [u8]>,
        req_size: usize,
    ) -> &'a mut [u8];
}
