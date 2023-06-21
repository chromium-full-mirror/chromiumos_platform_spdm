// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::deps::SpdmDeps;
use crate::types::error::ErrorCode;
use crate::Spdm;

/// WaitForKeyExchangeDispatcher handles the state where the responder hasn't received
/// a KeyExchange to start establishing the session. After processing KeyExchange
/// request successfully, the state handler should advance to the next state.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait WaitForKeyExchangeDispatcher {
    fn dispatch_request_wait_for_key_exchange(&mut self, buf: &mut [u8], req_size: usize) -> usize;
}

impl<D: SpdmDeps> WaitForKeyExchangeDispatcher for Spdm<D> {
    fn dispatch_request_wait_for_key_exchange(
        &mut self,
        buf: &mut [u8],
        _req_size: usize,
    ) -> usize {
        // TODO(b/284404632): Implement WaitForKeyExchangeDispatcher logic.
        ErrorCode::Unspecified.write_response(buf)
    }
}
