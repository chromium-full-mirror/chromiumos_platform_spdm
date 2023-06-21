// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod get_version;

use self::get_version::GetVersionDispatcher;
use crate::deps::SpdmDeps;
use crate::types::code::RequestCode;
use crate::types::error::{ErrorCode, SpdmResult};
use crate::Spdm;

/// WaitForKeyExchangeDispatcher handles the state where the responder hasn't received
/// a KeyExchange to start establishing the session. After processing KeyExchange
/// request successfully, the state handler should advance to the next state.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait WaitForKeyExchangeDispatcher {
    fn dispatch_request_wait_for_key_exchange(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

impl<D: SpdmDeps> WaitForKeyExchangeDispatcher for Spdm<D> {
    fn dispatch_request_wait_for_key_exchange(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match req_code {
            RequestCode::GetVersion => self.dispatch_get_version_request(buf, req_size),
            // TODO(b/284404632): Implement GetPubKey and KeyExchange logic.
            _ => Err(ErrorCode::UnexpectedRequest),
        }
    }
}
