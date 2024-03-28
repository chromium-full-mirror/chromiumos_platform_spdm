// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod get_pub_key;
mod get_version;
mod key_exchange;

use spdm::types::code::RequestCode;
use spdm::types::error::{ErrorCode, SpdmResult};

use self::get_pub_key::GetPubKeyDispatcher;
use self::get_version::GetVersionDispatcher;
use self::key_exchange::KeyExchangeDispatcher;
use crate::{Responder, ResponderDeps};

/// WaitForKeyExchangeDispatcher handles the state where the responder hasn't received
/// a KeyExchange to start establishing the session. After processing KeyExchange
/// request successfully, the state handler should advance to the next state.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait WaitForKeyExchangeDispatcher {
    fn dispatch_request_wait_for_key_exchange(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

impl<D: ResponderDeps> WaitForKeyExchangeDispatcher for Responder<D> {
    fn dispatch_request_wait_for_key_exchange(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match req_code {
            RequestCode::GetVersion => self.dispatch_get_version_request(buf, req_size),
            RequestCode::GetPubKey => self.dispatch_get_pub_key_request(buf, req_size),
            RequestCode::KeyExchange => self.dispatch_key_exchange_request(buf, req_size),
            _ => Err(ErrorCode::UnexpectedRequest),
        }
    }
}
