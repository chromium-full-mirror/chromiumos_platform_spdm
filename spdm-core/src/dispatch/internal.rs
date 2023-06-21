// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::wait_for_key_exchange::WaitForKeyExchangeDispatcher;
use crate::deps::SpdmDeps;
use crate::Spdm;

/// The SpdmState is an enum that holds the current state. In each state the
/// dispatcher expects to receive different requests.
pub enum SpdmState {
    WaitForKeyExchange,
}

impl Default for SpdmState {
    fn default() -> Self {
        Self::WaitForKeyExchange
    }
}

/// Defines the methods related to dispatching a request internally, including
/// dealing with encrypted/plaintext request/response.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait SpdmInternalDispatcher {
    /// Dispatches a plaintext SPDM request.
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> usize;

    /// Dispatches a plaintext SPDM request after all preprocessing.
    fn dispatch_request_internal(&mut self, buf: &mut [u8], req_size: usize) -> usize;
}

impl<D: SpdmDeps> SpdmInternalDispatcher for Spdm<D> {
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> usize {
        // TODO(b/284404632): If the request is GetVersion or GetPubKey request,
        // reset the state here.
        // TODO(b/284404632): If the session is established, block dispatching plaintext request.
        self.dispatch_request_internal(buf, req_size)
    }

    fn dispatch_request_internal(&mut self, buf: &mut [u8], req_size: usize) -> usize {
        match self.state {
            SpdmState::WaitForKeyExchange => {
                self.dispatch_request_wait_for_key_exchange(buf, req_size)
            }
        }
    }
}
