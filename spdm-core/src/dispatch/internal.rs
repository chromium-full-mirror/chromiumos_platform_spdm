// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::wait_for_key_exchange::WaitForKeyExchangeDispatcher;
use crate::deps::SpdmDeps;
use crate::session::SpdmSessionManager;
use crate::types::code::{parse_header, RequestCode};
use crate::types::error::ErrorCode;
use crate::Spdm;

/// The SpdmState is an enum that holds the current state. In each state the
/// dispatcher expects to receive different requests.
pub enum SpdmState {
    WaitForKeyExchange,
    WaitForRequesterKey,
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
    fn dispatch_request_internal(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> usize;
}

impl<D: SpdmDeps> SpdmInternalDispatcher for Spdm<D> {
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> usize {
        if buf.len() < req_size {
            return ErrorCode::Unspecified.write_response(buf);
        }
        let req_code = match parse_header(&buf[..req_size]) {
            Ok(req_code) => req_code,
            Err(error) => {
                return error.write_response(buf);
            }
        };
        if req_code == RequestCode::GetVersion {
            self.reset_session();
            self.state = SpdmState::default();
        }
        if req_code == RequestCode::GetPubKey {
            self.reset_session_keep_vca_cache();
            self.state = SpdmState::default();
        }
        // TODO(b/284404632): If the session is established, block dispatching plaintext request.
        self.dispatch_request_internal(buf, req_size, req_code)
    }

    fn dispatch_request_internal(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> usize {
        let result = match self.state {
            SpdmState::WaitForKeyExchange => {
                self.dispatch_request_wait_for_key_exchange(buf, req_size, req_code)
            }
            // TODO(b/284404632): Implement WaitForRequesterKeyDispatcher.
            SpdmState::WaitForRequesterKey => Err(ErrorCode::Unspecified),
        };
        match result {
            Ok(resp_size) => resp_size,
            Err(err) => err.write_response(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{SpdmTestDeps, TestIdentity};
    use crate::types::message::GET_PUBLIC_KEY_RESPONSE_SIZE;
    use crate::types::version::SPDM_THIS_VERSION;

    #[test]
    fn plaintext_get_version_resets_session() {
        let mut buf = [0x10, RequestCode::GetVersion.0, 0, 0, 0, 0, 0, 0];
        let req_size = 4;

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);

        let fake_transcript = [0xCC; 12];
        // Simulate the scenario that there's already some state.
        spdm.session.transcript = Some(fake_transcript);
        spdm.session.session_id = Some([0xAB, 0xCD, 0xEF, 0x89]);

        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(result, 8, "response: {:?}", &buf[..result]);
        // Transcript should be overwritten.
        assert_ne!(spdm.session.transcript, Some(fake_transcript));
        // Session ID should be cleared.
        assert_eq!(spdm.session.session_id, None);
    }

    #[test]
    fn plaintext_get_pub_key_keeps_vca() {
        let mut buf = vec![SPDM_THIS_VERSION, RequestCode::GetPubKey.0, 0, 0];
        buf.extend_from_slice(&[0; 100]);
        let req_size = 4;

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);

        let fake_transcript = [0xCC; 12];
        // Simulate the scenario that there's already some state.
        spdm.session.transcript = Some(fake_transcript);
        spdm.session.session_id = Some([0xAB, 0xCD, 0xEF, 0x89]);

        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(
            result,
            GET_PUBLIC_KEY_RESPONSE_SIZE,
            "response: {:?}",
            &buf[..result]
        );
        // Transcript should be kept.
        assert_eq!(spdm.session.transcript, Some(fake_transcript));
        // Session ID should be cleared.
        assert_eq!(spdm.session.session_id, None);
    }
}
