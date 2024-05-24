// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::MaybeUninit;

#[cfg_test_mock]
use mocktopus::macros::*;
use spdm::session::aead::{decrypt_secure_message, encrypt_secure_message, REQUEST_OFFSET};
use spdm::session::key_schedule::{get_session_keys, AeadSessionKeys};
use spdm::session::{SessionPhase, SpdmRole};
use spdm::types::code::RequestCode;
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm_proc_macros::{cfg_test_mock, cfg_test_mockable};

use super::session_established::SessionEstablishedDispatcher;
use super::wait_for_finish::WaitForFinishDispatcher;
use super::wait_for_key_exchange::WaitForKeyExchangeDispatcher;
use super::wait_for_requester_key::WaitForRequesterKeyDispatcher;
use crate::code::parse_header;
use crate::error::error_response;
use crate::{Responder, ResponderDeps};

/// The ResponderState is an enum that holds the current state. In each state the
/// dispatcher expects to receive different requests.
#[derive(Clone, Copy)]
pub enum ResponderState {
    WaitForKeyExchange,
    WaitForRequesterKey,
    WaitForFinish,
    SessionEstablished,
}

impl Default for ResponderState {
    fn default() -> Self {
        Self::WaitForKeyExchange
    }
}

impl ResponderState {
    fn phase(self) -> SessionPhase {
        match self {
            Self::WaitForKeyExchange => SessionPhase::None,
            Self::WaitForRequesterKey | Self::WaitForFinish => SessionPhase::Handshake,
            Self::SessionEstablished => SessionPhase::Data,
        }
    }
}

/// Defines the methods related to dispatching a request internally, including
/// dealing with encrypted/plaintext request/response.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait InternalDispatcher {
    /// Dispatches a plaintext SPDM request.
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize>;

    /// Dispatches a secure SPDM request.
    fn dispatch_secure_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize>;

    /// Dispatches a plaintext SPDM request after all preprocessing.
    fn dispatch_request_internal(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

#[cfg_test_mockable]
impl<D: ResponderDeps> InternalDispatcher for Responder<D> {
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize> {
        if buf.len() < req_size {
            return Err(ErrorCode::Unspecified);
        }
        let req_code = parse_header(&buf[..req_size])?;
        if req_code == RequestCode::GetVersion {
            self.session.reset_session(SpdmRole::Responder);
            self.state = ResponderState::default();
        }
        if req_code == RequestCode::GetPubKey {
            self.session
                .reset_session_keep_vca_cache(SpdmRole::Responder);
            self.state = ResponderState::default();
        }
        if self.state.phase() != SessionPhase::None {
            return Err(ErrorCode::SessionRequired);
        }
        self.dispatch_request_internal(buf, req_size, req_code)
    }

    fn dispatch_secure_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize> {
        let phase = self.state.phase();
        if phase == SessionPhase::None {
            return Err(ErrorCode::SessionRequired);
        }
        let Some(session_id) = self.session.session_id else {
            return Err(ErrorCode::Unspecified);
        };
        let mut session_keys = MaybeUninit::<AeadSessionKeys<D::Crypto>>::uninit();
        get_session_keys(&self.session, phase, &mut session_keys)?;
        // SAFETY: `session_keys` is guaranteed to be initialized after a successful
        // `get_session_keys`.
        let session_keys = unsafe { session_keys.assume_init() };
        let req_size =
            decrypt_secure_message(session_id, &session_keys.request_keys, buf, req_size)?;
        self.session.sequence_numbers.request += 1;
        let req_buf = &mut buf[REQUEST_OFFSET..];
        let req_code = parse_header(&req_buf[..req_size])?;
        let resp_size = match self.dispatch_request_internal(req_buf, req_size, req_code) {
            Ok(resp_size) => resp_size,
            Err(err) => error_response(buf, err),
        };
        let resp_size =
            encrypt_secure_message(session_id, &session_keys.response_keys, buf, resp_size)?;
        self.session.sequence_numbers.response += 1;
        Ok(resp_size)
    }

    fn dispatch_request_internal(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match self.state {
            ResponderState::WaitForKeyExchange => {
                self.dispatch_request_wait_for_key_exchange(buf, req_size, req_code)
            }
            ResponderState::WaitForRequesterKey => {
                self.dispatch_request_wait_for_requester_key(buf, req_size, req_code)
            }
            ResponderState::WaitForFinish => {
                self.dispatch_request_wait_for_finish(buf, req_size, req_code)
            }
            ResponderState::SessionEstablished => {
                self.dispatch_request_session_established(buf, req_size, req_code)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use spdm::types::message::GET_PUBLIC_KEY_RESPONSE_SIZE;
    use spdm_test_deps::{TestIdentity, TestVendor};

    use super::*;
    use crate::test::TestResponderDeps;
    use crate::version::SPDM_THIS_VERSION;

    #[test]
    fn plaintext_get_version_resets_session() {
        let mut buf = [0x10, RequestCode::GetVersion.0, 0, 0, 0, 0, 0, 0];
        let req_size = 4;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let fake_transcript = [0xCC; 12];
        // Simulate the scenario that there's already some state.
        spdm.session.transcript = Some(fake_transcript);
        spdm.session.session_id = Some([0xAB, 0xCD, 0xEF, 0x89]);

        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(result, Ok(8));
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

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let fake_transcript = [0xCC; 12];
        // Simulate the scenario that there's already some state.
        spdm.session.transcript = Some(fake_transcript);
        spdm.session.session_id = Some([0xAB, 0xCD, 0xEF, 0x89]);

        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(result, Ok(GET_PUBLIC_KEY_RESPONSE_SIZE));
        // Transcript should be kept.
        assert_eq!(spdm.session.transcript, Some(fake_transcript));
        // Session ID should be cleared.
        assert_eq!(spdm.session.session_id, None);
    }

    #[test]
    fn plaintext_blocked_during_active_session() {
        let mut buf = vec![SPDM_THIS_VERSION, RequestCode::KeyExchange.0, 0, 0];
        buf.extend_from_slice(&[0; 100]);
        let req_size = 4;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
        spdm.state = ResponderState::WaitForRequesterKey;
        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(result, Err(ErrorCode::SessionRequired));
    }

    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockContext, MockResult};
        use spdm_test_deps::{HmacDerivationKeyHandle, TestCrypto};
        use spdm_types::deps::Crypto;

        use super::*;

        #[test]
        fn dispatch_secure_request() {
            let mut buf = vec![0xaa, 0xbb, 0xcc, 0xdd, /*22*/ 0x16, 0x00];
            let stub_encrypted_req = [0xFF; 6];
            let original_req = [0x04, 0x00, 0x10, RequestCode::GetVersion.0, 0, 0];
            buf.extend_from_slice(&stub_encrypted_req);
            buf.extend_from_slice(&[0xEE; 16]);
            // Reserve size for response.
            buf.extend_from_slice(&[0; 100]);
            let req_size = 28;

            let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
            spdm.session.session_id = Some([0xaa, 0xbb, 0xcc, 0xdd]);
            spdm.session.th1 = Some([0xCC; 32]);
            spdm.session.handshake_secret = Some(HmacDerivationKeyHandle);
            spdm.state = ResponderState::WaitForRequesterKey;
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, _, buf| {
                    assert_eq!(buf, stub_encrypted_req);
                    buf.copy_from_slice(&original_req);
                    MockResult::Return(Ok(()))
                })
                .mock_safe(
                    Responder::<TestResponderDeps>::dispatch_request_internal,
                    |_, _, req_size, _| MockResult::Return(Ok(req_size)),
                )
                .run(|| {
                    let result = spdm.dispatch_secure_request(&mut buf, req_size);
                    assert!(result.is_ok(), "result: {result:?}");
                })
        }
    }
}
