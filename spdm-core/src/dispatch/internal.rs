// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::MaybeUninit;

#[cfg(all(test, feature = "mock"))]
use mocktopus::macros::*;
use spdm_types::deps::{Crypto, SpdmDeps};

use super::wait_for_key_exchange::WaitForKeyExchangeDispatcher;
use crate::session::aead::{decrypt_secure_message, encrypt_secure_message, REQUEST_OFFSET};
use crate::session::key_schedule::{
    generate_aead_keys, generate_message_secrets, AeadSessionKeys, MessageSecrets,
};
use crate::session::{Session, SessionPhase, SpdmSessionManager};
use crate::types::code::{parse_header, RequestCode};
use crate::types::error::{ErrorCode, SpdmResult};
use crate::Spdm;

/// The SpdmState is an enum that holds the current state. In each state the
/// dispatcher expects to receive different requests.
#[derive(Clone, Copy)]
pub enum SpdmState {
    WaitForKeyExchange,
    WaitForRequesterKey,
}

impl Default for SpdmState {
    fn default() -> Self {
        Self::WaitForKeyExchange
    }
}

impl SpdmState {
    fn phase(self) -> SessionPhase {
        match self {
            Self::WaitForKeyExchange => SessionPhase::None,
            Self::WaitForRequesterKey => SessionPhase::Handshake,
        }
    }
}

/// Defines the methods related to dispatching a request internally, including
/// dealing with encrypted/plaintext request/response.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait SpdmInternalDispatcher {
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

fn get_session_keys<'a, C: Crypto>(
    session: &Session<C>,
    phase: SessionPhase,
    keys: &'a mut MaybeUninit<AeadSessionKeys<C>>,
) -> SpdmResult<&'a mut AeadSessionKeys<C>> {
    let mut message_secrets = MaybeUninit::<MessageSecrets<C>>::uninit();
    let message_secrets = generate_message_secrets(session, phase, (&mut message_secrets).into())?;
    generate_aead_keys(message_secrets, keys.into())
}

#[cfg_attr(all(test, feature = "mock"), mockable)]
impl<D: SpdmDeps> SpdmInternalDispatcher for Spdm<D> {
    fn dispatch_plaintext_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize> {
        if buf.len() < req_size {
            return Err(ErrorCode::Unspecified);
        }
        let req_code = parse_header(&buf[..req_size])?;
        if req_code == RequestCode::GetVersion {
            self.reset_session();
            self.state = SpdmState::default();
        }
        if req_code == RequestCode::GetPubKey {
            self.reset_session_keep_vca_cache();
            self.state = SpdmState::default();
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
        let session_keys = get_session_keys(&self.session, phase, &mut session_keys)?;
        let req_size =
            decrypt_secure_message(session_id, &session_keys.request_keys, buf, req_size)?;
        let req_buf = &mut buf[REQUEST_OFFSET..];
        let req_code = parse_header(&req_buf[..req_size])?;
        let resp_size = self.dispatch_request_internal(req_buf, req_size, req_code)?;
        encrypt_secure_message(session_id, &session_keys.response_keys, buf, resp_size)
    }

    fn dispatch_request_internal(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match self.state {
            SpdmState::WaitForKeyExchange => {
                self.dispatch_request_wait_for_key_exchange(buf, req_size, req_code)
            }
            // TODO(b/284404632): Implement WaitForRequesterKeyDispatcher.
            SpdmState::WaitForRequesterKey => Err(ErrorCode::Unspecified),
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

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);

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

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);
        spdm.state = SpdmState::WaitForRequesterKey;
        let result = spdm.dispatch_plaintext_request(&mut buf, req_size);
        assert_eq!(result, Err(ErrorCode::SessionRequired));
    }

    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockContext, MockResult};

        use super::*;
        use crate::deps::TestCrypto;

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

            let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);
            spdm.session.session_id = Some([0xaa, 0xbb, 0xcc, 0xdd]);
            spdm.session.th1 = Some([0xCC; 32]);
            spdm.session.handshake_secret = Some(());
            spdm.state = SpdmState::WaitForRequesterKey;
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, _, buf| {
                    assert_eq!(buf, stub_encrypted_req);
                    buf.copy_from_slice(&original_req);
                    MockResult::Return(Ok(()))
                })
                .mock_safe(
                    Spdm::<SpdmTestDeps>::dispatch_request_internal,
                    |_, _, req_size, _| MockResult::Return(Ok(req_size)),
                )
                .run(|| {
                    let result = spdm.dispatch_secure_request(&mut buf, req_size);
                    assert!(result.is_ok(), "result: {result:?}");
                })
        }
    }
}
