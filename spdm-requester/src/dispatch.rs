// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::MaybeUninit;

#[cfg_test_mock]
use mocktopus::macros::*;
use spdm::session::aead::{decrypt_secure_message, encrypt_secure_message};
use spdm::session::key_schedule::{get_session_keys, AeadSessionKeys};
use spdm::session::SessionPhase;
use spdm::types::code::RequestCode;
use spdm_proc_macros::{cfg_test_mock, cfg_test_mockable};
use spdm_types::crypto::AES_GCM_128_TAG_SIZE;
use spdm_types::deps::Dispatch;
use uninit::extension_traits::AsOut;
use uninit::out_ref::Out;

use crate::error::{RequesterError, RequesterResult};
use crate::version::SPDM_THIS_VERSION;
use crate::{Requester, RequesterDeps};

const REQUEST_OFFSET: usize = 8;
const MAX_RANDOM_SIZE: usize = 16;

const VENDOR_COMMAND_HEADER_SIZE: usize = 4;

#[cfg_test_mockable]
pub trait DispatchSecure {
    // Dispatch a session-encrypted request. The encryption keys will be selected
    // based on `phase`. The plaintext request is the first `req_size` bytes of
    // `buf`. If successful, the mutable slice of the response is returned.
    // SAFETY: The first `req_size` of `buf` needs to be initialized.
    fn dispatch_secure_request<'a>(
        &mut self,
        phase: SessionPhase,
        mut buf: Out<'a, [u8]>,
        req_size: usize,
    ) -> RequesterResult<&'a mut [u8]> {
        let buf_len = buf.len();
        // SAFETY: buf[..req_size] is guaranteed to be initialized.
        let plain_req = unsafe { buf.r().get_unchecked_out(..req_size).assume_init() };
        // Reserve a vector with enough size to contain the encrypted response.
        let max_encrypted_response_size =
            REQUEST_OFFSET + buf_len + MAX_RANDOM_SIZE + AES_GCM_128_TAG_SIZE;
        let mut encrypted_request_buf = vec![0u8; max_encrypted_response_size];
        encrypted_request_buf[REQUEST_OFFSET..REQUEST_OFFSET + req_size].copy_from_slice(plain_req);
        let resp =
            self.dispatch_secure_request_internal(phase, &mut encrypted_request_buf, req_size)?;
        if buf.len() < resp.len() {
            return Err(RequesterError);
        }
        Ok(buf.get_out(..resp.len()).unwrap().copy_from_slice(resp))
    }

    /// Dispatches a vendor command to the SPDM responder. Returns Ok on success,
    /// containing the mutable slice to the response. If this fails, try establishing
    /// the session again.
    /// SAFETY: The first `req_size` of `buf` needs to be initialized.
    ///
    /// VendorCommand request format:
    ///
    /// | Byte offset | Size (bytes)    | Field               | Description                |
    /// | :---------- | :-------------- | :------------------ | :------------------------- |
    /// | 0           | 1               | SPDMVersion         | SPDM_THIS_VERSION          |
    /// | 1           | 1               | RequestResponseCode | RequestCode::VendorCommand |
    /// | 2           | 1               | Param1              | Reserved                   |
    /// | 3           | 1               | Param2              | Reserved                   |
    /// | 4           | N               | VendorMessage       |                            |
    ///
    /// VendorCommand response format:
    /// | Byte offset | Size (bytes) | Field               | Description                 |
    /// | :---------- | :----------- | :------------------ | :-------------------------- |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION           |
    /// | 1           | 1            | RequestResponseCode | ResponseCode::VendorCommand |
    /// | 2           | 1            | Param1              | Reserved                    |
    /// | 3           | 1            | Param2              | Reserved                    |
    /// | 4           | N            | VendorMessage       |                             |
    fn dispatch_vendor_request<'a>(
        &mut self,
        mut buf: Out<'a, [u8]>,
        req_size: usize,
    ) -> RequesterResult<&'a mut [u8]> {
        let buf_len = buf.len();
        // SAFETY: buf[..req_size] is guaranteed to be initialized.
        let plain_req = unsafe { buf.r().get_unchecked_out(..req_size).assume_init() };
        // Reserve a vector with enough size to contain the encrypted response.
        let offset = REQUEST_OFFSET + VENDOR_COMMAND_HEADER_SIZE;
        let max_encrypted_response_size = offset + buf_len + MAX_RANDOM_SIZE + AES_GCM_128_TAG_SIZE;
        let mut encrypted_request_buf = vec![0u8; max_encrypted_response_size];
        encrypted_request_buf[REQUEST_OFFSET..REQUEST_OFFSET + VENDOR_COMMAND_HEADER_SIZE]
            .copy_from_slice(&[SPDM_THIS_VERSION, RequestCode::VendorCommand.0, 0, 0]);
        encrypted_request_buf[offset..offset + req_size].copy_from_slice(plain_req);
        let resp = self.dispatch_secure_request_internal(
            SessionPhase::Data,
            &mut encrypted_request_buf,
            VENDOR_COMMAND_HEADER_SIZE + req_size,
        )?;
        if resp.len() < VENDOR_COMMAND_HEADER_SIZE {
            return Err(RequesterError);
        }
        let resp = &mut resp[VENDOR_COMMAND_HEADER_SIZE..];
        if buf.len() < resp.len() {
            return Err(RequesterError);
        }
        Ok(buf.get_out(..resp.len()).unwrap().copy_from_slice(resp))
    }

    // This assumes that buf is already well-formatted for encryption:
    // The plaintext request is placed at REQUEST_OFFSET, and the buffer
    // size is enough to contain the whole encrypted request/response.
    // Only this trait method needs to be implemented.
    fn dispatch_secure_request_internal<'a>(
        &mut self,
        phase: SessionPhase,
        buf: &'a mut [u8],
        req_size: usize,
    ) -> RequesterResult<&'a mut [u8]>;
}

#[cfg_test_mockable]
impl<D: RequesterDeps> DispatchSecure for Requester<D> {
    fn dispatch_secure_request_internal<'a>(
        &mut self,
        phase: SessionPhase,
        buf: &'a mut [u8],
        req_size: usize,
    ) -> RequesterResult<&'a mut [u8]> {
        let Some(session_id) = self.session.session_id else {
            return Err(RequesterError);
        };
        let mut session_keys = MaybeUninit::<AeadSessionKeys<D::Crypto>>::uninit();
        get_session_keys::<D::Crypto>(&self.session, phase, &mut session_keys)
            .map_err(|_| RequesterError)?;
        // SAFETY: `session_keys` is guaranteed to be initialized after a successful
        // `get_session_keys`.
        let session_keys = unsafe { session_keys.assume_init() };

        let encrypted_req_size = encrypt_secure_message::<D::Crypto>(
            session_id,
            &session_keys.request_keys,
            buf,
            req_size,
        )
        .map_err(|_| RequesterError)?;
        self.session.sequence_numbers.request += 1;
        // Send the encrypted request.
        let encrypted_resp = self
            .dispatch
            .dispatch_request(true, buf.as_out(), encrypted_req_size);
        // Parse the encrypted response.
        let resp_size = decrypt_secure_message::<D::Crypto>(
            session_id,
            &session_keys.response_keys,
            encrypted_resp,
            encrypted_resp.len(),
        )
        .map_err(|_| RequesterError)?;
        self.session.sequence_numbers.response += 1;
        Ok(&mut encrypted_resp[REQUEST_OFFSET..REQUEST_OFFSET + resp_size])
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use std::cell::RefCell;

        use mocktopus::mocking::{MockContext, MockResult};
        use spdm_test_deps::{HmacDerivationKeyHandle, TestCrypto, TestDispatch, TestIdentity};
        use spdm_types::deps::{Crypto, CryptoError};

        use super::super::*;
        use crate::test::TestRequesterDeps;

        #[test]
        fn dispatch_secure_request_success() {
            const ORIGINAL_REQUEST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
            let req = &mut ORIGINAL_REQUEST.clone();
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            requester.session.session_id = Some([0xaa, 0xbb, 0xcc, 0xdd]);
            requester.session.th1 = Some([0xCC; 32]);
            requester.session.handshake_secret = Some(HmacDerivationKeyHandle);

            let plaintext = RefCell::new(vec![]);
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_encrypt, |_, _, _, plain, tag| {
                    plaintext.replace(plain.to_vec());
                    // Stub encrypted buffer.
                    plain.fill(0x01);
                    MockResult::Return(Ok(tag.write([0x01; AES_GCM_128_TAG_SIZE])))
                })
                .mock_safe(
                    TestDispatch::dispatch_request,
                    |_, is_secure, buf, req_size| {
                        assert!(is_secure);
                        // Return response that is identical to the request.
                        // SAFETY: buf[..req_size] is guaranteed to be initialized.
                        MockResult::Return(unsafe {
                            buf.get_unchecked_out(..req_size).assume_init()
                        })
                    },
                )
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, tag, ciph| {
                    let plaintext = plaintext.borrow();
                    assert_eq!(tag, &[0x01; AES_GCM_128_TAG_SIZE]);
                    assert!(ciph.iter().all(|x| *x == 0x01));
                    assert_eq!(ciph.len(), plaintext.len());
                    ciph.copy_from_slice(&plaintext);
                    MockResult::Return(Ok(()))
                })
                .run(|| {
                    let resp = requester.dispatch_secure_request(
                        SessionPhase::Handshake,
                        req.as_out(),
                        ORIGINAL_REQUEST.len(),
                    );
                    assert_eq!(resp, Ok(ORIGINAL_REQUEST.clone().as_mut_slice()));
                    assert_eq!(requester.session.sequence_numbers.request, 1);
                    assert_eq!(requester.session.sequence_numbers.response, 1);
                })
        }

        #[test]
        fn dispatch_secure_request_state_not_ready() {
            const ORIGINAL_REQUEST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
            let req = &mut ORIGINAL_REQUEST.clone();
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            let plaintext = RefCell::new(vec![]);
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_encrypt, |_, _, _, plain, tag| {
                    plaintext.replace(plain.to_vec());
                    // Stub encrypted buffer.
                    plain.fill(0x01);
                    MockResult::Return(Ok(tag.write([0x01; AES_GCM_128_TAG_SIZE])))
                })
                .mock_safe(
                    TestDispatch::dispatch_request,
                    |_, is_secure, buf, req_size| {
                        assert!(is_secure);
                        // Return response that is identical to the request.
                        // SAFETY: buf[..req_size] is guaranteed to be initialized.
                        MockResult::Return(unsafe {
                            buf.get_unchecked_out(..req_size).assume_init()
                        })
                    },
                )
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, tag, ciph| {
                    let plaintext = plaintext.borrow();
                    assert_eq!(tag, &[0x01; AES_GCM_128_TAG_SIZE]);
                    assert!(ciph.iter().all(|x| *x == 0x01));
                    assert_eq!(ciph.len(), plaintext.len());
                    ciph.copy_from_slice(&plaintext);
                    MockResult::Return(Ok(()))
                })
                .run(|| {
                    let resp = requester.dispatch_secure_request(
                        SessionPhase::Handshake,
                        req.as_out(),
                        ORIGINAL_REQUEST.len(),
                    );
                    assert_eq!(resp, Err(RequesterError));
                    assert_eq!(requester.session.sequence_numbers.request, 0);
                    assert_eq!(requester.session.sequence_numbers.response, 0);
                })
        }

        #[test]
        fn dispatch_secure_request_decrypt_failure() {
            const ORIGINAL_REQUEST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
            let req = &mut ORIGINAL_REQUEST.clone();
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            let plaintext = RefCell::new(vec![]);
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_encrypt, |_, _, _, plain, tag| {
                    plaintext.replace(plain.to_vec());
                    // Stub encrypted buffer.
                    plain.fill(0x01);
                    MockResult::Return(Ok(tag.write([0x01; AES_GCM_128_TAG_SIZE])))
                })
                .mock_safe(
                    TestDispatch::dispatch_request,
                    |_, is_secure, buf, req_size| {
                        assert!(is_secure);
                        // Return response that is identical to the request.
                        // SAFETY: buf[..req_size] is guaranteed to be initialized.
                        MockResult::Return(unsafe {
                            buf.get_unchecked_out(..req_size).assume_init()
                        })
                    },
                )
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, tag, ciph| {
                    let plaintext = plaintext.borrow();
                    assert_eq!(tag, &[0x01; AES_GCM_128_TAG_SIZE]);
                    assert!(ciph.iter().all(|x| *x == 0x01));
                    assert_eq!(ciph.len(), plaintext.len());
                    ciph.copy_from_slice(&plaintext);
                    MockResult::Return(Err(CryptoError))
                })
                .run(|| {
                    let resp = requester.dispatch_secure_request(
                        SessionPhase::Handshake,
                        req.as_out(),
                        ORIGINAL_REQUEST.len(),
                    );
                    assert_eq!(resp, Err(RequesterError));
                    assert_eq!(requester.session.sequence_numbers.request, 0);
                    assert_eq!(requester.session.sequence_numbers.response, 0);
                })
        }

        #[test]
        fn dispatch_vendor_request_success() {
            const ORIGINAL_REQUEST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
            let req = &mut ORIGINAL_REQUEST.clone();
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            requester.session.session_id = Some([0xaa, 0xbb, 0xcc, 0xdd]);
            requester.session.th2 = Some([0xCC; 32]);
            requester.session.main_secret = Some(HmacDerivationKeyHandle);

            let plaintext = RefCell::new(vec![]);
            MockContext::new()
                .mock_safe(TestCrypto::aes_gcm_encrypt, |_, _, _, plain, tag| {
                    plaintext.replace(plain.to_vec());
                    // Stub encrypted buffer.
                    plain.fill(0x01);
                    MockResult::Return(Ok(tag.write([0x01; AES_GCM_128_TAG_SIZE])))
                })
                .mock_safe(
                    TestDispatch::dispatch_request,
                    |_, is_secure, buf, req_size| {
                        assert!(is_secure);
                        // Return response that is identical to the request.
                        // SAFETY: buf[..req_size] is guaranteed to be initialized.
                        MockResult::Return(unsafe {
                            buf.get_unchecked_out(..req_size).assume_init()
                        })
                    },
                )
                .mock_safe(TestCrypto::aes_gcm_decrypt, |_, _, _, tag, ciph| {
                    let plaintext = plaintext.borrow();
                    assert_eq!(tag, &[0x01; AES_GCM_128_TAG_SIZE]);
                    assert!(ciph.iter().all(|x| *x == 0x01));
                    assert_eq!(ciph.len(), plaintext.len());
                    ciph.copy_from_slice(&plaintext);
                    MockResult::Return(Ok(()))
                })
                .run(|| {
                    let resp =
                        requester.dispatch_vendor_request(req.as_out(), ORIGINAL_REQUEST.len());
                    println!("{:?}", resp);
                    // assert_eq!(resp, Ok(ORIGINAL_REQUEST.clone().as_mut_slice()));
                    assert_eq!(requester.session.sequence_numbers.request, 1);
                    assert_eq!(requester.session.sequence_numbers.response, 1);
                })
        }
    }
}
