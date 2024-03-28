// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::MaybeUninit;

use spdm::types::code::ResponseCode;
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm::types::message::{HalfSessionId, KeyExchangeRequest, KeyExchangeResponse};
use spdm_types::crypto::EcP256UncompressedPoint;
use spdm_types::deps::{Crypto, Identity};
use zerocopy::AsBytes;

use crate::dispatch::internal::ResponderState;
use crate::session::ResponderSession;
use crate::{Responder, ResponderDeps};

/// KeyExchangeDispatcher handles the KeyExchange request.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait KeyExchangeDispatcher {
    /// Handles the KeyExchange request and if successful, writes the KeyExchange response to `buf`.
    /// KeyExchange request format: see `KeyExchangeRequest` struct.
    /// KeyExchange response format: see `KeyExchangeResponse` struct.
    fn dispatch_key_exchange_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize>;
}

fn write_partial_response<'a, C: Crypto>(
    buf: &'a mut [u8],
    half_session_id: HalfSessionId,
    public_key: &mut EcP256UncompressedPoint,
) -> SpdmResult<&'a mut KeyExchangeResponse> {
    let response: &mut KeyExchangeResponse = (&mut buf[..KeyExchangeResponse::SIZE])
        .try_into()
        .map_err(|_| ErrorCode::Unspecified)?;
    response.response_code = ResponseCode::KeyExchange;
    response.param1 = KeyExchangeResponse::NO_HEARTBEAT;
    // Zero reserved field.
    response.param2 = 0;
    response.resp_session_id = half_session_id;
    response.mut_auth_requested = KeyExchangeResponse::NO_ENCAPSULATE;
    response.slot_id_param = KeyExchangeResponse::PROVISIONED_SLOT_ID;
    C::random_bytes(response.random_data.as_mut().into())?;
    response.exchange_data = public_key.clone();
    response.opaque_data_size = 0.into();
    Ok(response)
}

impl<D: ResponderDeps> KeyExchangeDispatcher for Responder<D> {
    fn dispatch_key_exchange_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize> {
        if req_size != KeyExchangeRequest::SIZE {
            return Err(ErrorCode::InvalidRequest);
        }
        // Without transcript, we can't perform KeyExchange. GetVersion request
        // should be sent first.
        if self.session.transcript.is_none() {
            return Err(ErrorCode::UnexpectedRequest);
        }
        if buf.len() < KeyExchangeResponse::SIZE {
            return Err(ErrorCode::ResponseTooLarge);
        }
        let request: &KeyExchangeRequest = (&buf[..req_size])
            .try_into()
            .map_err(|_| ErrorCode::Unspecified)?;

        // We skip checking the fields in the request we don't rely on - similar
        // to treating them as reserved.

        // Set the session ID using the request field.
        // Just 2 bytes, zero-init it to save complicated casting.
        let mut my_half_session_id = HalfSessionId::default();
        D::Crypto::random_bytes(my_half_session_id.as_mut().into())?;
        self.session
            .set_session_id(request.req_session_id, my_half_session_id);

        // Perform ECDHE using the request field.
        let mut my_public_key = MaybeUninit::<EcP256UncompressedPoint>::uninit();
        let my_public_key = self
            .session
            .generate_handshake_secret(&request.exchange_data, &mut my_public_key)?;

        // We've read all fields we need in the request, extend the hash then we
        // can start writing to the response.
        self.session
            .init_transcript_hash_with_key_exchange_request(request.as_bytes())?;

        let response = write_partial_response::<D::Crypto>(
            &mut buf[..KeyExchangeResponse::SIZE],
            my_half_session_id,
            my_public_key,
        )?;
        self.session
            .extend_transcript_hash_with_key_exchange_response(
                &response.as_bytes()[..KeyExchangeResponse::PARTIAL_SIZE],
            )?;

        // Add the signature and HMAC.
        self.session.sign_key_exchange_message(
            self.identity.identity_private_key_handle(),
            &mut response.signature,
        )?;
        self.session
            .hmac_key_exchange_message(&mut response.responder_verify_data)?;

        // Advance state.
        self.state = ResponderState::WaitForRequesterKey;
        Ok(KeyExchangeResponse::SIZE)
    }
}

#[cfg(test)]
mod tests {
    use spdm::types::code::RequestCode;
    use spdm_test_deps::{TestIdentity, TestVendor};
    use spdm_types::crypto::EC_P256_COORD_SIZE;

    use super::*;
    use crate::dispatch::wait_for_key_exchange::get_version::GetVersionDispatcher;
    use crate::test::TestResponderDeps;
    use crate::version::SPDM_THIS_VERSION;

    fn get_valid_key_exchange_buffer() -> Vec<u8> {
        let public_key = EcP256UncompressedPoint {
            x: [0x0C; EC_P256_COORD_SIZE],
            y: [0x0D; EC_P256_COORD_SIZE],
        };
        let mut buf = vec![SPDM_THIS_VERSION, RequestCode::KeyExchange.0, 0, 0xFF];
        // Session ID.
        buf.extend_from_slice(&[0xAB, 0xCD]);
        // Session policy/reserved.
        buf.extend_from_slice(&[0, 0]);
        // Random data.
        buf.extend_from_slice(&[0xFF; 32]);
        // Public key.
        buf.extend_from_slice(public_key.as_bytes());
        // Opaque data size = 0.
        buf.extend_from_slice(&[0, 0]);
        // Extend buffer size to fit the response in.
        buf.extend_from_slice(&[0; 200]);
        buf
    }

    #[test]
    fn key_exchange_request() {
        let mut buf = get_valid_key_exchange_buffer();
        let req_size = KeyExchangeRequest::SIZE;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        // A GetVersion request must come first to initialize the transcript.
        let mut get_version = [0x10, RequestCode::GetVersion.0, 0, 0, 0, 0, 0, 0];
        let result = spdm.dispatch_get_version_request(&mut get_version, 4);
        assert_eq!(result, Ok(8));

        let result = spdm.dispatch_key_exchange_request(&mut buf, req_size);
        assert_eq!(result, Ok(KeyExchangeResponse::SIZE));
        let response: &mut KeyExchangeResponse =
            (&mut buf[..KeyExchangeResponse::SIZE]).try_into().unwrap();
        assert_eq!(response.version, SPDM_THIS_VERSION);
        assert_eq!(response.response_code, ResponseCode::KeyExchange);
        assert_eq!(response.param1, KeyExchangeResponse::NO_HEARTBEAT);
        assert_eq!(
            response.mut_auth_requested,
            KeyExchangeResponse::NO_ENCAPSULATE
        );
        assert_eq!(response.opaque_data_size.get(), 0);
        assert!(matches!(spdm.state, ResponderState::WaitForRequesterKey));
    }

    #[test]
    fn key_exchange_no_transcript() {
        let mut buf = get_valid_key_exchange_buffer();
        let req_size = KeyExchangeRequest::SIZE;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let result = spdm.dispatch_key_exchange_request(&mut buf, req_size);
        assert_eq!(result, Err(ErrorCode::UnexpectedRequest));
        assert!(matches!(spdm.state, ResponderState::WaitForKeyExchange));
    }
}
