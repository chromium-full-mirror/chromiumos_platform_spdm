// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::MaybeUninit;

use spdm::types::code::RequestCode;
use spdm::types::message::{HalfSessionId, KeyExchangeRequest, KeyExchangeResponse};
use spdm_types::crypto::EcP256UncompressedPoint;
use spdm_types::deps::{Crypto, CryptoResult, Dispatch, IdentityPublicKey};
use uninit::extension_traits::AsOut;
use uninit::uninit_array;
use zerocopy::AsBytes;

use crate::error::{RequesterError, RequesterStatus};
use crate::session::RequesterSession;
use crate::version::SPDM_THIS_VERSION;
use crate::{Requester, RequesterDeps};

/// KeyExchangeSender sends the KeyExchange request.
///
/// This trait is only used for separating impl blocks of `Requester` struct by functionality.
pub trait KeyExchangeSender {
    /// Sends the KeyExchange request and handles the KeyExchange response.
    /// KeyExchange request format: see `KeyExchangeRequest` struct.
    /// KeyExchange response format: see `KeyExchangeResponse` struct.
    fn key_exchange(&mut self) -> RequesterStatus;
}

fn generate_key_exchange_request<C: Crypto>(
    half_session_id: HalfSessionId,
    public_key: &EcP256UncompressedPoint,
) -> CryptoResult<KeyExchangeRequest> {
    let mut random_data = [0; 32];
    C::random_bytes(random_data.as_out())?;
    Ok(KeyExchangeRequest {
        version: SPDM_THIS_VERSION,
        request_code: RequestCode::KeyExchange,
        param1: 0,
        param2: 0xFF,
        req_session_id: half_session_id,
        session_policy: 0,
        reserved: 0,
        random_data,
        exchange_data: public_key.clone(),
        opaque_data_size: 0.into(),
    })
}

impl<D: RequesterDeps> KeyExchangeSender for Requester<D> {
    fn key_exchange(&mut self) -> RequesterStatus {
        let mut buf = uninit_array![u8; KeyExchangeResponse::SIZE];

        // Randomly generate half session id.
        let mut my_half_session_id = HalfSessionId::default();
        D::Crypto::random_bytes(my_half_session_id.as_out()).map_err(|_| RequesterError)?;

        // Randomly generate public/private key pair.
        let mut private_key =
            MaybeUninit::<<D::Crypto as Crypto>::IdentityPrivateKeyHandle>::uninit();
        let mut public_key = MaybeUninit::<IdentityPublicKey>::uninit();
        let (_, public_key) = D::Crypto::random_key_pair(private_key.as_out(), public_key.as_out())
            .map_err(|_| RequesterError)?;
        // SAFETY: `private_key` is guaranteed to be initialized after a successful
        // `random_key_pair`.
        let private_key = unsafe { private_key.assume_init() };

        let request = generate_key_exchange_request::<D::Crypto>(my_half_session_id, public_key)
            .map_err(|_| RequesterError)?;

        // Update transcript with KEY_EXCHANGE request.
        self.session
            .init_transcript_hash_with_key_exchange_request(request.as_bytes())
            .map_err(|_| RequesterError)?;

        // Send request / receive response.
        buf[0..KeyExchangeRequest::SIZE]
            .as_out()
            .copy_from_slice(request.as_bytes());
        let resp =
            &*self
                .dispatch
                .dispatch_request(false, buf.as_mut().into(), KeyExchangeRequest::SIZE);
        if resp.len() != KeyExchangeResponse::SIZE {
            return Err(RequesterError);
        }
        let resp: &KeyExchangeResponse = resp.try_into().map_err(|_| RequesterError)?;

        // Set session ID and generate handshake secret.
        self.session
            .set_session_id(my_half_session_id, resp.resp_session_id);
        self.session
            .generate_handshake_secret(&resp.exchange_data, &private_key)
            .map_err(|_| RequesterError)?;

        // Update transcript with KEY_EXCHANGE response, along with verifying the signature/hmac.

        // Extend transcript with the part before the signature, and verify the signature.
        self.session
            .extend_transcript_hash_with_key_exchange_response(
                &resp.as_bytes()[..KeyExchangeResponse::PARTIAL_SIZE],
            )
            .map_err(|_| RequesterError)?;
        self.session
            .verify_key_exchange_message(&resp.signature)
            .map_err(|_| RequesterError)?;

        // Verify the hmac message and extend the transcript.
        self.session
            .verify_key_exchange_message_hmac(&resp.responder_verify_data)
            .map_err(|_| RequesterError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockResult, Mockable};
        use spdm::types::code::ResponseCode;
        use spdm::types::message::KeyExchangeResponse;
        use spdm_test_deps::{TestDispatch, TestIdentity};
        use spdm_types::crypto::{
            EcP256UncompressedPoint, EcdsaP256Signature, ECDSA_P256_SCALAR_SIZE,
            EC_P256_COORD_SIZE, SHA256_HASH_SIZE,
        };
        use zerocopy::AsBytes;

        use super::super::*;
        use crate::test::TestRequesterDeps;
        use crate::version::SPDM_THIS_VERSION;

        const TEST_HASH: [u8; SHA256_HASH_SIZE] = [0xFF; SHA256_HASH_SIZE];
        const TEST_SIGNATURE: EcdsaP256Signature = EcdsaP256Signature {
            r: [0x0A; ECDSA_P256_SCALAR_SIZE],
            s: [0x0B; ECDSA_P256_SCALAR_SIZE],
        };
        const TEST_PUBLIC_KEY: EcP256UncompressedPoint = EcP256UncompressedPoint {
            x: [0x0C; EC_P256_COORD_SIZE],
            y: [0x0D; EC_P256_COORD_SIZE],
        };

        #[test]
        fn key_exchange_success() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            // GetVersion and GetPubKey needs to be called before KeyExchange.
            // Inject the state instead.
            requester
                .session
                .set_negotiation_transcript([0xAB; 4], [0xCD; 8]);
            requester.session.set_responder_public_key(&TEST_PUBLIC_KEY);

            TestDispatch::dispatch_request.mock_safe(|_, _, buf, _| {
                let resp = KeyExchangeResponse {
                    version: SPDM_THIS_VERSION,
                    response_code: ResponseCode::KeyExchange,
                    param1: KeyExchangeResponse::NO_HEARTBEAT,
                    param2: 0,
                    resp_session_id: [0x12, 0x34],
                    mut_auth_requested: KeyExchangeResponse::NO_ENCAPSULATE,
                    slot_id_param: KeyExchangeResponse::PROVISIONED_SLOT_ID,
                    random_data: [0xAA; 32],
                    exchange_data: TEST_PUBLIC_KEY,
                    opaque_data_size: 0.into(),
                    signature: TEST_SIGNATURE,
                    responder_verify_data: TEST_HASH,
                };
                MockResult::Return(buf.copy_from_slice(resp.as_bytes()))
            });

            let result = requester.key_exchange();
            assert_eq!(result, Ok(()));
        }
    }
}
