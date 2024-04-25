// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::session::SessionPhase;
use spdm::types::code::RequestCode;
use spdm::types::message::{FinishRequest, GIVE_PUBLIC_KEY_RESPONSE_SIZE};
use spdm_types::crypto::{EcdsaP256Signature, ECDSA_P256_SCALAR_SIZE, SHA256_HASH_SIZE};
use spdm_types::deps::Identity;
use zerocopy::AsBytes;

use crate::dispatch::DispatchSecure;
use crate::error::{RequesterError, RequesterStatus};
use crate::session::RequesterSession;
use crate::version::SPDM_THIS_VERSION;
use crate::{Requester, RequesterDeps};

/// FinishSender sends the Finish request.
///
/// This trait is only used for separating impl blocks of `Requester` struct by functionality.
pub trait FinishSender {
    /// Sends the Finish request and handles the Finish response.
    /// Finish request format: see `FinishRequest` struct.
    /// Finish response format:
    /// | Byte offset | Size (bytes) | Field               | Description          |
    /// | :---------- | :----------- | :------------------ | :------------------- |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION    |
    /// | 1           | 1            | RequestResponseCode | ResponseCode::Finish |
    /// | 2           | 1            | Param1              | Reserved             |
    /// | 3           | 1            | Param2              | Reserved             |
    fn finish(&mut self) -> RequesterStatus;
}

impl<D: RequesterDeps> FinishSender for Requester<D> {
    fn finish(&mut self) -> RequesterStatus {
        let mut req = FinishRequest {
            version: SPDM_THIS_VERSION,
            request_code: RequestCode::Finish,
            param1: 0,
            param2: 0,
            // Fill the signature and hmac later.
            signature: EcdsaP256Signature {
                r: [0; ECDSA_P256_SCALAR_SIZE],
                s: [0; ECDSA_P256_SCALAR_SIZE],
            },
            requester_verify_data: [0; SHA256_HASH_SIZE],
        };
        let buf = req.as_bytes_mut();
        self.session
            .extend_transcript_hash_with_finish_request(&buf[..FinishRequest::PARTIAL_SIZE])
            .map_err(|_| RequesterError)?;

        self.session
            .sign_finish_message(
                self.identity.identity_private_key_handle(),
                &mut req.signature,
            )
            .map_err(|_| RequesterError)?;
        self.session
            .hmac_finish_message(&mut req.requester_verify_data)
            .map_err(|_| RequesterError)?;

        let buf = req.as_bytes_mut();
        let resp =
            self.dispatch_secure_request(SessionPhase::Handshake, buf.into(), FinishRequest::SIZE)?;
        if resp.len() != GIVE_PUBLIC_KEY_RESPONSE_SIZE {
            return Err(RequesterError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockResult, Mockable};
        use spdm::session::Session;
        use spdm_test_deps::{TestCrypto, TestDispatch, TestIdentity};

        use super::super::*;
        use crate::test::TestRequesterDeps;

        #[test]
        fn finish_success() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            Session::<TestCrypto>::extend_transcript_hash_with_finish_request
                .mock_safe(|_, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::sign_finish_message
                .mock_safe(|_, _, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::hmac_finish_message.mock_safe(|_, _| MockResult::Return(Ok(())));
            Requester::<TestRequesterDeps>::dispatch_secure_request.mock_safe(|_, _, buf, _| {
                let finish_response = [SPDM_THIS_VERSION, RequestCode::Finish.0, 0, 0];
                MockResult::Return(Ok(buf
                    .get_out(..4)
                    .unwrap()
                    .copy_from_slice(&finish_response)))
            });

            let result = requester.finish();
            assert_eq!(result, Ok(()));
        }

        #[test]
        fn finish_failure() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            Session::<TestCrypto>::extend_transcript_hash_with_finish_request
                .mock_safe(|_, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::sign_finish_message
                .mock_safe(|_, _, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::hmac_finish_message.mock_safe(|_, _| MockResult::Return(Ok(())));
            Requester::<TestRequesterDeps>::dispatch_secure_request
                .mock_safe(|_, _, _, _| MockResult::Return(Err(RequesterError)));

            let result = requester.finish();
            assert_eq!(result, Err(RequesterError));
        }
    }
}
