// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::session::SessionPhase;
use spdm::types::code::RequestCode;
use spdm::types::message::{GivePubKeyRequest, GIVE_PUBLIC_KEY_RESPONSE_SIZE};
use spdm_types::deps::Identity;
use zerocopy::AsBytes;

use crate::dispatch::DispatchSecure;
use crate::error::{RequesterError, RequesterStatus};
use crate::version::SPDM_THIS_VERSION;
use crate::{Requester, RequesterDeps};

/// GivePubKeySender sends the GivePubKey request.
///
/// This trait is only used for separating impl blocks of `Requester` struct by functionality.
pub trait GivePubKeySender {
    /// Sends the GivePubKey request and handles the GivePubKey response.
    ///
    /// GivePubKey request format:
    ///
    /// | Byte offset | Size (bytes)    | Field               | Description              |
    /// | :---------- | :-------------- | :------------------ | :----------------------- |
    /// | 0           | 1               | SPDMVersion         | SPDM_THIS_VERSION        |
    /// | 1           | 1               | RequestResponseCode | RequestCode::GivePubKey  |
    /// | 2           | 1               | Param1              | Reserved                 |
    /// | 3           | 1               | Param2              | Reserved                 |
    /// | 4           | PUBLIC_KEY_SIZE | PublicKey           | Public Key               |
    ///
    /// GivePubKey response format:
    /// | Byte offset | Size (bytes) | Field               | Description             |
    /// | :---------- | :----------- | :------------------ | :---------------------- |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION       |
    /// | 1           | 1            | RequestResponseCode | Response::GivePubKey    |
    /// | 2           | 1            | Param1              | Reserved                |
    /// | 3           | 1            | Param2              | Reserved                |
    fn give_pub_key(&mut self) -> RequesterStatus;
}

impl<D: RequesterDeps> GivePubKeySender for Requester<D> {
    fn give_pub_key(&mut self) -> RequesterStatus {
        let mut req = GivePubKeyRequest {
            version: SPDM_THIS_VERSION,
            request_code: RequestCode::GivePubKey,
            param1: 0,
            param2: 0,
            public_key: self.identity.identity_public_key().clone(),
        };
        let buf = req.as_bytes_mut();

        let resp = self.dispatch_secure_request(
            SessionPhase::Handshake,
            buf.into(),
            GivePubKeyRequest::SIZE,
        )?;
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
        use spdm_test_deps::{TestDispatch, TestIdentity};

        use super::super::*;
        use crate::test::TestRequesterDeps;

        #[test]
        fn give_pub_key_success() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            Requester::<TestRequesterDeps>::dispatch_secure_request.mock_safe(|_, _, buf, _| {
                let pub_key_response = [SPDM_THIS_VERSION, RequestCode::GivePubKey.0, 0, 0];
                MockResult::Return(Ok(buf
                    .get_out(..4)
                    .unwrap()
                    .copy_from_slice(&pub_key_response)))
            });

            let result = requester.give_pub_key();
            assert_eq!(result, Ok(()));
        }

        #[test]
        fn give_pub_key_failure() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            Requester::<TestRequesterDeps>::dispatch_secure_request
                .mock_safe(|_, _, _, _| MockResult::Return(Err(RequesterError)));

            let result = requester.give_pub_key();
            assert_eq!(result, Err(RequesterError));
        }
    }
}
